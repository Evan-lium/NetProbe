"""扫描引擎 — 统一的扫描流水线，CLI 和 Web 共用。"""

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests as req_lib

from .dns_utils import (
    is_subdomain_of, resolve_a_record, reverse_dns_lookup,
    resolve_dns_records, get_nameservers, try_zone_transfer,
)
from .scanner import check_nmap_available, run_dns_brute, run_port_scan, resolve_ports
from .tools.dnsx import run_dnsx
from .tools.httpx_tool import run_httpx
from .tools.masscan import run_masscan
from .tools.rustscan import run_rustscan
from .tools.subfinder import run_subfinder
from .tools.registry import get_available_tools
from .utils import extract_root_domain, is_ip_address, validate_input
from .fingerprint import detect_technologies
from .web_probe import probe_web_for_host
from .banner_grab import grab_banners_for_host
from .sensitive_probe import probe_sensitive_for_hosts
from .risk import compute_risk_score
from .tools.crtsh import query_crtsh, query_crtsh_certificates
from .tools.fofa import query_fofa
from .tools.hunter import query_hunter
from .tools.whois import query_rdap_domain, query_rdap_ip
from .wordlist import get_default_wordlist_path, load_external_wordlist


def parse_targets(raw: str) -> list[str]:
    """将逗号/换行/空格分隔的原始输入解析为目标列表。"""
    targets = []
    for part in raw.replace(',', ' ').replace('\n', ' ').replace('\r', ' ').split():
        part = part.strip()
        if part:
            targets.append(part)
    return targets


# ── 扫描引擎分发 ──────────────────────────────────────

def do_subdomain_enum(base_domain: str, options: dict, emit) -> list[dict]:
    """子域名枚举：auto 模式下跑所有可用引擎，合并去重。"""
    results = []
    seen = set()
    chosen = options.get('subdomain_tool', 'auto')

    if chosen in ('auto', 'subfinder'):
        try:
            subs = run_subfinder(base_domain, timeout=options.get('timeout', 300))
            new = 0
            for s in subs:
                h = s['hostname'].lower()
                if h not in seen:
                    seen.add(h)
                    results.append(s)
                    new += 1
            emit('progress', text=f'  [subfinder] 发现 {new} 个子域名')
        except Exception as e:
            emit('progress', text=f'  [subfinder] 不可用: {e}')

    if chosen in ('auto', 'nmap'):
        if check_nmap_available():
            wordlist_path = None
            use_temp = False
            try:
                wl = options.get('wordlist')
                wordlist_path = load_external_wordlist(wl) if wl else get_default_wordlist_path()
                if not wl:
                    use_temp = True
                raw = run_dns_brute(base_domain, wordlist_path, options.get('timeout', 300))
                new = 0
                for s in raw:
                    h = s['hostname'].lower()
                    if h not in seen:
                        seen.add(h)
                        results.append(s)
                        new += 1
                emit('progress', text=f'  [nmap dns-brute] 发现 {new} 个 (共 {len(raw)} 条)')
            except Exception as e:
                emit('progress', text=f'  [nmap dns-brute] 失败: {e}')
            finally:
                if use_temp and wordlist_path:
                    try:
                        os.remove(wordlist_path)
                    except OSError:
                        pass
        else:
            emit('progress', text='  [nmap] 未安装，跳过 dns-brute')

    return results


def do_dns_validate(hostnames: list[str], options: dict, emit) -> list[str]:
    """DNS 验证：auto 模式按优先级逐个尝试，成功即停。"""
    chosen = options.get('dns_tool', 'auto')

    if chosen in ('auto', 'dnspython'):
        valid = []
        for h in hostnames:
            if resolve_a_record(h):
                valid.append(h)
        emit('progress', text=f'  [dnspython] 验证完成: {len(valid)}/{len(hostnames)} 可解析')
        if valid or chosen == 'dnspython':
            return valid
        emit('progress', text='  [dnspython] 无结果，尝试 dnsx...')

    if chosen in ('auto', 'dnsx'):
        try:
            results = run_dnsx(hostnames, timeout=120)
            valid = [r['hostname'] for r in results]
            emit('progress', text=f'  [dnsx] 验证完成: {len(valid)}/{len(hostnames)} 可解析')
            return valid
        except Exception:
            emit('progress', text=f'  [dnsx] 不可用')
            return []

    return []


def _normalize_portscan(results) -> dict[str, list[dict]]:
    """统一端口扫描结果为 {ip: [port_dict, ...]} 格式。"""
    normalized = {}
    for ip, data in results.items():
        if isinstance(data, dict) and 'ports' in data:
            normalized[ip] = data['ports']
        elif isinstance(data, list):
            normalized[ip] = data
        else:
            normalized[ip] = []
    return normalized


def _try_port_engine(name, run_fn, ips, timeout, emit, ports_list=None, ports_str=None, process_callback=None):
    """尝试运行一个端口扫描引擎，返回 (结果, 是否成功)。"""
    def _log(msg):
        emit('progress', text=msg)

    try:
        if name == 'nmap':
            raw = run_fn(ips, ports=ports_str, timeout=timeout, on_progress=_log)
        else:
            raw = run_fn(ips, ports=ports_list, timeout=timeout, on_progress=_log, process_callback=process_callback)
        results = _normalize_portscan(raw)
        total = sum(len(v) for v in results.values())
        if total > 0:
            emit('progress', text=f'  [{name}] 扫描完成: {total} 个端口')
            return results, True
        emit('progress', text=f'  [{name}] 未发现开放端口，降级到下一引擎...')
        return {}, False
    except Exception as e:
        emit('progress', text=f'  [{name}] 不可用: {e}')
        return {}, False


def do_port_scan(hosts: list[dict], options: dict, emit) -> dict[str, list[dict]]:
    """端口扫描：auto 模式按优先级逐个尝试，成功即停。"""
    chosen = options.get('portscan_tool', 'auto')
    ips = list({h['ip'] for h in hosts})
    timeout = options.get('timeout', 300)
    process_cb = options.get('_process_callback')

    def _log(msg):
        emit('progress', text=msg)

    # 解析端口预设
    preset = options.get('port_preset', 'common')
    custom = options.get('custom_ports', '')
    ports_list, ports_str = resolve_ports(preset, custom)
    total_ports = len(ports_list)
    emit('progress', text=f'  端口范围: {preset} ({total_ports} 个端口)')

    if chosen == 'nmap':
        if check_nmap_available():
            return _normalize_portscan(run_port_scan(ips, ports=ports_str, timeout=timeout, on_progress=_log))
        emit('progress', text='  [nmap] 未安装')
        return {}
    if chosen == 'rustscan':
        results, _ = _try_port_engine('rustscan', run_rustscan, ips, timeout, emit, ports_list=ports_list, process_callback=process_cb)
        return results
    if chosen == 'masscan':
        results, _ = _try_port_engine('masscan', run_masscan, ips, timeout, emit, ports_list=ports_list, process_callback=process_cb)
        return results

    engines = []
    if check_nmap_available():
        engines.append(('nmap', lambda ips, timeout, **kw: run_port_scan(ips, ports=ports_str, timeout=timeout, on_progress=kw.get('on_progress'))))
    engines.append(('rustscan', lambda ips, timeout, **kw: run_rustscan(ips, ports=ports_list, timeout=timeout, process_callback=kw.get('process_callback'), on_progress=kw.get('on_progress'))))
    engines.append(('masscan', lambda ips, timeout, **kw: run_masscan(ips, ports=ports_list, timeout=timeout, process_callback=kw.get('process_callback'), on_progress=kw.get('on_progress'))))

    for engine_name, engine_fn in engines:
        results, ok = _try_port_engine(engine_name, engine_fn, ips, timeout, emit, process_callback=process_cb)
        if ok:
            return results

    emit('progress', text='  所有端口扫描引擎均无结果')
    return {}


def do_web_probe(hosts: list[dict], options: dict, emit) -> None:
    """Web 探测：auto 模式按优先级逐个尝试，成功即停。"""
    chosen = options.get('web_tool', 'auto')

    if chosen in ('auto', 'python'):
        emit('progress', text=f'  [python] Web 探测...')

        def _probe_host(host):
            open_ports = [p['port'] for p in host.get('ports', [])]
            return host, probe_web_for_host(host['hostname'], host['ip'], open_ports)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {pool.submit(_probe_host, h): h for h in hosts}
            for future in as_completed(futures):
                host, web_info = future.result()
                js_urls = []
                for w in web_info:
                    raw_hdrs = w.pop('_raw_headers', {})
                    raw_html = w.pop('_raw_html', '')
                    js_urls.extend(w.pop('_js_urls', []))
                    cookies = raw_hdrs.get('Set-Cookie', '')
                    try:
                        w['tech'] = detect_technologies(raw_hdrs, raw_html, cookies)
                    except Exception:
                        w['tech'] = []
                host['web_info'] = web_info
                host['_pending_js_urls'] = js_urls

        total = sum(len(h.get('web_info', [])) for h in hosts)
        emit('progress', text=f'  [python] 发现 {total} 个 Web 站点')
        return

    if chosen == 'httpx':
        try:
            host_list = list({h['hostname'] or h['ip'] for h in hosts})
            results = run_httpx(host_list, timeout=120)
            if results:
                emit('progress', text=f'  [httpx] 发现 {len(results)} 个 Web 站点')
                by_host = {}
                for r in results:
                    key = r.get('hostname', '').lower() or r.get('ip', '')
                    by_host[key] = r
                    if r.get('ip'):
                        by_host[r['ip']] = r
                for host in hosts:
                    key = host.get('hostname', '').lower() or host.get('ip', '')
                    match = by_host.get(key) or by_host.get(host['ip'])
                    host['web_info'] = [{
                        'port': match.get('port', 0),
                        'url': match.get('url', ''),
                        'status': match.get('status', 0),
                        'title': match.get('title', ''),
                        'tech': match.get('tech', ''),
                        'redirect': '',
                    }] if match else []
                return
        except Exception:
            emit('progress', text=f'  [httpx] 失败')
        emit('progress', text=f'  降级到 Python 探测...')
        for host in hosts:
            open_ports = [p['port'] for p in host.get('ports', [])]
            host['web_info'] = probe_web_for_host(host['hostname'], host['ip'], open_ports)


def do_passive_recon(base_domain: str, emit) -> list[dict]:
    """被动情报收集：从 crt.sh / FOFA / Hunter 获取子域名。"""
    results = []
    seen = set()

    try:
        crt_results = query_crtsh(base_domain)
        new = 0
        for r in crt_results:
            h = r['hostname'].lower()
            if h not in seen:
                seen.add(h)
                results.append(r)
                new += 1
        emit('progress', text=f'  [crt.sh] 发现 {new} 个子域名')
    except Exception as e:
        emit('progress', text=f'  [crt.sh] 查询失败: {e}')

    # 证书透明度日志增强：保留证书元数据 + 通配符发现
    try:
        cert_results = query_crtsh_certificates(base_domain)
        new = 0
        wildcards = 0
        for r in cert_results:
            h = r['hostname'].lower()
            if r.get('wildcard'):
                wildcards += 1
                continue  # 通配符域名不能直接扫描，仅统计
            if h not in seen:
                seen.add(h)
                results.append(r)
                new += 1
        if wildcards:
            emit('progress', text=f'  [crt.sh 证书] 发现 {new} 个子域名，{wildcards} 个通配符证书线索')
        elif new:
            emit('progress', text=f'  [crt.sh 证书] 补充发现 {new} 个子域名')
    except Exception as e:
        emit('progress', text=f'  [crt.sh 证书] 查询失败: {e}')

    fofa_results = query_fofa(base_domain)
    if fofa_results:
        new = 0
        for r in fofa_results:
            h = r['hostname'].lower()
            if h not in seen:
                seen.add(h)
                results.append(r)
                new += 1
        emit('progress', text=f'  [FOFA] 发现 {new} 个子域名')

    hunter_results = query_hunter(base_domain)
    if hunter_results:
        new = 0
        for r in hunter_results:
            h = r['hostname'].lower()
            if h not in seen:
                seen.add(h)
                results.append(r)
                new += 1
        emit('progress', text=f'  [Hunter] 发现 {new} 个子域名')

    # DNS 记录收集（MX/NS/CNAME/TXT，情报线索）
    try:
        mx = resolve_dns_records(base_domain, 'MX')
        if mx:
            emit('progress', text=f'  [DNS] MX: {", ".join(mx[:3])}')
        ns_records = get_nameservers(base_domain)
        if ns_records:
            emit('progress', text=f'  [DNS] NS: {", ".join(ns_records[:3])}')
        txt = resolve_dns_records(base_domain, 'TXT')
        if txt:
            emit('progress', text=f'  [DNS] TXT 记录 {len(txt)} 条')
    except Exception as e:
        emit('progress', text=f'  [DNS] 记录查询失败: {e}')

    # 尝试 DNS 区域传送（绝大多数域名会拒绝，仅线索）
    try:
        zone = try_zone_transfer(base_domain, timeout=8)
        if zone:
            emit('progress', text=f'  [DNS] AXFR 成功({zone["ns"]})，获取 {zone["count"]} 条记录')
            # 从 zone 记录里提取可能的子域名作为线索
            for rec in zone.get('records', []):
                if rec['type'] in ('A', 'CNAME') and rec['name'] and rec['name'] != base_domain:
                    h = rec['name'].lower()
                    if h.endswith('.' + base_domain) and h not in seen:
                        seen.add(h)
                        results.append({'hostname': h, 'ip': rec['value'] if rec['type'] == 'A' else '', 'source': 'axfr'})
        else:
            emit('progress', text='  [DNS] AXFR 被拒绝（正常）')
    except Exception as e:
        emit('progress', text=f'  [DNS] AXFR 失败: {e}')

    return results


# ── 单目标 / 多目标扫描 ──────────────────────────────────────

def _is_cancelled(options: dict) -> bool:
    """检查是否收到取消信号。"""
    cb = options.get('_cancel_check')
    return cb() if cb else False


def do_seed_expansion(hosts: list[dict], options: dict, emit):
    """种子扩展（单层 pivot）: IP→ASN→网段→反向DNS 发现新域名。

    流程:
    1. 收集 hosts 里所有唯一 IP
    2. 对每个 IP 查 ASN/网段（ipwhois RDAP）
    3. 对发现的网段，反向 DNS 扫前若干 IP 发现新 hostname
    4. 新发现的 hostname 加入 hosts（单层，不递归）

    防无限循环: 限单层、seen 去重、每网段最多扫 20 IP。
    """
    import ipaddress

    try:
        from ipwhois import IPWhois
    except ImportError:
        emit('progress', text='  [种子扩展] ipwhois 未安装，跳过')
        return

    if _is_cancelled(options):
        return

    emit('progress', text='  [种子扩展] 分析 IP 的 ASN/网段 ...')
    seen_ips = {h.get('ip') for h in hosts if h.get('ip')}
    seen_hostnames = {h.get('hostname', '').lower() for h in hosts}
    discovered = []

    for ip in list(seen_ips):
        if _is_cancelled(options):
            break
        try:
            lookup = IPWhois(ip).lookup_rdap(rate_limit_timeout=15)
        except Exception:
            continue

        asn = lookup.get('asn') or ''
        cidr = lookup.get('asn_cidr') or ''
        if not cidr:
            continue

        emit('progress', text=f'    {ip} → AS{asn} {cidr} ({(lookup.get("asn_description") or "")[:40]})')

        # 对网段内 IP 反向 DNS，发现新 hostname（最多扫 20 个）
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue

        scanned = 0
        for candidate_ip in net.hosts():
            if scanned >= 20 or _is_cancelled(options):
                break
            scanned += 1
            candidate = str(candidate_ip)
            if candidate in seen_ips:
                continue
            hostname = reverse_dns_lookup(candidate)
            if hostname and hostname.lower() not in seen_hostnames:
                seen_hostnames.add(hostname.lower())
                seen_ips.add(candidate)
                discovered.append({'hostname': hostname, 'ip': candidate, 'source': 'seed_expansion'})

    if discovered:
        for d in discovered:
            hosts.append({
                'hostname': d['hostname'],
                'ip': d['ip'],
                'ports': [], 'banners': [], 'web_info': [],
                'sensitive': [], 'js_findings': [], '_whois': [],
            })
        emit('progress', text=f'  ✓ 种子扩展完成: 发现 {len(discovered)} 个新域名（单层 pivot）')
    else:
        emit('progress', text='  ✓ 种子扩展完成: 无新发现')


def scan_target(target: str, options: dict, emit) -> list[dict]:
    """扫描单个目标，返回主机列表。emit(event, **data) 用于进度回调。"""
    target_start = time.time()

    try:
        target = validate_input(target)
    except ValueError as e:
        emit('progress', text=f'  跳过无效目标 {target}: {e}')
        return []

    skip_dns = options.get('no_dns_brute')
    skip_web = options.get('no_web')

    # 计算阶段数
    phases = 2  # DNS解析 + 端口扫描 始终执行
    if not skip_dns:
        phases += 2  # 被动收集 + 子域名枚举
    if not skip_web:
        phases += 3  # Web探测 + 敏感路径 + JS分析
    phases += 1  # Banner
    phase_num = [0]
    def ph(text):
        phase_num[0] += 1
        return f'[{phase_num[0]}/{phases}] {text}'

    # ── DNS 解析 ──
    if is_ip_address(target):
        emit('progress', text=ph(f'目标识别: IP {target}，反向 DNS 解析...'))
        hostname = reverse_dns_lookup(target)
        if not hostname:
            emit('progress', text=f'  ✗ 无法反向解析 IP: {target}，跳过')
            return []
        base_domain = extract_root_domain(hostname)
        main_ip = target
        main_hostname = hostname
        emit('progress', text=f'  ✓ 反向解析: {target} → {hostname} → {base_domain}')
    else:
        base_domain = target.lower().rstrip('.')
        emit('progress', text=ph(f'域名解析: {base_domain} ...'))
        ips = resolve_a_record(base_domain)
        if not ips:
            emit('progress', text=f'  ✗ 无法解析域名: {base_domain}，跳过')
            return []
        main_ip = ips[0]
        main_hostname = base_domain
        emit('progress', text=f'  ✓ 解析成功: {base_domain} → {main_ip}')

    if _is_cancelled(options):
        emit('progress', text='  扫描已取消')
        return []

    # ── 被动情报收集 ──
    passive_results = []
    if not skip_dns:
        emit('progress', text=ph(f'被动情报收集 ({base_domain}) ...'))
        t0 = time.time()
        passive_results = do_passive_recon(base_domain, emit)
        elapsed = time.time() - t0
        emit('progress', text=f'  ✓ 被动收集完成: {len(passive_results)} 个子域名 ({elapsed:.1f}s)')

    if _is_cancelled(options):
        emit('progress', text='  扫描已取消')
        return []

    # ── 子域名枚举 ──
    subdomains = []
    if not skip_dns:
        emit('progress', text=ph(f'主动子域名枚举 ({base_domain}) ...'))
        t0 = time.time()
        raw = do_subdomain_enum(base_domain, options, emit)
        raw = [s for s in raw if is_subdomain_of(s['hostname'], base_domain)]

        seen_hosts = {s['hostname'].lower() for s in raw}
        for p in passive_results:
            if p['hostname'].lower() not in seen_hosts and is_subdomain_of(p['hostname'], base_domain):
                raw.append(p)
                seen_hosts.add(p['hostname'].lower())

        if not options.get('no_validate'):
            hostnames = [s['hostname'] for s in raw]
            valid = do_dns_validate(hostnames, options, emit)
            subdomains = [s for s in raw if s['hostname'] in valid]
        else:
            subdomains = raw
        elapsed = time.time() - t0
        emit('progress', text=f'  ✓ 子域名枚举完成: {len(subdomains)} 个有效 ({elapsed:.1f}s)')

    if _is_cancelled(options):
        emit('progress', text='  扫描已取消')
        return []

    # 构建主机列表
    all_hosts = [{'hostname': main_hostname, 'ip': main_ip}]
    for sub in subdomains:
        if sub.get('ip'):
            all_hosts.append({'hostname': sub['hostname'], 'ip': sub['ip']})
        else:
            ips = resolve_a_record(sub['hostname'])
            if ips:
                all_hosts.append({'hostname': sub['hostname'], 'ip': ips[0]})

    emit('progress', text=f'  → 目标主机: {len(all_hosts)} 台 ({", ".join(h["ip"] for h in all_hosts[:5])}{"..." if len(all_hosts) > 5 else ""})')

    # ── 端口扫描 ──
    emit('progress', text=ph(f'端口扫描 ({len(all_hosts)} 台主机) ...'))
    t0 = time.time()
    scan_results = do_port_scan(all_hosts, options, emit)
    for host in all_hosts:
        ip = host['ip']
        if ip in scan_results:
            data = scan_results[ip]
            host['ports'] = data if isinstance(data, list) else data.get('ports', [])
            if isinstance(data, dict) and data.get('os'):
                host['os'] = data['os']
        else:
            host['ports'] = []
    total_open = sum(len(h.get('ports', [])) for h in all_hosts)
    elapsed = time.time() - t0
    emit('progress', text=f'  ✓ 端口扫描完成: {total_open} 个开放端口 ({elapsed:.1f}s)')

    if _is_cancelled(options):
        emit('progress', text='  扫描已取消')
        return all_hosts

    # ── Web 探测 ──
    if not skip_web:
        emit('progress', text=ph(f'Web 站点探测 ({len(all_hosts)} 台主机) ...'))
        t0 = time.time()
        do_web_probe(all_hosts, options, emit)
        total_web = sum(len(h.get('web_info', [])) for h in all_hosts)
        elapsed = time.time() - t0
        emit('progress', text=f'  ✓ Web 探测完成: {total_web} 个站点 ({elapsed:.1f}s)')
    else:
        for host in all_hosts:
            host['web_info'] = []

    if _is_cancelled(options):
        emit('progress', text='  扫描已取消')
        return all_hosts

    # ── 敏感路径探测 ──
    if not skip_web:
        emit('progress', text=ph('敏感路径探测 ...'))
        t0 = time.time()
        probe_sensitive_for_hosts(all_hosts)
        sensitive_total = sum(len(h.get('sensitive', [])) for h in all_hosts)
        elapsed = time.time() - t0
        if sensitive_total:
            emit('progress', text=f'  ✓ 敏感路径探测完成: {sensitive_total} 条发现 ({elapsed:.1f}s)')
        else:
            emit('progress', text=f'  ✓ 敏感路径探测完成: 无发现 ({elapsed:.1f}s)')

    # ── JS 文件分析 ──
    if not skip_web:
        from .js_analyzer import analyze_js_for_hosts
        emit('progress', text=ph('JavaScript 文件分析 ...'))
        t0 = time.time()
        analyze_js_for_hosts(all_hosts)
        js_total = sum(len(h.get('js_findings', [])) for h in all_hosts)
        js_secrets = sum(
            len(j.get('secrets', [])) for h in all_hosts for j in h.get('js_findings', [])
        )
        elapsed = time.time() - t0
        if js_total:
            detail = f'{js_total} 个文件'
            if js_secrets:
                detail += f', {js_secrets} 条泄露'
            emit('progress', text=f'  ✓ JS 分析完成: {detail} ({elapsed:.1f}s)')
        else:
            emit('progress', text=f'  ✓ JS 分析完成: 无发现 ({elapsed:.1f}s)')

    if _is_cancelled(options):
        emit('progress', text='  扫描已取消')
        return all_hosts

    # ── Banner 抓取 ──
    emit('progress', text=ph('Banner 抓取 ...'))
    t0 = time.time()

    def _grab_host_banners(host):
        open_ports = [p['port'] for p in host.get('ports', [])]
        return host, grab_banners_for_host(host['ip'], open_ports)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_grab_host_banners, h): h for h in all_hosts}
        for future in as_completed(futures):
            host, banners = future.result()
            host['banners'] = banners

    banner_total = sum(len(h.get('banners', [])) for h in all_hosts)
    elapsed = time.time() - t0
    if banner_total:
        emit('progress', text=f'  ✓ Banner 抓取完成: {banner_total} 条 ({elapsed:.1f}s)')
    else:
        emit('progress', text=f'  ✓ Banner 抓取完成: 无结果 ({elapsed:.1f}s)')

    # ── WHOIS/RDAP 查询（域名注册信息 + IP 的 ASN/网段）──
    emit('progress', text=ph('WHOIS/RDAP 查询 ...'))
    t0 = time.time()
    whois_count = 0
    queried_domains = set()
    queried_ips = set()
    for host in all_hosts:
        hostname = host.get('hostname', '')
        ip = host.get('ip', '')
        host['_whois'] = []
        # 域名 RDAP（同域名只查一次）
        root = extract_root_domain(hostname) if hostname else ''
        if root and root not in queried_domains:
            queried_domains.add(root)
            rdap = query_rdap_domain(root)
            if rdap:
                host['_whois'].append({'type': 'domain', 'target': root, 'data': rdap})
                whois_count += 1
        # IP 的 ASN/网段（同 IP 只查一次）
        if ip and ip not in queried_ips:
            queried_ips.add(ip)
            rdap_ip = query_rdap_ip(ip)
            if rdap_ip:
                host['_whois'].append({'type': 'ip', 'target': ip, 'data': rdap_ip})
                whois_count += 1
    elapsed = time.time() - t0
    if whois_count:
        emit('progress', text=f'  ✓ WHOIS 查询完成: {whois_count} 条 ({elapsed:.1f}s)')
    else:
        emit('progress', text=f'  ✓ WHOIS 查询完成: 无结果 ({elapsed:.1f}s)')

    # ── 风险评分（综合敏感路径/高危端口/CVE/SSL/威胁情报）──
    emit('progress', text=ph('风险评分 ...'))
    t0 = time.time()
    high_risk = 0
    for host in all_hosts:
        # 从 passive recon 结果透传 Hunter threat risk_level
        threat_level = 0
        for src in host.get('_sources', []):
            if src.get('source') == 'hunter' and src.get('risk_level', 0) >= 2:
                threat_level = src.get('risk_level', 0)
        if threat_level:
            host['threat_risk_level'] = threat_level
        result = compute_risk_score(host)
        host['risk_score'] = result['score']
        host['risk_factors'] = result['factors']
        if result['score'] >= 70:
            high_risk += 1
    elapsed = time.time() - t0
    if high_risk:
        emit('progress', text=f'  ✓ 风险评分完成: {high_risk} 台高危主机 ({elapsed:.1f}s)')
    else:
        emit('progress', text=f'  ✓ 风险评分完成: 无高危主机 ({elapsed:.1f}s)')

    # ── 种子扩展（单层 pivot: IP→ASN→网段→反向DNS 发现新域名）──
    if not options.get('no_seed_expansion'):
        do_seed_expansion(all_hosts, options, emit)

    # ── 目标扫描总结 ──
    total_elapsed = time.time() - target_start
    total_hosts = len(all_hosts)
    total_ports = sum(len(h.get('ports', [])) for h in all_hosts)
    total_web = sum(len(h.get('web_info', [])) for h in all_hosts)
    emit('progress', text=f'━━━ {target} 扫描完成: {total_hosts} 台主机 · {total_ports} 个端口 · {total_web} 个网站 · 耗时 {total_elapsed:.1f}s ━━━')

    return all_hosts


def scan_all_targets(targets: list[str], options: dict, emit) -> list[dict]:
    """扫描多个目标，返回所有主机结果。

    参数:
        targets: 已解析的目标列表
        options: 扫描选项
        emit: 进度回调，签名为 emit(event, **data)
    """
    req_lib.packages.urllib3.disable_warnings(
        req_lib.packages.urllib3.exceptions.InsecureRequestWarning
    )

    tools = get_available_tools()
    avail = [v['label'] for v in tools.values() if v['available']]
    emit('progress', text=f'可用工具: {", ".join(avail) if avail else "无外部工具 (仅内置)"}')

    if not targets:
        emit('error', text='未提供有效的扫描目标')
        return []

    emit('progress', text=f'共 {len(targets)} 个目标: {", ".join(targets)}')

    scan_start = time.time()
    all_hosts = []
    for i, target in enumerate(targets, 1):
        if _is_cancelled(options):
            emit('progress', text='扫描已取消')
            break
        emit('progress', text=f'\n━━━ 目标 [{i}/{len(targets)}] {target} ━━━')
        hosts = scan_target(target, options, emit)
        if hosts:
            for h in hosts:
                h['target'] = target
            all_hosts.extend(hosts)

    if not all_hosts:
        emit('error', text='所有目标均未获取到结果')
        return []

    total_elapsed = time.time() - scan_start
    total_hosts = len(all_hosts)
    total_ports = sum(len(h.get('ports', [])) for h in all_hosts)
    total_web = sum(len(h.get('web_info', [])) for h in all_hosts)
    total_sensitive = sum(len(h.get('sensitive', [])) for h in all_hosts)
    emit('progress', text=f'\n{"═" * 40}')
    emit('progress', text=f'扫描全部完成')
    emit('progress', text=f'  目标: {len(targets)} 个')
    emit('progress', text=f'  主机: {total_hosts} 台')
    emit('progress', text=f'  端口: {total_ports} 个')
    emit('progress', text=f'  网站: {total_web} 个')
    if total_sensitive:
        emit('progress', text=f'  敏感路径: {total_sensitive} 条')
    emit('progress', text=f'  总耗时: {total_elapsed:.1f}s')
    emit('progress', text=f'{"═" * 40}')

    return all_hosts
