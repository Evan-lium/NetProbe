"""扫描引擎 — 统一的扫描流水线，CLI 和 Web 共用。"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests as req_lib

from .dns_utils import is_subdomain_of, resolve_a_record, reverse_dns_lookup
from .scanner import check_nmap_available, run_dns_brute, run_port_scan
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
from .tools.crtsh import query_crtsh
from .tools.fofa import query_fofa
from .tools.hunter import query_hunter
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


def _try_port_engine(name, run_fn, ips, timeout, emit):
    """尝试运行一个端口扫描引擎，返回 (结果, 是否成功)。"""
    try:
        raw = run_fn(ips, timeout=timeout)
        results = _normalize_portscan(raw)
        total = sum(len(v) for v in results.values())
        if total > 0:
            emit('progress', text=f'  [{name}] 扫描完成: {total} 个端口')
            return results, True
        emit('progress', text=f'  [{name}] 未发现开放端口，降级到下一引擎...')
        return {}, False
    except Exception:
        emit('progress', text=f'  [{name}] 不可用，降级到下一引擎...')
        return {}, False


def do_port_scan(hosts: list[dict], options: dict, emit) -> dict[str, list[dict]]:
    """端口扫描：auto 模式按优先级逐个尝试，成功即停。"""
    chosen = options.get('portscan_tool', 'auto')
    ips = list({h['ip'] for h in hosts})
    timeout = options.get('timeout', 300)

    if chosen == 'nmap':
        if check_nmap_available():
            return _normalize_portscan(run_port_scan(ips, timeout=timeout))
        emit('progress', text='  [nmap] 未安装')
        return {}
    if chosen == 'rustscan':
        results, _ = _try_port_engine('rustscan', run_rustscan, ips, timeout, emit)
        return results
    if chosen == 'masscan':
        results, _ = _try_port_engine('masscan', run_masscan, ips, timeout, emit)
        return results

    engines = []
    if check_nmap_available():
        engines.append(('nmap', lambda ips, timeout: run_port_scan(ips, timeout=timeout)))
    engines.append(('rustscan', run_rustscan))
    engines.append(('masscan', run_masscan))

    for engine_name, engine_fn in engines:
        results, ok = _try_port_engine(engine_name, engine_fn, ips, timeout, emit)
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

    return results


# ── 单目标 / 多目标扫描 ──────────────────────────────────────

def scan_target(target: str, options: dict, emit) -> list[dict]:
    """扫描单个目标，返回主机列表。emit(event, **data) 用于进度回调。"""
    try:
        target = validate_input(target)
    except ValueError as e:
        emit('progress', text=f'  跳过无效目标 {target}: {e}')
        return []

    if is_ip_address(target):
        emit('progress', text=f'  检测到 IP: {target}，反向 DNS...')
        hostname = reverse_dns_lookup(target)
        if not hostname:
            emit('progress', text=f'  无法反向解析 IP: {target}，跳过')
            return []
        base_domain = extract_root_domain(hostname)
        main_ip = target
        main_hostname = hostname
        emit('progress', text=f'  反向解析: {target} → {hostname} → {base_domain}')
    else:
        base_domain = target.lower().rstrip('.')
        ips = resolve_a_record(base_domain)
        if not ips:
            emit('progress', text=f'  无法解析域名: {base_domain}，跳过')
            return []
        main_ip = ips[0]
        main_hostname = base_domain
        emit('progress', text=f'  主域名解析: {base_domain} → {main_ip}')

    # 1. 被动情报收集
    passive_results = []
    if not options.get('no_dns_brute'):
        emit('progress', text=f'  被动情报收集 ({base_domain})...')
        passive_results = do_passive_recon(base_domain, emit)

    # 2. 主动子域名枚举
    subdomains = []
    if not options.get('no_dns_brute'):
        emit('progress', text=f'  子域名枚举 ({base_domain})...')
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
        emit('progress', text=f'  子域名枚举完成: {len(subdomains)} 个有效')

    # 构建主机列表
    all_hosts = [{'hostname': main_hostname, 'ip': main_ip}]
    for sub in subdomains:
        if sub.get('ip'):
            all_hosts.append({'hostname': sub['hostname'], 'ip': sub['ip']})
        else:
            ips = resolve_a_record(sub['hostname'])
            if ips:
                all_hosts.append({'hostname': sub['hostname'], 'ip': ips[0]})

    # 3. 端口扫描
    emit('progress', text=f'  端口扫描 ({len(all_hosts)} 个主机)...')
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

    # 4. Web 探测
    if not options.get('no_web'):
        do_web_probe(all_hosts, options, emit)
    else:
        for host in all_hosts:
            host['web_info'] = []

    # 5. 敏感路径探测
    if not options.get('no_web'):
        emit('progress', text='  敏感路径探测...')
        probe_sensitive_for_hosts(all_hosts)
        sensitive_total = sum(len(h.get('sensitive', [])) for h in all_hosts)
        if sensitive_total:
            emit('progress', text=f'  敏感路径探测完成: {sensitive_total} 条发现')
        else:
            emit('progress', text='  敏感路径探测完成: 无发现')

    # 5.5 JS 文件分析
    if not options.get('no_web'):
        from .js_analyzer import analyze_js_for_hosts
        emit('progress', text='  JavaScript 文件分析...')
        analyze_js_for_hosts(all_hosts)
        js_total = sum(len(h.get('js_findings', [])) for h in all_hosts)
        js_secrets = sum(
            len(j.get('secrets', [])) for h in all_hosts for j in h.get('js_findings', [])
        )
        if js_total:
            detail = f'{js_total} 个文件'
            if js_secrets:
                detail += f', {js_secrets} 条泄露'
            emit('progress', text=f'  JS 分析完成: {detail}')
        else:
            emit('progress', text='  JS 分析完成: 无发现')

    # 6. Banner 抓取
    def _grab_host_banners(host):
        open_ports = [p['port'] for p in host.get('ports', [])]
        return host, grab_banners_for_host(host['ip'], open_ports)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_grab_host_banners, h): h for h in all_hosts}
        for future in as_completed(futures):
            host, banners = future.result()
            host['banners'] = banners

    banner_total = sum(len(h.get('banners', [])) for h in all_hosts)
    if banner_total:
        emit('progress', text=f'  Banner 抓取完成: {banner_total} 条')

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

    all_hosts = []
    for i, target in enumerate(targets, 1):
        emit('progress', text=f'━━━ 目标 [{i}/{len(targets)}] {target} ━━━')
        hosts = scan_target(target, options, emit)
        if hosts:
            for h in hosts:
                h['target'] = target
            all_hosts.extend(hosts)

    if not all_hosts:
        emit('error', text='所有目标均未获取到结果')
        return []

    return all_hosts
