import json
import os
import queue
import threading
import uuid
from datetime import datetime

import requests as req_lib
from flask import Flask, Response, jsonify, render_template, request

from dns_utils import resolve_a_record, reverse_dns_lookup
from formatter import save_results
from scanner import check_nmap_available, run_dns_brute, run_port_scan
from tools.dnsx import run_dnsx
from tools.httpx_tool import run_httpx
from tools.masscan import run_masscan
from tools.rustscan import run_rustscan
from tools.subfinder import run_subfinder
from tools.registry import get_available_tools
from utils import extract_root_domain, is_ip_address, validate_input
from web_probe import probe_web_for_host
from banner_grab import grab_banners_for_host
from wordlist import get_default_wordlist_path, load_external_wordlist

app = Flask(__name__)
tasks: dict[str, dict] = {}

# 自动清理已完成任务（超过 1 小时的）
_TASK_MAX_AGE = 3600


def _cleanup_old_tasks():
    """清理超时的已完成任务，防止内存泄漏。"""
    now = datetime.now()
    expired = [
        tid for tid, t in tasks.items()
        if t.get('status') in ('done', 'error')
        and (now - t.get('created_at', now)).total_seconds() > _TASK_MAX_AGE
    ]
    for tid in expired:
        del tasks[tid]


def parse_targets(raw: str) -> list[str]:
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

    # Subfinder
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

    # Nmap dns-brute
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
    """DNS 验证：auto 模式按优先级逐个尝试，成功即停。

    优先级: dnspython（最可靠）> dnsx
    """
    chosen = options.get('dns_tool', 'auto')

    if chosen in ('auto', 'dnspython'):
        from dns_utils import resolve_a_record
        valid = []
        for h in hostnames:
            if resolve_a_record(h):
                valid.append(h)
        emit('progress', text=f'  [dnspython] 验证完成: {len(valid)}/{len(hostnames)} 可解析')
        return valid

    # dnsx
    if chosen == 'dnsx':
        try:
            results = run_dnsx(hostnames, timeout=120)
            valid = [r['hostname'] for r in results]
            emit('progress', text=f'  [dnsx] 验证完成: {len(valid)}/{len(hostnames)} 可解析')
            return valid
        except Exception:
            emit('progress', text=f'  [dnsx] 不可用')
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
    """端口扫描：auto 模式按优先级逐个尝试，成功即停。

    优先级: Nmap（最可靠）> RustScan > Masscan
    """
    chosen = options.get('portscan_tool', 'auto')
    ips = list({h['ip'] for h in hosts})
    timeout = options.get('timeout', 300)

    # 指定引擎：只跑指定的
    if chosen == 'nmap':
        if check_nmap_available():
            return _normalize_portscan(run_port_scan(ips, timeout=timeout))
        emit('progress', text='  [nmap] 未安装')
        return {}
    if chosen == 'rustscan':
        results, ok = _try_port_engine('rustscan', run_rustscan, ips, timeout, emit)
        return results
    if chosen == 'masscan':
        results, ok = _try_port_engine('masscan', run_masscan, ips, timeout, emit)
        return results

    # auto 模式：按可靠性优先级逐个尝试，有结果就停
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
    """Web 探测：auto 模式按优先级逐个尝试，成功即停。

    优先级: Python requests（最可靠）> httpx
    """
    chosen = options.get('web_tool', 'auto')

    # Python 内置探测：最可靠，总能用
    if chosen in ('auto', 'python'):
        emit('progress', text=f'  [python] Web 探测...')
        for host in hosts:
            open_ports = [p['port'] for p in host.get('ports', [])]
            host['web_info'] = probe_web_for_host(host['hostname'], host['ip'], open_ports)
        total = sum(len(h.get('web_info', [])) for h in hosts)
        emit('progress', text=f'  [python] 发现 {total} 个 Web 站点')
        return

    # httpx
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
        # httpx 失败，降级到 Python
        emit('progress', text=f'  降级到 Python 探测...')
        for host in hosts:
            open_ports = [p['port'] for p in host.get('ports', [])]
            host['web_info'] = probe_web_for_host(host['hostname'], host['ip'], open_ports)


# ── 单目标扫描 ──────────────────────────────────────

def scan_single_target(target: str, options: dict, emit) -> list[dict]:
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

    # 1. 子域名枚举
    subdomains = []
    if not options.get('no_dns_brute'):
        emit('progress', text=f'  子域名枚举 ({base_domain})...')
        raw = do_subdomain_enum(base_domain, options, emit)
        # 过滤：只保留属于 base_domain 的
        from dns_utils import is_subdomain_of
        raw = [s for s in raw if is_subdomain_of(s['hostname'], base_domain)]
        # DNS 验证
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

    # 2. 端口扫描
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

    # 3. Web 探测
    if not options.get('no_web'):
        do_web_probe(all_hosts, options, emit)
    else:
        for host in all_hosts:
            host['web_info'] = []

    # 4. Banner 抓取
    for host in all_hosts:
        open_ports = [p['port'] for p in host.get('ports', [])]
        host['banners'] = grab_banners_for_host(host['ip'], open_ports)
    banner_total = sum(len(h.get('banners', [])) for h in all_hosts)
    if banner_total:
        emit('progress', text=f'  Banner 抓取完成: {banner_total} 条')

    return all_hosts


# ── 扫描主流程 ──────────────────────────────────────

def run_scan(task_id: str, raw_targets: str, options: dict):
    task = tasks[task_id]
    emit = lambda msg, **kw: _emit(task_id, msg, **kw)

    try:
        req_lib.packages.urllib3.disable_warnings(
            req_lib.packages.urllib3.exceptions.InsecureRequestWarning
        )

        # 报告可用工具
        tools = get_available_tools()
        avail = [f"{v['label']}" for v in tools.values() if v['available']]
        emit('progress', text=f'可用工具: {", ".join(avail) if avail else "无外部工具 (仅内置)"}')

        targets = parse_targets(raw_targets)
        if not targets:
            emit('error', text='未提供有效的扫描目标')
            return

        emit('progress', text=f'共 {len(targets)} 个目标: {", ".join(targets)}')

        all_hosts = []
        domain_labels = []

        for i, target in enumerate(targets, 1):
            emit('progress', text=f'━━━ 目标 [{i}/{len(targets)}] {target} ━━━')
            hosts = scan_single_target(target, options, emit)
            if hosts:
                for h in hosts:
                    h['target'] = target
                all_hosts.extend(hosts)
                domain_labels.append(hosts[0].get('hostname', target))

        if not all_hosts:
            emit('error', text='所有目标均未获取到结果')
            return

        label = '+'.join(domain_labels[:3])
        if len(domain_labels) > 3:
            label += f'+{len(domain_labels)-3}more'

        task['hosts'] = all_hosts
        task['base_domain'] = label
        task['status'] = 'done'
        emit('done', hosts=all_hosts, base_domain=label)

    except Exception as e:
        emit('error', text=f'扫描异常: {e}')
        task['status'] = 'error'


def _emit(task_id: str, event: str, **data):
    task = tasks.get(task_id)
    if task and task.get('queue'):
        payload = {'event': event, **data}
        task['queue'].put(payload)
    if event in ('done', 'error'):
        task['status'] = event


# ── 路由 ──────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/tools')
def api_tools():
    """返回可用工具列表。"""
    return jsonify(get_available_tools())


@app.route('/api/scan', methods=['POST'])
def api_scan():
    body = request.get_json(force=True)
    raw_targets = body.get('target', '').strip()
    if not raw_targets:
        return jsonify({'error': '目标不能为空'}), 400

    task_id = uuid.uuid4().hex[:12]
    tasks[task_id] = {
        'id': task_id,
        'target': raw_targets,
        'status': 'running',
        'queue': queue.Queue(),
        'hosts': [],
        'base_domain': '',
        'created_at': datetime.now(),
    }
    _cleanup_old_tasks()

    options = {
        'no_dns_brute': body.get('no_dns_brute', False),
        'no_web': body.get('no_web', False),
        'no_validate': body.get('no_validate', False),
        'timeout': body.get('timeout', 300),
        'subdomain_tool': body.get('subdomain_tool', 'auto'),
        'portscan_tool': body.get('portscan_tool', 'auto'),
        'web_tool': body.get('web_tool', 'auto'),
        'dns_tool': body.get('dns_tool', 'auto'),
    }

    thread = threading.Thread(target=run_scan, args=(task_id, raw_targets, options), daemon=True)
    thread.start()

    return jsonify({'task_id': task_id})


@app.route('/api/stream/<task_id>')
def api_stream(task_id):
    task = tasks.get(task_id)
    if not task:
        return jsonify({'error': '任务不存在'}), 404

    def generate():
        q = task['queue']
        while True:
            try:
                data = q.get(timeout=60)
                yield f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
                if data.get('event') in ('done', 'error'):
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'event': 'heartbeat'})}\n\n"
                if task['status'] in ('done', 'error'):
                    break

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/result/<task_id>')
def api_result(task_id):
    task = tasks.get(task_id)
    if not task:
        return jsonify({'error': '任务不存在'}), 404
    return jsonify({
        'task_id': task_id,
        'status': task['status'],
        'base_domain': task.get('base_domain', ''),
        'hosts': task.get('hosts', []),
    })


@app.route('/api/download/<task_id>/<fmt>')
def api_download(task_id, fmt):
    task = tasks.get(task_id)
    if not task or task['status'] != 'done':
        return jsonify({'error': '结果未就绪'}), 404

    hosts = task.get('hosts', [])
    base_domain = task.get('base_domain', 'result')
    date_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'{base_domain}_{date_str}.{fmt}'

    filepath = os.path.join(os.path.dirname(__file__), 'output', filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    save_results(hosts, filepath, fmt, base_domain)

    from flask import send_file
    return send_file(filepath, as_attachment=True, download_name=filename)


if __name__ == '__main__':
    print('[*] 域名探测 Web 服务启动中...')
    print('[*] 访问 http://127.0.0.1:5000')
    app.run(host='0.0.0.0', port=5000, debug=False)
