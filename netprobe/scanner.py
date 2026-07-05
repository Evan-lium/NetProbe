import os
import re
import sys
from pathlib import Path

# 确保 nmap 可被 python-nmap 库找到（跨平台）
def _ensure_nmap_in_path():
    """将 nmap 安装目录加入 PATH（如果尚未包含）。"""
    existing = set(p.lower() for p in os.environ.get('PATH', '').split(os.pathsep))
    ext = '.exe' if sys.platform == 'win32' else ''
    nmap_name = f'nmap{ext}'

    search_dirs = []
    if sys.platform == 'win32':
        for drive in ('C', 'D', 'E'):
            for pf in (f'{drive}:\\Program Files\\Nmap',
                       f'{drive}:\\Program Files (x86)\\Nmap'):
                search_dirs.append(pf)
    elif sys.platform == 'darwin':
        search_dirs += ['/usr/local/bin', '/opt/homebrew/bin', '/opt/homebrew/sbin',
                        '/opt/local/bin', '/opt/local/sbin']
    else:
        search_dirs += ['/usr/bin', '/usr/local/bin', '/usr/sbin', '/usr/local/sbin', '/snap/bin']

    for d in search_dirs:
        if d.lower() not in existing and Path(d).is_dir():
            if (Path(d) / nmap_name).is_file():
                os.environ['PATH'] = d + os.pathsep + os.environ.get('PATH', '')
                return

_ensure_nmap_in_path()

import nmap

# 常见端口列表
COMMON_PORTS = [
    # ── 基础协议 ──
    21, 22, 23, 25, 53, 67, 68, 69, 110, 111, 119, 123,
    135, 137, 138, 139, 143, 161, 162, 179, 389, 427, 443, 445,
    465, 514, 515, 587, 631, 636, 873, 990, 992, 993, 995,
    # ── Web / Proxy / API ──
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
    444, 591, 593, 1080, 1311, 2301, 2375, 2376, 2381,
    3000, 3001, 3128, 4443, 4567, 5000, 5601, 5800, 5984,
    6443, 7000, 7001, 7080, 7443, 7474, 8000, 8001, 8002,
    8003, 8005, 8006, 8007, 8008, 8009, 8010, 8042, 8069,
    8080, 8081, 8082, 8083, 8088, 8089, 8090, 8091, 8098,
    8161, 8181, 8200, 8222, 8333, 8443, 8444, 8500, 8530, 8531,
    8649, 8765, 8800, 8834, 8848, 8880, 8881, 8888, 8889,
    8983, 9000, 9001, 9002, 9003, 9043, 9060, 9080, 9090, 9091,
    9100, 9200, 9300, 9418, 9443, 9800, 9981, 9999, 10000,
    10443, 18080, 18081, 28017,
    # ── 数据库 ──
    1433, 1521, 1526, 2638, 3050, 3306, 3307, 3389,
    5000, 5432, 5433, 5984, 6379, 6380, 7473, 7474,
    8529, 9042, 9043, 11211, 27017, 27018, 27019,
    # ── 消息队列 / 缓存 ──
    4369, 5671, 5672, 61613, 61614, 8333, 9092, 9192,
    # ── 远程 / VPN ──
    1080, 1194, 1701, 1723, 2222, 3389, 4444, 4500,
    5060, 5061, 5900, 5901, 5902, 5985, 5986, 7777,
    # ── 文件共享 / 集群 ──
    2049, 8445, 8480, 8889, 9092,
    # ── 监控 / 运维 ──
    2181, 2375, 2376, 2381, 4848, 6161, 6162,
    7070, 7071, 8161, 8500, 8848, 9100, 9990, 9991,
    # ── 目录服务 / 认证 ──
    464, 636, 3268, 3269, 749, 88, 389,
    # ── Docker / K8s / 容器 ──
    2375, 2376, 2381, 4243, 5000, 6443, 8443, 8500, 10250, 10255,
    # ── 云 / SaaS 常见 ──
    3000, 4567, 8123, 8200, 8649, 8800, 9090,
]

PORTS_STR = ','.join(str(p) for p in COMMON_PORTS)

# Top 1000 常用端口（按 nmap 默认扫描端口排序）
TOP1000_PORTS = sorted(set(COMMON_PORTS + [
    # Web / Proxy
    81, 280, 444, 591, 593, 832, 981, 1010, 1080, 1311,
    1527, 2082, 2083, 2086, 2087, 2095, 2096, 2301, 2480,
    3000, 3128, 3333, 4243, 4443, 4567, 4711, 4712, 4993,
    5000, 5104, 5108, 5280, 5281, 5800, 5801, 5802, 6543,
    7000, 7001, 7396, 7474, 8000, 8001, 8008, 8014, 8042,
    8069, 8081, 8083, 8088, 8090, 8091, 8118, 8123, 8172,
    8222, 8243, 8280, 8281, 8333, 8384, 8403, 8530, 8531,
    8834, 8880, 8888, 8983, 9000, 9001, 9043, 9060, 9080,
    9090, 9091, 9100, 9443, 9800, 9981, 9999, 10000,
    10443, 12043, 12443, 16080, 18091, 18092, 20720,
    # SSH / Remote
    2222, 4444, 5555, 6667, 8889,
    # Mail
    26, 109, 119, 587, 2525, 25565,
    # Database
    1526, 2638, 3050, 5001, 5433, 5984, 6380, 7473,
    8529, 9042, 11211, 27018, 27019, 28017,
    # DNS
    43, 853, 2443, 5353,
    # File sharing
    111, 135, 137, 138, 139, 515, 2049, 8445,
    # VPN / Tunnel
    1194, 1701, 1723, 4500, 5060, 5061,
    # Monitoring / Mgmt
    161, 162, 514, 515, 2181, 3273, 4848, 6161, 6162,
    7071, 8161, 8444, 9100, 9990,
    # Message Queue
    4369, 5671, 5672, 61613, 61614,
    # Common services
    67, 68, 69, 123, 179, 389, 636, 990, 992,
    1025, 1026, 1027, 1028, 1029, 1030, 1434, 1812,
    1813, 2000, 2001, 2048, 2223, 3268, 3269, 3389,
    4445, 5003, 5060, 5357, 5631, 5632, 5900, 5901,
    5902, 5903, 5985, 5986, 6000, 6001, 6646, 7002,
    7070, 7071, 8009, 8010, 8089, 8443, 8888, 9003,
    9092, 9192, 9990, 9991, 9999,
]))

TOP1000_PORTS_STR = ','.join(str(p) for p in TOP1000_PORTS)


def resolve_ports(preset: str = "common", custom: str = "") -> tuple[list[int], str]:
    """根据预设名解析端口列表。

    返回 (list[int], str) — 分别用于 masscan/rustscan 和 nmap。
    """
    if preset == "all":
        ports_list = list(range(1, 65536))
    elif preset == "top1000":
        ports_list = TOP1000_PORTS
    elif preset == "custom" and custom.strip():
        ports_list = _parse_custom_ports(custom.strip())
    else:  # common (default)
        ports_list = list(COMMON_PORTS)

    # nmap 参数有 Windows 命令行长度限制 (~8191)，全端口用范围语法
    if preset == "all":
        ports_str = "1-65535"
    else:
        ports_str = ','.join(str(p) for p in ports_list)
    return ports_list, ports_str


def _parse_custom_ports(raw: str) -> list[int]:
    """解析自定义端口字符串，支持逗号分隔和范围。如 '80,443,8000-9000'。"""
    ports = set()
    for part in raw.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                start, end = int(start.strip()), int(end.strip())
                if 1 <= start <= 65535 and 1 <= end <= 65535:
                    ports.update(range(min(start, end), max(start, end) + 1))
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return sorted(ports) if ports else list(COMMON_PORTS)


def check_nmap_available() -> bool:
    """检查 nmap 是否可用（仅检测可执行文件，不发起扫描）。"""
    try:
        nmap.PortScanner()
        return True
    except (nmap.PortScannerError, FileNotFoundError, OSError):
        return False


def run_dns_brute(
    domain: str,
    wordlist_path: str,
    timeout: int = 300,
) -> list[dict]:
    """执行 nmap dns-brute 脚本，返回原始结果列表。"""
    nm = nmap.PortScanner()
    args = (
        f'-Pn -sn '
        f'--script dns-brute '
        f'--script-args dns-brute.hostlist={wordlist_path} '
        f'--host-timeout {timeout}s'
    )
    try:
        nm.scan(hosts=domain, arguments=args)
    except nmap.PortScannerError as e:
        raise RuntimeError(f"nmap 扫描失败: {e}") from e

    return parse_dns_brute_output(nm)


def run_port_scan(
    targets: list[str],
    ports: str = PORTS_STR,
    timeout: int = 300,
    on_progress=None,
) -> dict[str, dict]:
    """对目标列表执行端口扫描 + 服务版本检测。

    两步策略：
    1. 快速扫描（-sS/-sT）发现 open 端口
    2. 仅对 open 端口做 -sV 服务版本检测

    on_progress(msg) — 可选回调，输出进度日志。
    返回: {ip: {'hostname': str, 'ports': [...]}}
    """
    import time

    if not targets:
        return {}

    nm = nmap.PortScanner()
    targets_str = ' '.join(targets)
    log = on_progress or (lambda msg: None)

    # 第一步：快速端口发现（不做版本检测，速度快）
    log(f'  [nmap] 端口发现: {len(targets)} 个目标, 端口范围 {ports[:50]}{"..." if len(ports) > 50 else ""}')
    t0 = time.time()
    try:
        nm.scan(hosts=targets_str, arguments=f'-Pn -p {ports} --max-retries 2 --open --stats-every 10s')
    except nmap.PortScannerError as e:
        raise RuntimeError(f"端口扫描失败: {e}") from e
    elapsed = time.time() - t0
    log(f'  [nmap] 端口发现完成 ({elapsed:.1f}s)')

    # 收集每个 IP 的 open 端口
    ip_open_ports = {}
    hostnames_map = {}
    for host in nm.all_hosts():
        host_data = nm[host]
        hn_list = host_data.get('hostnames', [])
        hostnames_map[host] = hn_list[0]['name'] if hn_list else ''
        open_list = []
        for proto in ('tcp', 'udp'):
            proto_data = host_data.get(proto, {})
            if not isinstance(proto_data, dict):
                continue
            for port_str, port_info in proto_data.items():
                if isinstance(port_info, dict) and port_info.get('state') == 'open':
                    open_list.append((int(port_str), proto))
        if open_list:
            ip_open_ports[host] = open_list
            for p, pr in open_list:
                log(f'  [nmap] 发现: {host}:{p}/{pr}')

    if not ip_open_ports:
        return {}

    # 第二步：批量对所有 IP 的 open 端口做 -sV 服务版本检测 + OS 识别
    # 合并所有端口，nmap 只对 open 端口做版本检测
    all_ports = sorted(set(p[0] for ports in ip_open_ports.values() for p in ports))
    all_ips = list(ip_open_ports.keys())
    port_str = ','.join(str(p) for p in all_ports)
    targets_str = ' '.join(all_ips)

    total_open = sum(len(v) for v in ip_open_ports.values())
    log(f'  [nmap] 服务版本检测: {total_open} 个开放端口...')
    t1 = time.time()

    try:
        nm_sv = nmap.PortScanner()
        try:
            nm_sv.scan(hosts=targets_str, arguments=f'-Pn -sV -O -p {port_str} --max-retries 2 --stats-every 10s')
        except nmap.PortScannerError:
            nm_sv.scan(hosts=targets_str, arguments=f'-Pn -sV -p {port_str} --max-retries 2 --stats-every 10s')
    except nmap.PortScannerError:
        # 全部失败，返回基础端口信息
        log(f'  [nmap] 服务检测失败，返回基础端口信息')
        results = {}
        for ip, port_list in ip_open_ports.items():
            results[ip] = {
                'hostname': hostnames_map.get(ip, ''),
                'os': '',
                'ports': [{'port': p, 'proto': pr, 'state': 'open', 'service': '', 'product': '', 'version': ''} for p, pr in port_list],
            }
        return results

    elapsed = time.time() - t1
    log(f'  [nmap] 服务版本检测完成 ({elapsed:.1f}s)')

    results = {}
    for ip, port_list in ip_open_ports.items():
        sv_data = nm_sv[ip] if ip in nm_sv.all_hosts() else {}

        # 提取 OS 信息
        os_info = ''
        os_matches = sv_data.get('osmatch', [])
        if os_matches:
            best = os_matches[0]
            os_info = best.get('name', '')
            accuracy = best.get('accuracy', '')
            if accuracy:
                os_info += f' ({accuracy}%)'

        ports_result = []
        for port_num, proto in port_list:
            proto_data = sv_data.get(proto, {})
            if isinstance(proto_data, dict):
                port_info = proto_data.get(port_num) or proto_data.get(str(port_num), {})
            else:
                port_info = {}
            ports_result.append({
                'port': port_num,
                'proto': proto,
                'state': 'open',
                'service': port_info.get('name', '') if isinstance(port_info, dict) else '',
                'product': port_info.get('product', '') if isinstance(port_info, dict) else '',
                'version': port_info.get('version', '') if isinstance(port_info, dict) else '',
                'cpe': ','.join(port_info.get('cpe', [])) if isinstance(port_info, dict) and port_info.get('cpe') else '',
            })

        results[ip] = {
            'hostname': hostnames_map.get(ip, ''),
            'os': os_info,
            'ports': ports_result,
        }

    return results


def parse_dns_brute_output(nm: nmap.PortScanner) -> list[dict]:
    """从 python-nmap 结果中提取 dns-brute 输出。"""
    results = []
    seen = set()

    for host in nm.all_hosts():
        host_data = nm[host]

        scripts = host_data.get('hostscript', [])
        for script in scripts:
            if script.get('id') == 'dns-brute':
                results.extend(_parse_script_output(script.get('output', '')))

        for proto in host_data.get('tcp', {}), host_data.get('udp', {}):
            if not isinstance(proto, dict):
                continue
            for port_data in proto.values():
                if not isinstance(port_data, dict):
                    continue
                for sid, output in port_data.get('script', {}).items():
                    if sid == 'dns-brute':
                        results.extend(_parse_script_output(output))

    unique = []
    for item in results:
        key = (item['hostname'], item['ip'])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _parse_script_output(text: str) -> list[dict]:
    """解析 dns-brute 脚本的文本输出。"""
    results = []
    for line in text.splitlines():
        line = line.strip()
        if ' - ' not in line:
            continue
        match = re.match(r'^(\S+)\s*-\s*(\S+)', line)
        if match:
            hostname = match.group(1).rstrip('.')
            ip = match.group(2)
            results.append({'hostname': hostname, 'ip': ip})
    return results
