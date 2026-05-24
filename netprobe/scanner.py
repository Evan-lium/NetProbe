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
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 6379,
    8080, 8443, 9200, 9300, 27017,
]

PORTS_STR = ','.join(str(p) for p in COMMON_PORTS)


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
) -> dict[str, dict]:
    """对目标列表执行端口扫描 + 服务版本检测。

    两步策略：
    1. 快速扫描（-sS/-sT）发现 open 端口
    2. 仅对 open 端口做 -sV 服务版本检测

    返回: {ip: {'hostname': str, 'ports': [...]}}
    """
    if not targets:
        return {}

    nm = nmap.PortScanner()
    targets_str = ' '.join(targets)

    # 第一步：快速端口发现（不做版本检测，速度快）
    try:
        nm.scan(hosts=targets_str, arguments=f'-Pn -p {ports} --max-retries 2 --open')
    except nmap.PortScannerError as e:
        raise RuntimeError(f"端口扫描失败: {e}") from e

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

    if not ip_open_ports:
        return {}

    # 第二步：批量对所有 IP 的 open 端口做 -sV 服务版本检测 + OS 识别
    # 合并所有端口，nmap 只对 open 端口做版本检测
    all_ports = sorted(set(p[0] for ports in ip_open_ports.values() for p in ports))
    all_ips = list(ip_open_ports.keys())
    port_str = ','.join(str(p) for p in all_ports)
    targets_str = ' '.join(all_ips)

    try:
        nm_sv = nmap.PortScanner()
        try:
            nm_sv.scan(hosts=targets_str, arguments=f'-Pn -sV -O -p {port_str} --max-retries 2')
        except nmap.PortScannerError:
            nm_sv.scan(hosts=targets_str, arguments=f'-Pn -sV -p {port_str} --max-retries 2')
    except nmap.PortScannerError:
        # 全部失败，返回基础端口信息
        results = {}
        for ip, port_list in ip_open_ports.items():
            results[ip] = {
                'hostname': hostnames_map.get(ip, ''),
                'os': '',
                'ports': [{'port': p, 'proto': pr, 'state': 'open', 'service': '', 'product': '', 'version': ''} for p, pr in port_list],
            }
        return results

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
