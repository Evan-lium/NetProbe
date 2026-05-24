"""RustScan — 快速端口发现，自动调用 nmap 做服务检测。"""

import json
import subprocess

# 先确保 nmap 路径注入（必须在 import nmap 之前）
from ..scanner import COMMON_PORTS  # noqa: E402 (triggers _ensure_nmap_in_path)

import nmap as nmap_lib


def run_rustscan(
    targets: list[str],
    ports: list[int] | None = None,
    timeout: int = 300,
    ulimit: int = 5000,
) -> dict[str, list[dict]]:
    """运行 RustScan 端口扫描 + nmap 服务检测。

    RustScan 快速发现开放端口，然后自动调用 nmap -sV 做版本检测。
    返回格式与 nmap run_port_scan 一致。
    """
    if not targets:
        return {}

    if ports is None:
        ports = COMMON_PORTS
    ports_str = ','.join(str(p) for p in ports)
    targets_str = ' '.join(targets)

    # 第一步：RustScan 快速发现端口（不调用 nmap，自己解析）
    from .registry import get_tool_path
    cmd = [
        get_tool_path('rustscan'),
        '-a', targets_str,
        '-p', ports_str,
        '--ulimit', str(ulimit),
        '--no-nmap',
        '--',  # 不传 nmap 参数
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        raise RuntimeError(f"rustscan 执行失败: {e}") from e

    # 解析 RustScan 输出，提取开放端口
    open_ports_by_ip = _parse_rustscan_output(result.stdout + '\n' + result.stderr)

    if not open_ports_by_ip:
        return {}

    # 第二步：对发现开放端口的主机用 nmap -sV 做详细检测
    nm = nmap_lib.PortScanner()
    all_results = {}

    for ip, port_list in open_ports_by_ip.items():
        if not port_list:
            continue
        port_str = ','.join(str(p) for p in port_list)
        try:
            nm.scan(ip, ports=port_str, arguments=f'-Pn -sV --host-timeout {timeout}s')
        except nmap_lib.PortScannerError:
            continue

        host_data = nm.get(ip, {})
        hostnames = host_data.get('hostnames', [])
        ports_result = []

        for proto in ('tcp', 'udp'):
            proto_data = host_data.get(proto, {})
            if not isinstance(proto_data, dict):
                continue
            for port_str_key, port_info in proto_data.items():
                if not isinstance(port_info, dict):
                    continue
                ports_result.append({
                    'port': int(port_str_key),
                    'proto': proto,
                    'state': port_info.get('state', ''),
                    'service': port_info.get('name', ''),
                    'product': port_info.get('product', ''),
                    'version': port_info.get('version', ''),
                })

        all_results[ip] = {
            'hostname': hostnames[0]['name'] if hostnames else '',
            'ports': ports_result,
        }

    return all_results


def _parse_rustscan_output(text: str) -> dict[str, list[int]]:
    """从 RustScan 输出中提取 IP -> 开放端口映射。

    典型输出:
    Open 93.184.216.34:80
    Open 93.184.216.34:443
    """
    results = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith('Open'):
            continue
        # 格式: "Open IP:PORT" 或 "[+] IP:PORT"
        import re
        match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
        if match:
            ip = match.group(1)
            port = int(match.group(2))
            if ip not in results:
                results[ip] = []
            results[ip].append(port)
    return results
