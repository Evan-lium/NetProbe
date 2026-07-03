"""RustScan — 快速端口发现，自动调用 nmap 做服务检测。"""

import re
import subprocess
import threading

# 先确保 nmap 路径注入（必须在 import nmap 之前）
from ..scanner import COMMON_PORTS  # noqa: E402 (triggers _ensure_nmap_in_path)

import nmap as nmap_lib


def run_rustscan(
    targets: list[str],
    ports: list[int] | None = None,
    timeout: int = 300,
    ulimit: int = 5000,
    on_progress=None,
    process_callback=None,
) -> dict[str, list[dict]]:
    """运行 RustScan 端口扫描 + nmap 服务检测。

    on_progress(msg) — 可选回调，实时输出进度日志。
    返回格式与 nmap run_port_scan 一致。
    """
    if not targets:
        return {}

    if ports is None:
        ports = COMMON_PORTS
    if len(ports) == 65535 and ports[0] == 1 and ports[-1] == 65535:
        ports_str = '1-65535'
    else:
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

    open_ports_by_ip: dict[str, list[int]] = {}
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        if process_callback:
            process_callback("start", proc)

        # RustScan 输出到 stderr，逐行读取
        def _read_stderr():
            for line in proc.stderr:
                line = line.strip()
                match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                if match:
                    ip = match.group(1)
                    port = int(match.group(2))
                    if ip not in open_ports_by_ip:
                        open_ports_by_ip[ip] = []
                    open_ports_by_ip[ip].append(port)
                    if on_progress:
                        on_progress(f'  [rustscan] 发现: {ip}:{port}')

        # stdout 也读取（有些版本输出到 stdout）
        def _read_stdout():
            for line in proc.stdout:
                line = line.strip()
                match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                if match:
                    ip = match.group(1)
                    port = int(match.group(2))
                    if ip not in open_ports_by_ip:
                        open_ports_by_ip[ip] = []
                    if port not in open_ports_by_ip[ip]:
                        open_ports_by_ip[ip].append(port)
                        if on_progress:
                            on_progress(f'  [rustscan] 发现: {ip}:{port}')

        stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
        stdout_thread = threading.Thread(target=_read_stdout, daemon=True)
        stderr_thread.start()
        stdout_thread.start()

        proc.wait()
        if process_callback:
            process_callback("end", proc)
        stderr_thread.join(timeout=5)
        stdout_thread.join(timeout=5)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        try:
            proc.kill()
        except Exception:
            pass
        raise RuntimeError(f"rustscan 执行失败: {e}") from e

    if not open_ports_by_ip:
        return {}

    # 第二步：对发现开放端口的主机用 nmap -sV 做详细检测
    if on_progress:
        total_found = sum(len(v) for v in open_ports_by_ip.values())
        on_progress(f'  [rustscan] 发现 {total_found} 个开放端口，nmap -sV 服务检测...')

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
                    'cpe': ','.join(port_info['cpe']) if port_info.get('cpe') else '',
                })

        all_results[ip] = {
            'hostname': hostnames[0]['name'] if hostnames else '',
            'ports': ports_result,
        }

    return all_results
