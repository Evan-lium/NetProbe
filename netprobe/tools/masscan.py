"""Masscan — 世界上最快的端口扫描器。"""

import re
import subprocess

from ..scanner import COMMON_PORTS


def run_masscan(
    targets: list[str],
    ports: list[int] | None = None,
    rate: int = 1000,
    timeout: int = 300,
) -> dict[str, list[dict]]:
    """运行 masscan 端口扫描。

    返回 {ip: [{'port': int, 'proto': str, 'state': str, 'service': ''}]}
    """
    if not targets:
        return {}

    if ports is None:
        ports = COMMON_PORTS
    ports_str = ','.join(str(p) for p in ports)

    from tools.registry import get_tool_path
    cmd = [
        get_tool_path('masscan'),
        *targets,
        '-p', ports_str,
        '--rate', str(rate),
        '--wait', '3',
        '-oL', '-',  # 输出到 stdout
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        raise RuntimeError(f"masscan 执行失败: {e}") from e

    return _parse_output(result.stdout)


def _parse_output(text: str) -> dict[str, list[dict]]:
    """解析 masscan -oL 输出格式。

    格式:
    Open tcp 80 93.184.216.34 1620000000
    """
    results = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        state, proto, port_str, ip = parts[0], parts[1], parts[2], parts[3]
        if state.lower() != 'open':
            continue
        port = int(port_str)
        if ip not in results:
            results[ip] = []
        results[ip].append({
            'port': port,
            'proto': proto.lower(),
            'state': 'open',
            'service': '',
            'product': '',
            'version': '',
        })
    return results
