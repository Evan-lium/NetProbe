"""DNSx — 快速 DNS 解析验证工具。"""

import json
import os
import subprocess
import tempfile


def run_dnsx(
    hostnames: list[str],
    timeout: int = 120,
) -> list[dict]:
    """对主机名列表做 DNS 解析验证。

    输入: ['www.example.com', 'mail.example.com', ...]
    返回: [{'hostname': str, 'ip': str}, ...]  仅包含可解析的
    """
    if not hostnames:
        return []

    fd, path = tempfile.mkstemp(suffix='.txt', prefix='dnsx_')
    try:
        with os.fdopen(fd, 'w') as f:
            for h in hostnames:
                f.write(h + '\n')

        from .registry import get_tool_path
        cmd = [
            get_tool_path('dnsx'),
            '-l', path,
            '-silent',
            '-json',
            '-a',
            '-r', '8.8.8.8,1.1.1.1',
            '-t', '10',
            '-timeout', '5',
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            raise RuntimeError(f"dnsx 执行失败: {e}") from e

    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    return _parse_output(result.stdout)


def _parse_output(text: str) -> list[dict]:
    """解析 dnsx JSON 输出。"""
    results = []
    seen = set()
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        hostname = data.get('host', '')
        a_records = data.get('a', [])
        if not hostname or not a_records:
            continue

        hostname = hostname.rstrip('.').lower()
        if hostname in seen:
            continue
        seen.add(hostname)

        results.append({
            'hostname': hostname,
            'ip': a_records[0],
        })

    return results
