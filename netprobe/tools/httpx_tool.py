"""Httpx — ProjectDiscovery 出品的批量 Web 探测工具。"""

import json
import os
import subprocess
import tempfile


def run_httpx(
    hosts: list[str],
    timeout: int = 120,
) -> list[dict]:
    """对主机列表运行 httpx 探测。

    输入: ['example.com', '93.184.216.34', ...]
    返回: [{'hostname': str, 'ip': str, 'url': str, 'status': int, 'title': str, 'tech': str, 'port': int}, ...]
    """
    if not hosts:
        return []

    # 写入临时文件作为 httpx 输入
    fd, path = tempfile.mkstemp(suffix='.txt', prefix='httpx_')
    try:
        with os.fdopen(fd, 'w') as f:
            for h in hosts:
                f.write(h + '\n')

        from .registry import get_tool_path
        cmd = [
            get_tool_path('httpx'),
            '-l', path,
            '-silent',
            '-json',
            '-threads', '10',
            '-timeout', '10',
            '-follow-redirects', 'false',
            '-status-code',
            '-title',
            '-tech-detect',
            '-ip',
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            raise RuntimeError(f"httpx 执行失败: {e}") from e

    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    return _parse_output(result.stdout)


def _parse_output(text: str) -> list[dict]:
    """解析 httpx JSON 输出。"""
    results = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        url = data.get('url', '')
        status = data.get('status_code', 0)
        title = data.get('title', '')
        host = data.get('host', '')
        ip_list = data.get('a', [])
        ip = ip_list[0] if ip_list else ''
        tech_list = data.get('tech', [])
        tech = ', '.join(tech_list) if isinstance(tech_list, list) else str(tech_list)

        # 从 URL 提取端口
        port = 0
        if url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            except Exception:
                pass

        results.append({
            'hostname': host,
            'ip': ip,
            'url': url,
            'status': status,
            'title': title,
            'tech': tech,
            'port': port,
        })

    return results
