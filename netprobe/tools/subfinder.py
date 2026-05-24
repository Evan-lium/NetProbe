"""Subfinder — 被域名被动枚举，聚合 30+ 数据源。"""

import json
import subprocess


def run_subfinder(
    domain: str,
    timeout: int = 300,
    extra_args: list[str] | None = None,
) -> list[dict]:
    """运行 subfinder 枚举子域名。

    返回 [{'hostname': str, 'ip': str}, ...]
    """
    from .registry import get_tool_path
    cmd = [
        get_tool_path('subfinder'),
        '-d', domain,
        '-silent',
        '-json',
        '-t', '10',
        '-timeout', str(timeout),
    ]
    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        raise RuntimeError(f"subfinder 执行失败: {e}") from e

    if result.returncode != 0 and result.stderr:
        raise RuntimeError(f"subfinder 错误: {result.stderr.strip()}")

    hosts = []
    seen = set()
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            # 纯文本格式 fallback
            hostname = line
            ip = ''
        else:
            hostname = data.get('host', '')
            ip = data.get('ip', '')

        if not hostname:
            continue
        hostname = hostname.rstrip('.').lower()
        if hostname in seen:
            continue
        seen.add(hostname)
        hosts.append({'hostname': hostname, 'ip': ip})

    return hosts
