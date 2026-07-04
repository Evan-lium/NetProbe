"""Masscan — 世界上最快的端口扫描器。"""

import re
import subprocess
import threading

from ..scanner import COMMON_PORTS


def run_masscan(
    targets: list[str],
    ports: list[int] | None = None,
    rate: int = 1000,
    timeout: int = 300,
    on_progress=None,
    process_callback=None,
) -> dict[str, list[dict]]:
    """运行 masscan 端口扫描。

    on_progress(msg) — 可选回调，实时输出进度日志。
    返回 {ip: [{'port': int, 'proto': str, 'state': str, 'service': ''}]}
    """
    if not targets:
        return {}

    if ports is None:
        ports = COMMON_PORTS
    if len(ports) == 65535 and ports[0] == 1 and ports[-1] == 65535:
        ports_str = '1-65535'
    else:
        ports_str = ','.join(str(p) for p in ports)

    from .registry import get_tool_path
    cmd = [
        get_tool_path('masscan'),
        *targets,
        '-p', ports_str,
        '--rate', str(rate),
        '--wait', '3',
        '-oL', '-',  # 输出到 stdout
    ]

    results = {}
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

        # 后台线程读取 stderr（masscan 进度信息输出到 stderr）
        def _read_stderr():
            last_pct = -1
            for line in proc.stderr:
                line = line.strip()
                # masscan stderr: "rate: 0.78-kpps, 3.96% done, 0:00:51 remaining, found: 0"
                m = re.search(r'([\d.]+)%\s+done.*?found:\s*(\d+)', line)
                if m:
                    pct = float(m.group(1))
                    found = int(m.group(2))
                    pct_int = int(pct)
                    if pct_int != last_pct and pct_int % 5 == 0:
                        last_pct = pct_int
                        if on_progress:
                            on_progress(f'  [masscan] 进度: {pct_int}% (已发现 {found} 个端口)')

        stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
        stderr_thread.start()

        # 主线程逐行读取 stdout（发现的端口实时输出）
        for line in proc.stdout:
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
            if on_progress:
                on_progress(f'  [masscan] 发现: {ip}:{port}/{proto}')

        proc.wait()
        if process_callback:
            process_callback("end", proc)
        stderr_thread.join(timeout=5)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        try:
            proc.kill()
        except Exception:
            pass
        raise RuntimeError(f"masscan 执行失败: {e}") from e

    return results
