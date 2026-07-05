"""Nuclei — ProjectDiscovery 漏洞扫描器集成。

调用 nuclei 对 Web 站点批量扫描，解析 JSONL 输出提取漏洞信息。
照抄 masscan.py 的 subprocess + 逐行解析 + 进度回调 + process_callback 模式。
"""

import json
import subprocess
import tempfile
import threading


def run_nuclei(
    urls: list[str],
    severity: str = 'critical,high,medium',
    templates: str | None = None,
    rate_limit: int = 50,
    concurrency: int = 10,
    timeout: int = 5,
    max_time: int = 300,
    on_progress=None,
    process_callback=None,
) -> list[dict]:
    """运行 nuclei 漏洞扫描。

    参数:
        urls: 待扫描的 URL 列表
        severity: 严重度过滤 (critical,high,medium,low,info)
        templates: 模板目录/标签（如 'cves/,vulnerabilities/'），None=默认全部
        rate_limit: 每秒请求数限制
        concurrency: 并发模板数
        timeout: 单个请求超时秒数
        max_time: 整体最大扫描时间秒数
        on_progress: 进度回调 on_progress(text)
        process_callback: 子进程注册回调 process_callback('start'|'end', proc)
    返回: [{template_id, name, severity, cve, cvss_score, url, matched_at, extracted_data}, ...]
    """
    from .registry import get_tool_path

    if not urls:
        return []

    # 把 URLs 写入临时文件，nuclei 用 -l 批量扫描
    fd, url_file = tempfile.mkstemp(suffix='.txt', prefix='nuclei_targets_')
    try:
        import os
        os.write(fd, '\n'.join(urls).encode())
        os.close(fd)
    except OSError:
        return []

    cmd = [
        get_tool_path('nuclei'),
        '-l', url_file,
        '-j', '-silent',
        '-severity', severity,
        '-rl', str(rate_limit),
        '-bs', str(concurrency),
        '-timeout', str(timeout),
        '-retries', '1',
        '-no-color',
        '-duc',
    ]
    # 模板范围（控制扫描时长，6287 全量模板太慢）
    if templates:
        cmd.extend(['-t', templates])
    else:
        # 默认只跑高价值类别，避免 6000+ 全量模板超时
        cmd.extend(['-tags', 'cve,vuln,misconfig,exposure,detect,tech,fuzz'])
    if max_time and max_time < 300:
        # nuclei 无 -max-time，用 -timeout 间接控制；短超时减少等待
        cmd.extend(['-timeout', str(min(timeout, 3))])
    if templates:
        cmd.extend(['-t', templates])

    vulns = []

    def _read_stderr(proc):
        """后台线程读 stderr，转发为进度日志。"""
        try:
            for line in proc.stderr:
                line = line.strip()
                if not line:
                    continue
                # nuclei stderr 含 INF/WRN/ERR 日志
                if on_progress and ('[' in line or 'ERR' in line or 'FTL' in line):
                    # 只上报错误/警告，跳过 INF 噪音
                    if 'ERR' in line or 'FTL' in line or 'WRN' in line:
                        on_progress(f'    nuclei: {line[40:] if len(line) > 40 else line}')
        except Exception:
            pass

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            encoding='utf-8',
            errors='replace',
        )

        if process_callback:
            process_callback('start', proc)

        # 后台读 stderr
        stderr_thread = threading.Thread(target=_read_stderr, args=(proc,), daemon=True)
        stderr_thread.start()

        # 主线程逐行读 stdout（JSONL），用后台计时线程在超时后 kill 进程
        import time
        max_time_val = max_time or 300

        def _timeout_killer():
            time.sleep(max_time_val)
            if proc.poll() is None:
                try:
                    proc.kill()
                    if on_progress:
                        on_progress('    [nuclei] 达到最大扫描时间，终止')
                except Exception:
                    pass

        killer_thread = threading.Thread(target=_timeout_killer, daemon=True)
        killer_thread.start()

        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            vuln = _parse_nuclei_result(data)
            if vuln:
                vulns.append(vuln)
                if on_progress:
                    sev = vuln.get('severity', 'info')
                    name = vuln.get('name', '')[:60]
                    on_progress(f'    [{sev}] {name}')

        proc.wait(timeout=15)

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        try:
            proc.kill()
        except Exception:
            pass
        if isinstance(e, FileNotFoundError):
            if on_progress:
                on_progress('    [nuclei] 工具未安装，跳过漏洞扫描')
            return []
    except Exception:
        pass
    finally:
        if process_callback and 'proc' in dir():
            try:
                process_callback('end', proc)
            except Exception:
                pass
        # 清理临时文件
        try:
            import os
            os.unlink(url_file)
        except OSError:
            pass

    return vulns


def _parse_nuclei_result(data: dict) -> dict | None:
    """解析 nuclei JSONL 单行结果，提取标准化漏洞字段（含分类标签和 CWE）。"""
    info = data.get('info') or {}

    # CVE（取第一个）
    classification = info.get('classification') or {}
    cve_ids = classification.get('cve-id') or []
    if isinstance(cve_ids, list) and cve_ids:
        cve = cve_ids[0]
    elif isinstance(cve_ids, str):
        cve = cve_ids
    else:
        cve = ''

    cvss_score = ''
    cvss = classification.get('cvss-score')
    if cvss is not None:
        cvss_score = str(cvss)

    # CWE（取第一个）
    cwe = ''
    cwe_ids = classification.get('cwe-id') or []
    if isinstance(cwe_ids, list) and cwe_ids:
        cwe = cwe_ids[0]
    elif isinstance(cwe_ids, str):
        cwe = cwe_ids

    # 分类标签：从 template-path 推导（nuclei 模板目录结构）
    template_path = data.get('template-path', '') or data.get('matcher-name', '')
    category = _classify_template(template_path, data.get('tags', []))

    # OOB 带外检测确认（interactsh 回连）
    interactsh_data = data.get('interactsh')
    oob_confirmed = bool(interactsh_data) if isinstance(interactsh_data, (list, str, dict)) else False

    return {
        'template_id': data.get('template-id', '') or data.get('templateID', ''),
        'name': info.get('name', ''),
        'severity': (info.get('severity', 'info') or 'info').lower(),
        'cve': cve,
        'cvss_score': cvss_score,
        'cwe': cwe,
        'category': category,
        'oob_confirmed': oob_confirmed,
        'tags': data.get('tags', []) if isinstance(data.get('tags'), list) else [],
        'url': data.get('url', '') or data.get('matched-at', ''),
        'matched_at': data.get('matched-at', '') or data.get('matched', ''),
        'extracted_data': data,
    }


def _classify_template(template_path: str, tags: list) -> str:
    """从 nuclei 模板路径/标签推导分类。

    nuclei 模板目录结构：
      cves/           → CVE 漏洞
      vulnerabilities/ → 通用漏洞
      misconfiguration/ → 配置错误
      exposures/      → 信息暴露（.git/.env/备份）
      default-logins/ → 默认凭证
      takeovers/      → 子域接管
      detections/     → 技术检测
    """
    path_lower = (template_path or '').lower()
    tags_lower = [str(t).lower() for t in (tags or [])]

    if 'cve' in path_lower or 'cve' in tags_lower:
        return 'cve'
    if 'exposure' in path_lower or 'exposure' in tags_lower or 'exposed' in tags_lower:
        return 'exposure'
    if 'misconfig' in path_lower or 'misconfig' in tags_lower:
        return 'misconfig'
    if 'default-login' in path_lower or 'default-login' in tags_lower:
        return 'default-login'
    if 'takeover' in path_lower or 'takeover' in tags_lower:
        return 'takeover'
    if 'detect' in path_lower or 'tech' in tags_lower:
        return 'detection'
    if 'vulnerabilit' in path_lower:
        return 'vulnerability'
    return 'other'
