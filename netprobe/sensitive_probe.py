"""敏感路径/文件探测 — 检测 Web 站点的信息泄露风险。"""

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import requests

REQUEST_TIMEOUT = 6
_MAX_WORKERS = 12

# ── 敏感路径规则（从 JSON 加载） ──
_DATA_DIR = Path(__file__).parent / 'data'

with open(_DATA_DIR / 'sensitive_paths.json', encoding='utf-8') as f:
    SENSITIVE_PATHS = json.load(f)


def probe_sensitive_paths(base_url: str) -> list[dict]:
    """对 Web 站点进行敏感路径探测。

    参数:
        base_url: 基础 URL (如 https://example.com)

    返回: [{'path', 'description', 'severity', 'status', 'size'}, ...]
    """
    results = []
    base = base_url.rstrip('/')

    def _check_one(item):
        path = item['path']
        desc = item['description']
        indicator = item['indicator']
        severity = item['severity']
        url = base + path
        try:
            resp = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                verify=False,
            )
            if resp.status_code == 200:
                content = resp.text[:2048]
                if indicator and indicator.lower() not in content.lower():
                    return None
                return {
                    'path': path,
                    'description': desc,
                    'severity': severity,
                    'status': resp.status_code,
                    'size': len(resp.content),
                }
            if resp.status_code == 403 and severity in ('high', 'medium'):
                return {
                    'path': path,
                    'description': f'{desc} (403 Forbidden)',
                    'severity': 'info',
                    'status': 403,
                    'size': 0,
                }
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = [pool.submit(_check_one, item) for item in SENSITIVE_PATHS]
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    return results


def probe_sensitive_for_hosts(hosts: list[dict]) -> None:
    """对所有主机的 Web 站点批量进行敏感路径探测。"""
    for host in hosts:
        web_info = host.get('web_info', [])
        sensitive = []
        seen_urls = set()

        for w in web_info:
            url = w.get('url', '')
            if not url:
                continue
            # 只探测每个唯一 origin 一次
            origin = f'{urlparse(url).scheme}://{urlparse(url).netloc}'
            if origin in seen_urls:
                continue
            seen_urls.add(origin)

            found = probe_sensitive_paths(origin)
            if found:
                sensitive.extend(found)

        host['sensitive'] = sensitive
