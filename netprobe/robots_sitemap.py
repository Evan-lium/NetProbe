"""robots.txt 与 sitemap.xml 解析 — 从中提取隐藏路径用于后续探测。

robots.txt 与 sitemap.xml 是站点向爬虫公开的「路径清单」，常包含管理后台、
API、备份等敏感路径。本模块解析后把路径追加到待探测列表，供 sensitive_probe /
dir_brute 复用。

参考 sensitive_probe.py 的容错风格。
"""

import re
from urllib.parse import urljoin, urlparse

import requests

REQUEST_TIMEOUT = 8

# robots.txt 中 Sitemap: 指令
_SITEMAP_DIRECTIVE_RE = re.compile(r'(?im)^\s*sitemap\s*:\s*(\S+)')
# sitemap.xml 中的 <loc> 标签
_LOC_RE = re.compile(r'<loc>\s*(.*?)\s*</loc>', re.IGNORECASE | re.DOTALL)


def parse_robots(url: str) -> dict:
    """抓取并解析 robots.txt。

    参数:
        url: 站点基础 URL（如 https://example.com）

    返回: {'found': bool, 'disallow_paths': [...], 'sitemap_urls': [...]}
    """
    base = url.rstrip('/')
    robots_url = base + '/robots.txt'
    result = {'found': False, 'disallow_paths': [], 'sitemap_urls': []}

    try:
        resp = requests.get(
            robots_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=False,
        )
    except requests.RequestException:
        return result

    if resp.status_code != 200 or not resp.text:
        return result

    result['found'] = True
    text = resp.text

    # 解析 Disallow 路径（同时兼容大写 DISALLOW）
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        # 形如 Disallow: /admin 或 Disallow: /private/
        m = re.match(r'(?i)^disallow\s*:\s*(\S*)', stripped)
        if m:
            path = m.group(1)
            if path and path != '/':  # 跳过空值和根 /
                result['disallow_paths'].append(path)

    # 解析 Sitemap: 指令
    for m in _SITEMAP_DIRECTIVE_RE.finditer(text):
        sitemap_url = m.group(1).strip()
        if sitemap_url:
            result['sitemap_urls'].append(sitemap_url)

    # 去重保序
    result['disallow_paths'] = _dedup(result['disallow_paths'])
    result['sitemap_urls'] = _dedup(result['sitemap_urls'])

    return result


def parse_sitemap(url: str, sitemap_urls: list[str] | None = None) -> list[str]:
    """抓取并解析 sitemap.xml，返回其中的路径（仅 path 部分）。

    参数:
        url: 站点基础 URL（如 https://example.com）
        sitemap_urls: 从 robots.txt 发现的 sitemap URL；为空则尝试 /sitemap.xml

    返回: 路径列表（已去 host 前缀，如 ['/admin', '/api/users']）
    """
    base = url.rstrip('/')
    candidates: list[str] = list(sitemap_urls or [])
    candidates.append(base + '/sitemap.xml')

    paths: list[str] = []
    seen_urls: set[str] = set()

    for sitemap_url in candidates:
        if sitemap_url in seen_urls:
            continue
        seen_urls.add(sitemap_url)
        urls = _fetch_sitemap_locs(sitemap_url)
        for full_url in urls:
            path = _url_to_path(full_url, base)
            if path:
                paths.append(path)

    return _dedup(paths)


def _fetch_sitemap_locs(sitemap_url: str) -> list[str]:
    """抓取单个 sitemap.xml，返回其中的 <loc> URL 列表。"""
    try:
        resp = requests.get(
            sitemap_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=False,
        )
    except requests.RequestException:
        return []

    if resp.status_code != 200 or not resp.text:
        return []

    return [m.group(1).strip() for m in _LOC_RE.finditer(resp.text)]


def _url_to_path(full_url: str, base: str) -> str:
    """把完整 URL 转为 path 部分；非同源或无路径返回空串。"""
    full_url = full_url.strip()
    if not full_url:
        return ''
    parsed = urlparse(full_url)
    # 只保留 http(s) URL
    if parsed.scheme not in ('http', 'https'):
        return ''
    path = parsed.path or ''
    if not path or path == '/':
        return ''
    # 拼接 query 以保留参数化路径（如 /search?q=）
    if parsed.query:
        path += '?' + parsed.query
    return path


def _dedup(items: list[str]) -> list[str]:
    """去重保序。"""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def parse_robots_for_hosts(hosts: list[dict]) -> None:
    """对所有主机的 Web 站点批量解析 robots.txt 与 sitemap.xml。

    结果写入 host['_robots_findings']（[{'url', 'robots', 'sitemap_paths'}, ...]），
    解析出的路径追加到该站点的待探测列表 host['_extra_paths']（供 dir_brute /
    sensitive_probe 复用）。每个 origin 只解析一次。
    """
    for host in hosts:
        web_info = host.get('web_info', [])
        findings: list[dict] = []
        extra_paths: list[str] = []
        seen_origins: set[str] = set()

        for w in web_info:
            url = w.get('url', '')
            if not url:
                continue
            parsed = urlparse(url)
            origin = f'{parsed.scheme}://{parsed.netloc}'
            if origin in seen_origins:
                continue
            seen_origins.add(origin)

            try:
                robots = parse_robots(origin)
                sitemap_paths: list[str] = []
                if robots['found']:
                    sitemap_paths = parse_sitemap(origin, robots.get('sitemap_urls'))
            except Exception:
                continue

            if not robots['found'] and not sitemap_paths:
                continue

            finding = {
                'url': origin,
                'robots': robots,
                'sitemap_paths': sitemap_paths,
            }
            findings.append(finding)
            # 收集路径供后续探测
            extra_paths.extend(robots.get('disallow_paths', []))
            extra_paths.extend(sitemap_paths)

        host['_robots_findings'] = findings
        if extra_paths:
            host['_extra_paths'] = _dedup(extra_paths)
