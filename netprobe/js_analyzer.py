"""JavaScript 文件分析 — 从 JS 中提取 API 端点和泄露的密钥。"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests

_REQUEST_TIMEOUT = 10
_MAX_JS_SIZE = 512_000
_MAX_JS_PER_HOST = 10
_MAX_WORKERS = 6

# 第三方 CDN 域名，跳过分析以减少噪音
_SKIP_DOMAINS = {
    'googleapis.com', 'google-analytics.com', 'googletagmanager.com',
    'cloudflare.com', 'cdn.jsdelivr.net', 'ajax.googleapis.com',
    'cdnjs.cloudflare.com', 'stackpath.bootstrapcdn.com',
    'cdn.bootcss.com', 'unpkg.com', 'cdn.jsdelivr.net',
    'polyfill.io', 'assets.adobedtm.com',
}

# ── API 端点提取规则 ──────────────────────────────────

_API_PATTERNS = [
    # /api/... /v1/... /v2/... 路径
    re.compile(r'''["']\s*(/+(?:api|v\d+)/[^\s"'<>]{3,}?)\s*["']'''),
    # fetch("...")
    re.compile(r'''fetch\s*\(\s*["']([^"']+)["']'''),
    # axios.get/post/...("...")
    re.compile(r'''axios\.\w+\s*\(\s*["']([^"']+)["']'''),
    # $.get/post/ajax("...")
    re.compile(r'''\$\.\s*(?:get|post|ajax)\s*\(\s*["']([^"']+)["']'''),
    # XMLHttpRequest.open("GET", "...")
    re.compile(r'''\.open\s*\(\s*["']\w+["']\s*,\s*["']([^"']+)["']'''),
    # 完整 URL 以 .json/.xml 结尾
    re.compile(r'''["']\s*(https?://[^\s"'<>]+\.(?:json|xml))\s*["']'''),
]

# ── 密钥泄露检测规则 ──────────────────────────────────
# (pattern, type_name, severity)

_SECRET_RULES = [
    # AWS Access Key ID
    (re.compile(r'AKIA[0-9A-Z]{16}'), 'AWS Access Key', 'high'),
    # AWS Secret Key
    (re.compile(r'''(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']([A-Za-z0-9/+=]{20,})["']'''), 'AWS Secret Key', 'high'),
    # GitHub Token
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), 'GitHub Token', 'high'),
    # JWT Token
    (re.compile(r'eyJ[A-Za-z0-9\-_+=]{10,}\.eyJ[A-Za-z0-9\-_+=]{10,}'), 'JWT Token', 'medium'),
    # Bearer / Basic Auth
    (re.compile(r'''(?:Bearer|Basic)\s+[A-Za-z0-9\-._~+/]+=*'''), 'Auth Token', 'high'),
    # API Key
    (re.compile(r'''(?:api[_-]?key|apikey|api_secret)\s*[=:]\s*["']([^\s"']{8,})["']''', re.IGNORECASE), 'API Key', 'high'),
    # 硬编码密码
    (re.compile(r'''(?:password|passwd|pwd)\s*[=:]\s*["']([^\s"']{4,})["']''', re.IGNORECASE), 'Password', 'high'),
    # Private Key
    (re.compile(r'''-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'''), 'Private Key', 'high'),
    # 通用 secret/token
    (re.compile(r'''(?:secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[=:]\s*["']([^\s"']{8,})["']''', re.IGNORECASE), 'Secret', 'high'),
]


def extract_js_urls(html: str, base_url: str) -> list[str]:
    """从 HTML 中提取 script src URL 列表。"""
    if not html:
        return []
    urls = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = m.group(1).strip()
        if not src or src.startswith('data:'):
            continue
        full = urljoin(base_url, src)
        # 跳过第三方 CDN
        domain = full.split('//', 1)[-1].split('/', 1)[0].split(':')[0]
        if any(d in domain for d in _SKIP_DOMAINS):
            continue
        urls.append(full)
    return urls


def analyze_js(js_url: str) -> dict | None:
    """下载并分析单个 JS 文件，提取 API 端点和泄露密钥。"""
    try:
        resp = requests.get(js_url, timeout=_REQUEST_TIMEOUT, verify=False)
        if resp.status_code != 200:
            return None
        content = resp.text
        if len(content) > _MAX_JS_SIZE:
            content = content[:_MAX_JS_SIZE]
    except requests.RequestException:
        return None

    # 提取 API 端点（去重）
    api_endpoints = set()
    for pattern in _API_PATTERNS:
        for m in pattern.finditer(content):
            endpoint = m.group(1).strip()
            # 过滤掉明显不是 API 的路径
            if len(endpoint) < 5 or endpoint.endswith(('.js', '.css', '.png', '.jpg', '.svg', '.ico')):
                continue
            api_endpoints.add(endpoint)

    # 检测泄露密钥
    secrets = []
    for pattern, stype, severity in _SECRET_RULES:
        for m in pattern.finditer(content):
            match_text = m.group(0)
            # 截断过长的匹配
            if len(match_text) > 80:
                match_text = match_text[:80] + '...'
            secrets.append({
                'type': stype,
                'match': match_text,
                'severity': severity,
            })

    # 没发现就不返回
    if not api_endpoints and not secrets:
        return None

    return {
        'js_url': js_url,
        'size': len(content),
        'api_endpoints': sorted(api_endpoints)[:20],
        'secrets': secrets,
    }


def analyze_js_for_hosts(hosts: list[dict]) -> None:
    """对所有主机的 Web 页面中引用的 JS 文件进行分析。"""
    for host in hosts:
        js_urls = host.pop('_pending_js_urls', [])
        if not js_urls:
            host['js_findings'] = []
            continue

        js_urls = js_urls[:_MAX_JS_PER_HOST]
        findings = []

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = {pool.submit(analyze_js, url): url for url in js_urls}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)

        host['js_findings'] = findings
