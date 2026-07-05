"""HTTP 安全响应头检查 — 检测缺失/弱配置的安全响应头。

对 Web 站点检查 6 项关键安全头：
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options (防点击劫持)
  - X-Content-Type-Options (防 MIME 嗅探)
  - Referrer-Policy
  - Permissions-Policy

参考 sensitive_probe.py 的容错与并发风格。
"""

from urllib.parse import urlparse

import requests

REQUEST_TIMEOUT = 8

# 6 个月 ≈ 15552000 秒，OWASP 推荐 HSTS max-age 至少 6 个月
_HSTS_MIN_AGE = 15552000

# ── 安全响应头规则 ──────────────────────────────────
# (header, missing 时的严重度, 修复建议)
_SECURITY_HEADER_RULES = [
    {
        'header': 'Strict-Transport-Security',
        'missing_severity': 'high',
        'suggestion': '配置 HSTS 强制 HTTPS，建议 max-age 至少 6 个月（15552000）并启用 includeSubDomains',
    },
    {
        'header': 'Content-Security-Policy',
        'missing_severity': 'high',
        'suggestion': '配置 CSP 策略限制资源加载来源，防范 XSS 与数据外泄',
    },
    {
        'header': 'X-Frame-Options',
        'missing_severity': 'high',
        'suggestion': '设置 X-Frame-Options: DENY 或 SAMEORIGIN，防点击劫持',
    },
    {
        'header': 'X-Content-Type-Options',
        'missing_severity': 'medium',
        'suggestion': '设置 X-Content-Type-Options: nosniff，防 MIME 嗅探',
    },
    {
        'header': 'Referrer-Policy',
        'missing_severity': 'medium',
        'suggestion': '配置 Referrer-Policy（如 strict-origin-when-cross-origin），控制 Referer 泄露',
    },
    {
        'header': 'Permissions-Policy',
        'missing_severity': 'medium',
        'suggestion': '配置 Permissions-Policy 限制浏览器功能（摄像头/麦克风/地理位置等）',
    },
]


def check_security_headers(url: str, headers: dict | None = None) -> list[dict]:
    """检查指定 URL 的安全响应头配置。

    参数:
        url: 目标 URL（如 https://example.com）
        headers: 已有的响应头 dict；若为 None 则发请求获取

    返回: [{header, status, severity, suggestion}, ...]
        status: 'missing' | 'weak' | 'ok'
        仅返回缺失或弱配置项（ok 项不返回，避免噪音）
    """
    # 若调用方未提供响应头，则发请求获取
    if headers is None:
        try:
            resp = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                verify=False,
            )
            headers = dict(resp.headers)
        except requests.RequestException:
            return []

    if not headers:
        return []

    findings: list[dict] = []
    # 大小写不敏感查找（HTTP 头字段大小写不敏感）
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for rule in _SECURITY_HEADER_RULES:
        header_name = rule['header']
        value = lower_headers.get(header_name.lower(), '')

        if not value:
            # 缺失
            findings.append({
                'header': header_name,
                'status': 'missing',
                'severity': rule['missing_severity'],
                'suggestion': rule['suggestion'],
            })
            continue

        # 弱配置检测
        weak = _detect_weak_config(header_name, value)
        if weak:
            findings.append({
                'header': header_name,
                'status': 'weak',
                'severity': 'medium',
                'value': value[:120],
                'suggestion': rule['suggestion'],
            })
        # 否则视为 ok，不返回（减少噪音）

    return findings


def _detect_weak_config(header: str, value: str) -> bool:
    """检测单个头的弱配置，返回是否弱配置。"""
    value_lower = value.lower()

    if header == 'Strict-Transport-Security':
        # 解析 max-age
        for part in value_lower.split(';'):
            part = part.strip()
            if part.startswith('max-age'):
                try:
                    # max-age=31536000
                    age_str = part.split('=', 1)[-1].strip()
                    age = int(age_str)
                    if age < _HSTS_MIN_AGE:
                        return True
                except (ValueError, IndexError):
                    return True
                return False
        # 没有 max-age 也算弱配置
        return True

    if header == 'X-Frame-Options':
        # 仅 ALLOW-FROM 是弱配置（旧规范，已废弃）；DENY/SAMEORIGIN 正常
        return value_lower.startswith('allow-from')

    if header == 'Content-Security-Policy':
        # unsafe-inline / unsafe-eval 显著削弱 CSP
        if 'unsafe-inline' in value_lower or 'unsafe-eval' in value_lower:
            return True
        return False

    return False


def check_security_headers_for_hosts(hosts: list[dict]) -> None:
    """对所有主机的 Web 站点批量检查安全响应头。

    结果写入 host['_security_findings']（[{header, status, severity, ...}, ...]）。
    每个 origin 只检查一次。
    """
    for host in hosts:
        web_info = host.get('web_info', [])
        findings: list[dict] = []
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
                found = check_security_headers(origin)
            except Exception:
                found = []
            if found:
                findings.extend(found)

        host['_security_findings'] = findings
