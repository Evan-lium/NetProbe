"""CORS 配置检测 — 通过特殊 Origin 请求检测反射/通配缺陷。

对 Web 站点发送恶意 Origin 请求，根据响应头判断 CORS 配置是否安全：
  - 反射 evil.com + Allow-Credentials: true  → critical（可窃取凭证数据）
  - 通配 *（Allow-Origin: *）                 → high（任意源可读响应）
  - 反射 Origin 无 credentials                → medium（可读公共数据）

参考 sensitive_probe.py 的容错风格。
"""

from urllib.parse import urlparse

import requests

REQUEST_TIMEOUT = 8

# 测试用的恶意 Origin
_TEST_ORIGIN_EVIL = 'https://evil.com'
_TEST_ORIGIN_NULL = 'null'


def check_cors(url: str) -> list[dict]:
    """检测指定 URL 的 CORS 配置。

    参数:
        url: 目标 URL（如 https://example.com）

    返回: [{origin, allow_origin, allow_credentials, severity, vulnerable}, ...]
        对每个测试 Origin 返回一条结果；仅返回存在配置缺陷的项。
    """
    results: list[dict] = []
    test_origins = [_TEST_ORIGIN_EVIL, _TEST_ORIGIN_NULL]

    for origin in test_origins:
        finding = _test_origin(url, origin)
        if finding:
            results.append(finding)

    return results


def _test_origin(url: str, origin: str) -> dict | None:
    """对单个 Origin 发请求并评估 CORS 配置缺陷。

    返回缺陷描述 dict，无缺陷返回 None。
    """
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            verify=False,
            headers={'Origin': origin},
        )
    except requests.RequestException:
        return None

    # 大小写不敏感读取响应头
    lower_headers = {k.lower(): v for k, v in resp.headers.items()}
    allow_origin = lower_headers.get('access-control-allow-origin', '')
    allow_creds = lower_headers.get('access-control-allow-credentials', '').lower()

    if not allow_origin:
        return None  # 未返回 CORS 头，配置正常

    with_credentials = allow_creds == 'true'

    # 评估缺陷等级
    severity = ''
    vulnerable = False

    # 通配 *：任意源可访问
    if allow_origin == '*':
        # 通配 + credentials = 严重（虽然规范禁止，但部分实现存在）
        if with_credentials:
            severity = 'critical'
        else:
            severity = 'high'
        vulnerable = True
    # 精确反射我们的恶意 Origin
    elif allow_origin == origin:
        # 反射 + 允许凭证 = 严重（可窃取登录态数据）
        if with_credentials:
            severity = 'critical'
        else:
            severity = 'medium'
        vulnerable = True
    # null 反射缺陷：某些配置会反射 null Origin
    elif allow_origin == 'null' and origin == _TEST_ORIGIN_NULL:
        if with_credentials:
            severity = 'critical'
        else:
            severity = 'medium'
        vulnerable = True

    if not vulnerable:
        return None

    return {
        'origin': origin,
        'allow_origin': allow_origin,
        'allow_credentials': with_credentials,
        'severity': severity,
        'vulnerable': True,
    }


def check_cors_for_hosts(hosts: list[dict]) -> None:
    """对所有主机的 Web 站点批量检测 CORS 配置。

    结果写入 host['_cors_findings']，并将漏洞追加到 host['vulnerabilities']
    （severity 取 medium/high；critical 在 vuln 体系中映射为 high）。
    每个 origin 只检测一次。
    """
    for host in hosts:
        web_info = host.get('web_info', [])
        findings: list[dict] = []
        seen_origins: set[str] = set()

        # 确保 vulnerabilities 字段存在
        vulnerabilities = host.setdefault('vulnerabilities', [])

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
                found = check_cors(origin)
            except Exception:
                found = []
            if found:
                findings.extend(found)
                # 追加到 vulnerabilities（critical 映射为 high，medium 保持）
                for f in found:
                    sev = f['severity']
                    vuln_sev = 'high' if sev == 'critical' else sev
                    vulnerabilities.append({
                        'name': f"CORS 配置缺陷（Origin: {f['origin']}）",
                        'severity': vuln_sev,
                        'url': origin,
                        'matched_at': origin,
                        'template_id': 'cors-misconfig',
                        'detail': (
                            f"Allow-Origin 反射/通配: {f['allow_origin']}, "
                            f"Allow-Credentials: {f['allow_credentials']}"
                        ),
                    })

        host['_cors_findings'] = findings
