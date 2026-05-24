import re
import socket
import ssl
from datetime import datetime

import requests

# Web 常见端口与协议映射
WEB_PORTS = {
    80: 'http', 443: 'https',
    8080: 'http', 8443: 'https', 8000: 'http',
    3000: 'http', 5000: 'http', 9000: 'http',
    8888: 'http', 9090: 'http', 7001: 'http',
    8880: 'http', 8001: 'http', 8002: 'http',
    10000: 'http', 4000: 'http', 6000: 'http',
}

REQUEST_TIMEOUT = 8


def probe_web(hostname: str, ip: str, port: int) -> dict | None:
    """对指定主机的端口进行 Web 探测。

    返回 {'url', 'status', 'title', 'redirect', 'headers', 'ssl'} 或 None。
    """
    scheme = WEB_PORTS.get(port)
    if not scheme:
        return None

    # 优先用 hostname 访问，fallback 到 IP
    for target in (hostname, ip):
        if not target:
            continue
        url = f'{scheme}://{target}:{port}'
        try:
            resp = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                verify=False,
                headers={'Host': hostname} if target == ip else {},
            )
            # 修正编码
            resp.encoding = _detect_charset(resp) or resp.apparent_encoding
            title = _extract_title(resp.text)
            redirect = resp.headers.get('Location', '')

            result = {
                'url': url,
                'status': resp.status_code,
                'title': title,
                'redirect': redirect,
                'headers': _extract_http_fingerprint(resp),
            }

            # SSL/TLS 证书信息
            if scheme == 'https':
                result['ssl'] = _get_ssl_info(target, port)

            return result
        except requests.RequestException:
            continue
    return None


def probe_web_for_host(
    hostname: str,
    ip: str,
    open_ports: list[int],
) -> list[dict]:
    """对主机所有开放的 Web 端口逐一探测。"""
    results = []
    for port in open_ports:
        if port not in WEB_PORTS:
            continue
        info = probe_web(hostname, ip, port)
        if info:
            info['port'] = port
            results.append(info)
    return results


def _extract_http_fingerprint(resp: requests.Response) -> dict:
    """从 HTTP 响应头中提取指纹信息。"""
    headers = resp.headers
    fingerprint = {}

    server = headers.get('Server', '')
    if server:
        fingerprint['server'] = server

    powered_by = headers.get('X-Powered-By', '')
    if powered_by:
        fingerprint['powered_by'] = powered_by

    # 从 Set-Cookie 推断框架
    set_cookie = headers.get('Set-Cookie', '')
    if set_cookie:
        if 'JSESSIONID' in set_cookie:
            fingerprint['framework'] = 'Java/Tomcat'
        elif 'PHPSESSID' in set_cookie:
            fingerprint['framework'] = 'PHP'
        elif 'ASP.NET_SessionId' in set_cookie:
            fingerprint['framework'] = 'ASP.NET'
        elif 'sessionid' in set_cookie.lower() and 'csrftoken' in set_cookie.lower():
            fingerprint['framework'] = 'Django'
        elif 'connect.sid' in set_cookie:
            fingerprint['framework'] = 'Node.js/Express'

    # X-AspNet-Version
    aspnet_ver = headers.get('X-AspNet-Version', '')
    if aspnet_ver:
        fingerprint['aspnet_version'] = aspnet_ver

    # X-Generator (CMS)
    generator = headers.get('X-Generator', '')
    if generator:
        fingerprint['cms'] = generator

    return fingerprint


def _get_ssl_info(hostname: str, port: int) -> dict:
    """获取 SSL/TLS 证书信息。"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        if not cert:
            return {'protocol': version or ''}

        # 提取证书信息
        subject = dict(x[0] for x in cert.get('subject', ()))
        issuer = dict(x[0] for x in cert.get('issuer', ()))

        cn = subject.get('commonName', '')
        org = subject.get('organizationName', '')
        issuer_name = issuer.get('commonName', '') or issuer.get('organizationName', '')

        not_before = cert.get('notBefore', '')
        not_after = cert.get('notAfter', '')

        # SAN 域名列表
        san = []
        for ext in cert.get('subjectAltName', ()):
            if ext[0] == 'DNS':
                san.append(ext[1])

        # 过期检查
        expired = False
        if not_after:
            try:
                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                expired = expiry < datetime.now()
            except ValueError:
                pass

        result = {
            'subject': cn,
            'issuer': issuer_name,
            'org': org,
            'not_before': not_before,
            'not_after': not_after,
            'expired': expired,
            'protocol': version or '',
        }
        if cipher:
            result['cipher'] = cipher[0]
        if san:
            result['san'] = san[:10]  # 最多 10 个

        return result

    except Exception:
        return {}


def _detect_charset(resp: requests.Response) -> str | None:
    """从 HTML meta 标签或 Content-Type 中提取字符编码。"""
    content_type = resp.headers.get('Content-Type', '')
    match = re.search(r'charset=([\w-]+)', content_type, re.IGNORECASE)
    if match:
        return match.group(1)

    # 从 HTML meta 标签检测
    html = resp.content[:2048].decode('ascii', errors='ignore').lower()
    match = re.search(r'charset=[\'"]?([\w-]+)', html, re.IGNORECASE)
    if match:
        return match.group(1)

    return None


def _extract_title(html: str) -> str:
    """从 HTML 中提取 <title> 内容。"""
    start = html.lower().find('<title>')
    if start == -1:
        return ''
    start += len('<title>')
    end = html.lower().find('</title>', start)
    if end == -1:
        return ''
    return html[start:end].strip()[:200]
