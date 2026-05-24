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
                '_raw_headers': dict(resp.headers),
                '_raw_html': resp.text[:65536],
                '_js_urls': _extract_script_urls(resp.text, url),
            }

            # 重定向时再请求最终页面获取完整 HTML 用于指纹识别
            if redirect and resp.status_code in (301, 302, 303, 307, 308):
                try:
                    resp2 = requests.get(
                        redirect, timeout=REQUEST_TIMEOUT,
                        verify=False, allow_redirects=True,
                    )
                    resp2.encoding = _detect_charset(resp2) or resp2.apparent_encoding
                    result['_raw_html'] = resp2.text[:65536]
                    if not title:
                        result['title'] = _extract_title(resp2.text)
                    result['_js_urls'] = _extract_script_urls(resp2.text, redirect)
                except requests.RequestException:
                    pass

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
        # 用 CERT_REQUIRED 获取完整证书（CERT_NONE 拿不到详情）
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # fallback: 用 binary_form 获取
                    cert_bin = ssock.getpeercert(binary_form=True)
                    if cert_bin:
                        # 解析 DER 格式证书
                        return _parse_der_cert(cert_bin, ssock.version(), ssock.cipher())
                    return {'protocol': ssock.version() or ''}
                cipher = ssock.cipher()
                version = ssock.version()
    except ssl.SSLError:
        # 证书验证失败，用 CERT_NONE 至少拿 protocol
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    if cert_bin:
                        return _parse_der_cert(cert_bin, ssock.version(), ssock.cipher())
                    return {'protocol': ssock.version() or ''}
        except Exception:
            return {}
    except Exception:
        return {}

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
        result['san'] = san[:10]

    return result


def _parse_der_cert(der_data: bytes, protocol: str | None, cipher: tuple | None) -> dict:
    """解析 DER 格式的 SSL 证书（不依赖 cryptography 库）。"""
    result = {'protocol': protocol or ''}
    if cipher:
        result['cipher'] = cipher[0]

    try:
        # 用 ssl 标准库的 DER 解析
        import ssl as _ssl
        # 通过临时 socket 反向获取证书信息
        # 直接从 DER 解析关键字段
        cert = _ssl._ssl._test_decode_cert(der_data)
        if not cert:
            return result

        subject = dict(x[0] for x in cert.get('subject', ()))
        issuer = dict(x[0] for x in cert.get('issuer', ()))

        cn = subject.get('commonName', '')
        org = subject.get('organizationName', '')
        issuer_name = issuer.get('commonName', '') or issuer.get('organizationName', '')

        result['subject'] = cn
        result['issuer'] = issuer_name
        result['org'] = org

        not_after = cert.get('notAfter', '')
        not_before = cert.get('notBefore', '')
        result['not_before'] = not_before
        result['not_after'] = not_after

        if not_after:
            try:
                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                result['expired'] = expiry < datetime.now()
            except ValueError:
                pass

        san = []
        for ext in cert.get('subjectAltName', ()):
            if ext[0] == 'DNS':
                san.append(ext[1])
        if san:
            result['san'] = san[:10]

    except Exception:
        pass

    return result


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


def _extract_script_urls(html: str, base_url: str) -> list[str]:
    """从 HTML 中提取 script src URL 列表（供 JS 分析器使用）。"""
    if not html:
        return []
    from urllib.parse import urljoin
    urls = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = m.group(1).strip()
        if src and not src.startswith('data:'):
            urls.append(urljoin(base_url, src))
    return urls[:20]
