import re

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

    返回 {'url': str, 'status': int, 'title': str, 'redirect': str} 或 None。
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
            # 修正编码：优先用 HTML meta 声明，其次用 apparent_encoding
            resp.encoding = _detect_charset(resp) or resp.apparent_encoding
            title = _extract_title(resp.text)
            redirect = resp.headers.get('Location', '')
            return {
                'url': url,
                'status': resp.status_code,
                'title': title,
                'redirect': redirect,
            }
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
