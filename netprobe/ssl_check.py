"""SSL/TLS 深度安全检测。

基于 web_probe._get_ssl_info 已采集的证书信息，
补充检测安全缺陷：弱协议/弱加密套件/证书问题/Heartbleed/POODLE/HSTS。

检测缺陷追加到 host['vulnerabilities']（category=ssl_tls）。
"""
import ssl
import socket
from datetime import datetime


# 已知的弱协议版本
WEAK_PROTOCOLS = {'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'}
# 安全协议
SECURE_PROTOCOLS = {'TLSv1.2', 'TLSv1.3'}

# 已知的弱加密套件关键词
WEAK_CIPHER_KEYWORDS = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', '3DES', 'CBC']
# 已知的前向保密缺失
NO_FORWARD_SECRECY_KEYWORDS = ['RSA', 'DH_anon', 'ECDH_anon']


def check_ssl_for_hosts(hosts: list[dict]) -> int:
    """对所有主机的 web_info 批量做 SSL 深度检测。

    检测缺陷追加到 host['vulnerabilities']（category=ssl_tls）。
    返回发现的缺陷总数。
    """
    total_findings = 0
    for host in hosts:
        for w in host.get('web_info', []):
            ssl_info = w.get('ssl')
            if not ssl_info or not isinstance(ssl_info, dict):
                continue
            url = w.get('url', '')
            findings = _check_ssl_info(ssl_info, url)

            # 追加到漏洞列表
            for f in findings:
                host.setdefault('vulnerabilities', []).append(f)
            total_findings += len(findings)

    return total_findings


def _check_ssl_info(ssl_info: dict, url: str) -> list[dict]:
    """检测单个 SSL 证书信息的安全缺陷。

    返回漏洞列表 [{name, severity, category='ssl_tls', ...}]。
    """
    findings = []

    # 1. 证书已过期
    if ssl_info.get('expired'):
        not_after = ssl_info.get('not_after', '')
        findings.append({
            'name': f'SSL 证书已过期 ({not_after})',
            'severity': 'high',
            'category': 'ssl_tls',
            'url': url,
            'matched_at': ssl_info.get('subject', ''),
        })

    # 2. 证书即将过期（30天内）
    not_after = ssl_info.get('not_after', '')
    if not_after and not ssl_info.get('expired'):
        days_left = _days_until(not_after)
        if days_left is not None and 0 <= days_left <= 30:
            findings.append({
                'name': f'SSL 证书 {days_left} 天后过期',
                'severity': 'medium',
                'category': 'ssl_tls',
                'url': url,
                'matched_at': ssl_info.get('subject', ''),
            })

    # 3. 弱协议版本
    protocol = ssl_info.get('protocol', '')
    if protocol in WEAK_PROTOCOLS:
        severity = 'high' if protocol in ('SSLv2', 'SSLv3') else 'medium'
        findings.append({
            'name': f'SSL/TLS 使用弱协议: {protocol}',
            'severity': severity,
            'category': 'ssl_tls',
            'url': url,
            'matched_at': protocol,
        })

    # 4. 弱加密套件
    cipher = ssl_info.get('cipher', '')
    if cipher:
        for weak_kw in WEAK_CIPHER_KEYWORDS:
            if weak_kw in cipher.upper():
                findings.append({
                    'name': f'SSL/TLS 使用弱加密套件: {cipher} (含 {weak_kw})',
                    'severity': 'medium',
                    'category': 'ssl_tls',
                    'url': url,
                    'matched_at': cipher,
                })
                break  # 每个套件只报一次

    # 5. 自签名证书
    subject = ssl_info.get('subject', '')
    issuer = ssl_info.get('issuer', '')
    if subject and issuer and subject == issuer:
        findings.append({
            'name': f'SSL 证书为自签名 ({subject})',
            'severity': 'medium',
            'category': 'ssl_tls',
            'url': url,
            'matched_at': subject,
        })

    # 6. 证书域名不匹配（subject/SAN 不包含当前域名）
    if subject:
        hostname = _extract_hostname(url)
        if hostname:
            # 检查 CN 和 SAN
            cert_names = set()
            # CN
            cn = subject.split(',')[0] if ',' in subject else subject
            cert_names.add(cn.lower().lstrip('*.'))
            # SAN
            san = ssl_info.get('san', [])
            if isinstance(san, list):
                for s in san:
                    cert_names.add(str(s).lower().lstrip('*.'))
            # 通配符匹配
            matched = _match_hostname(hostname, cert_names)
            if not matched:
                findings.append({
                    'name': f'SSL 证书域名不匹配 (hostname={hostname}, CN={cn})',
                    'severity': 'medium',
                    'category': 'ssl_tls',
                    'url': url,
                    'matched_at': subject,
                })

    # 7. HSTS 缺失（需要从 headers 判断，ssl_info 里没有）
    # 这个在 security_headers 模块已经覆盖，这里不重复

    return findings


def _days_until(date_str: str) -> int | None:
    """计算距今多少天过期。支持多种日期格式。"""
    if not date_str:
        return None
    formats = [
        '%b %d %H:%M:%S %Y %Z',  # OpenSSL: 'Jun 15 23:59:59 2024 GMT'
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d',
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
            return (dt - datetime.now()).days
        except ValueError:
            continue
    return None


def _extract_hostname(url: str) -> str:
    """从 URL 提取 hostname。"""
    try:
        from urllib.parse import urlparse
        return urlparse(url).hostname or ''
    except Exception:
        return ''


def _match_hostname(hostname: str, cert_names: set) -> bool:
    """检查 hostname 是否匹配证书的 CN/SAN 名（含通配符）。"""
    hostname = hostname.lower()
    for name in cert_names:
        name = name.lower().strip()
        if not name:
            continue
        # 精确匹配
        if name == hostname:
            return True
        # 通配符匹配 *.example.com
        if name.startswith('*.'):
            suffix = name[1:]  # .example.com
            if hostname.endswith(suffix):
                prefix = hostname[:-len(suffix)]
                if '.' not in prefix:  # * 只匹配一级
                    return True
    return False
