"""WHOIS / RDAP 查询 — 域名注册信息 + IP 的 ASN/网段。

域名 WHOIS 走 RDAP（IETF 标准、公开免费、无需 key）:
  默认: https://rdap.org/domain/{domain}（通用跳转，对部分 TLD 不完整）
  .cn: https://rdap.cnnic.cn/domain/{domain}（CNNIC 中国互联网络信息中心）
IP 的 ASN/网段走 ipwhois 库的 RDAP lookup。

参考 fofa.py/hunter.py 模式: 单一 query 函数 + 异常容错返回空。
"""

import json

import requests

RDAP_DOMAIN_URL = 'https://rdap.org/domain/{}'
REQUEST_TIMEOUT = 20

# 特殊 TLD 的专用 RDAP 服务器（rdap.org 对这些支持不完整）
RDAP_TLD_SERVERS = {
    'cn': 'https://rdap.cnnic.cn/domain/{}',       # CNNIC 中国互联网络信息中心
    '中国': 'https://rdap.cnnic.cn/domain/{}',      # CNNIC 中文域名
    '公司': 'https://rdap.cnnic.cn/domain/{}',      # CNNIC 中文域名
    '网络': 'https://rdap.cnnic.cn/domain/{}',      # CNNIC 中文域名
    'jp': 'https://rdap.jprs.jp/domain/{}',         # 日本 JPRS
    'kr': 'https://rdap.kisa.or.kr/domain/{}',      # 韩国 KISA
    'ru': 'https://www.tcinet.ru/rdap/domain/{}',   # 俄罗斯
}


def query_rdap_domain(domain: str, timeout: int = 20) -> dict:
    """查询域名 RDAP 注册信息。

    返回: {'registrar', 'status', 'creation_date', 'expiration_date',
           'updated_date', 'nameservers', 'domain_name'} 或空 dict。
    """
    # 按域名 TLD 选择 RDAP 服务器（专用服务器优先，fallback rdap.org）
    tld = domain.rsplit('.', 1)[-1].lower() if '.' in domain else ''
    servers = []
    if tld in RDAP_TLD_SERVERS:
        servers.append(RDAP_TLD_SERVERS[tld])  # 专用服务器优先
    servers.append(RDAP_DOMAIN_URL)  # 通用 fallback

    for server_url in servers:
        try:
            url = server_url.format(domain)
            resp = requests.get(url, timeout=timeout, headers={
                'Accept': 'application/rdap+json',
                'User-Agent': 'NetProbe/3.0',
            })
            if resp.status_code != 200:
                continue  # 试下一个服务器

            data = resp.json()
            result = {
                'domain_name': domain,
                'registrar': _extract_registrar(data),
                'status': data.get('status', []),
                'nameservers': _extract_nameservers(data),
            }

            # 日期事件（registration/expiration/last changed）
            for event in data.get('events', []):
                action = event.get('eventAction', '')
                date = event.get('eventDate', '')
                if action == 'registration':
                    result['creation_date'] = date
                elif action == 'expiration':
                    result['expiration_date'] = date
                elif action == 'last changed':
                    result['updated_date'] = date

            # 至少有注册商或到期时间才算查到
            if result.get('registrar') or result.get('expiration_date') or result.get('creation_date'):
                return result
        except (requests.RequestException, json.JSONDecodeError, ValueError):
            continue

    # RDAP 全部失败 → fallback 到 WHOIS 协议（port 43）
    return _query_whois_port43(domain, timeout)


# WHOIS 服务器按 TLD 映射（RDAP 不可用时的 fallback）
WHOIS_SERVERS = {
    'cn': 'whois.cnnic.cn',         # CNNIC
    '中国': 'whois.cnnic.cn',
    'com': 'whois.verisign-grs.com',  # Verisign
    'net': 'whois.verisign-grs.com',
    'org': 'whois.publicinterestregistry.org',
    'io': 'whois.nic.io',
    'co': 'whois.nic.co',
    'info': 'whois.afilias.net',
    'xyz': 'whois.nic.xyz',
    'top': 'whois.nic.top',
    'vip': 'whois.nic.vip',
    'cc': 'ccwhois.verisign-grs.com',
    'tv': 'tvwhois.verisign-grs.com',
    'me': 'whois.nic.me',
    'ru': 'whois.tcinet.ru',
    'jp': 'whois.jprs.jp',
}


def _query_whois_port43(domain: str, timeout: int = 15) -> dict:
    """通过 WHOIS 协议（port 43）查询域名注册信息。

    RDAP 不可用时（如 .cn 域名）的 fallback。
    返回与 query_rdap_domain 相同结构的结果 dict。
    """
    import socket
    import re

    tld = domain.rsplit('.', 1)[-1].lower() if '.' in domain else ''
    server = WHOIS_SERVERS.get(tld, 'whois.iana.org')

    try:
        sock = socket.create_connection((server, 43), timeout=timeout)
        sock.sendall((domain + '\r\n').encode())
        data = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        text = data.decode('utf-8', errors='replace')
    except (socket.error, OSError):
        return {}

    if not text or 'No match' in text or 'NOT FOUND' in text:
        return {}

    # 解析 WHOIS 文本为结构化字段（兼容多种格式）
    result = {'domain_name': domain}

    for line in text.splitlines():
        line = line.strip()
        lower = line.lower()
        # 注册商
        if any(k in lower for k in ['sponsoring registrar', 'registrar:', 'registrar name']):
            val = line.split(':', 1)[-1].strip()
            if val and 'registrar' not in result:
                result['registrar'] = val
        # 注册人/持有者
        elif any(k in lower for k in ['registrant:', 'registrant name', 'holder:']):
            val = line.split(':', 1)[-1].strip()
            if val:
                result['registrant'] = val
        # 注册时间
        elif any(k in lower for k in ['registration time', 'creation date', 'created:', 'registered:']):
            val = line.split(':', 1)[-1].strip()
            if val:
                result['creation_date'] = val
        # 到期时间
        elif any(k in lower for k in ['expiration time', 'expiry date', 'expires:', 'paid-till']):
            val = line.split(':', 1)[-1].strip()
            if val:
                result['expiration_date'] = val
        # 更新时间
        elif any(k in lower for k in ['updated date', 'last updated']):
            val = line.split(':', 1)[-1].strip()
            if val:
                result['updated_date'] = val
        # NS
        elif 'name server' in lower:
            val = line.split(':', 1)[-1].strip() if ':' in line else line.split(None, 2)[-1].strip()
            if val:
                result.setdefault('nameservers', []).append(val)
        # 状态
        elif 'domain status' in lower or (lower.startswith('status:') ):
            val = line.split(':', 1)[-1].strip() if ':' in line else ''
            if val:
                result.setdefault('status', []).append(val)
        # 邮箱
        elif 'email' in lower or 'e-mail' in lower:
            m = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', line)
            if m:
                result.setdefault('email', m.group(0))

    # 至少有注册商或到期时间才算查到
    if result.get('registrar') or result.get('expiration_date') or result.get('creation_date'):
        return result
    return {}


def query_rdap_ip(ip: str, timeout: int = 20) -> dict:
    """查询 IP 的 ASN / 网段信息（via ipwhois RDAP）。

    返回: {'ip', 'asn', 'asn_cidr', 'asn_description', 'asn_country_code',
           'asn_registry', 'network'} 或空 dict。
    """
    try:
        from ipwhois import IPWhois
        obj = IPWhois(ip)
        lookup = obj.lookup_rdap(rate_limit_timeout=timeout)

        network = lookup.get('network', {}) or {}
        return {
            'ip': ip,
            'asn': lookup.get('asn') or '',
            'asn_cidr': lookup.get('asn_cidr') or '',
            'asn_description': (lookup.get('asn_description') or '').strip(),
            'asn_country_code': lookup.get('asn_country_code') or '',
            'asn_registry': lookup.get('asn_registry') or '',
            'network': {
                'cidr': network.get('cidr') or '',
                'name': network.get('name') or '',
                'handle': network.get('handle') or '',
            },
        }

    except Exception:
        return {}


def _extract_registrar(data: dict) -> str:
    """从 RDAP entities 里提取 registrar（role=registrar 的实体名）。"""
    for entity in data.get('entities', []):
        roles = entity.get('roles', [])
        if 'registrar' in roles:
            vcard = entity.get('vcardArray', [])
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == 'fn':
                        return item[3]
            return entity.get('handle', '')
    return ''


def _extract_nameservers(data: dict) -> list[str]:
    """提取 NS 主机名列表。"""
    nameservers = data.get('nameservers', []) or []
    result = []
    for ns in nameservers:
        ldh = ns.get('ldhName') or ns.get('unicodeName') or ''
        if ldh:
            result.append(ldh.lower().rstrip('.'))
    return result
