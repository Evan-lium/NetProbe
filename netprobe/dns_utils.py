import random
import socket
import string

import dns.resolver
import dns.reversename
import dns.query
import dns.zone
import dns.rdatatype


def reverse_dns_lookup(ip_address: str) -> str | None:
    """反向 DNS 查询，返回主机名或 None。"""
    try:
        rev_name = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(rev_name, 'PTR')
        if answers:
            hostname = str(answers[0]).rstrip('.')
            return hostname
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.Timeout, dns.exception.DNSException):
        pass
    return None


def resolve_a_record(hostname: str) -> list[str]:
    """查询 A 记录，返回 IP 列表。解析失败返回空列表。"""
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        return [rdata.address for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.Timeout, dns.resolver.NoNameservers,
            dns.exception.DNSException):
        pass
    # dnspython 失败时，用系统 DNS fallback
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ips = list({r[4][0] for r in results})
        return ips
    except socket.gaierror:
        return []


def is_subdomain_of(hostname: str, base_domain: str) -> bool:
    """判断 hostname 是否属于 base_domain 或其子域名。"""
    h = hostname.rstrip('.').lower()
    b = base_domain.rstrip('.').lower()
    return h == b or h.endswith('.' + b)


def detect_wildcard_resolution(domain: str) -> list[str]:
    """检测域名是否开启了 DNS 泛解析。

    泛解析会把任意不存在的子域名都解析到固定 IP，导致子域名枚举产生
    大量假阳性。本函数生成 3 组随机长串子域名（极大概率不存在），
    若它们都能解析且指向相同的 IP，则判定为泛解析。

    参数:
        domain: 根域名（如 example.com）

    返回: 泛解析 IP 列表（说明开启了泛解析）；空列表表示未开启。
    """
    wildcard_ips: list[str] = []
    domain = domain.rstrip('.')

    for _ in range(3):
        # 生成 15 位随机字母数字串，碰撞概率极低
        rand_label = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))
        probe = f'{rand_label}.{domain}'
        ips = resolve_a_record(probe)
        if not ips:
            # 任意一组解析失败 → 未开启泛解析
            return []
        if not wildcard_ips:
            wildcard_ips = ips
        else:
            # 要求多组解析到相同 IP（取交集），否则可能非泛解析
            common = [ip for ip in ips if ip in wildcard_ips]
            if not common:
                return []
            wildcard_ips = common

    return wildcard_ips


def filter_results(
    results: list[dict],
    base_domain: str,
    validate_dns: bool = True,
) -> list[dict]:
    """过滤结果：后缀匹配 + 可选的 DNS 解析验证。"""
    filtered = []
    seen = set()
    for item in results:
        hostname = item.get('hostname', '').strip()
        ip = item.get('ip', '').strip()
        if not hostname or hostname in seen:
            continue
        if not is_subdomain_of(hostname, base_domain):
            continue
        if validate_dns:
            ips = resolve_a_record(hostname)
            if not ips:
                continue
            # 用实际解析到的 IP 替换/补充
            if not ip:
                ip = ips[0]
        seen.add(hostname)
        filtered.append({'hostname': hostname, 'ip': ip})
    return filtered


# ── DNS 多记录查询 + 区域传送（v2.3）────────────────────────────

def resolve_dns_records(name: str, rtype: str = 'CNAME') -> list[str]:
    """通用 DNS 记录查询，支持 CNAME/MX/NS/TXT/SOA 等任意类型。

    返回字符串列表（rdata 的文本表示）。失败返回空列表。
    """
    try:
        answers = dns.resolver.resolve(name, rtype)
        records = []
        for rdata in answers:
            records.append(str(rdata).rstrip('.'))
        return records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.Timeout, dns.resolver.NoNameservers,
            dns.exception.DNSException):
        return []


def get_nameservers(domain: str) -> list[str]:
    """查询域名的权威 NS 记录，返回 NS 主机名列表。"""
    return resolve_dns_records(domain, 'NS')


def get_all_dns_records(domain: str) -> dict:
    """查询域名的全类型 DNS 记录 + 邮件安全配置检查。

    返回 {
        records: {A:[], AAAA:[], CNAME:[], MX:[], NS:[], TXT:[], SOA:[], CAA:[]},
        mail_security: {spf: bool, spf_record: str, dmarc: bool, dmarc_record: str},
        warnings: [str]  # SPF/DMARC 缺失等告警
    }
    """
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA']
    records = {}
    for rtype in record_types:
        vals = resolve_dns_records(domain, rtype)
        if vals:
            records[rtype] = vals

    # 邮件安全检查：SPF（在 TXT 里）和 DMARC（_dmarc 子域 TXT）
    warnings = []
    all_txt = records.get('TXT', [])
    spf_record = next((t for t in all_txt if t.startswith('"v=spf1') or 'v=spf1' in t), '')
    if not spf_record:
        # TXT 记录可能带引号
        spf_record = next((t for t in all_txt if 'spf1' in t.lower()), '')
    has_spf = bool(spf_record)

    dmarc_records = resolve_dns_records(f'_dmarc.{domain}', 'TXT')
    dmarc_record = next((d for d in dmarc_records if 'v=dmarc1' in d.lower() or 'dmarc1' in d.lower()), '')
    has_dmarc = bool(dmarc_record)

    # 缺失告警
    if not has_spf:
        warnings.append('SPF 记录缺失：邮件可被伪造发件人')
    if not has_dmarc:
        warnings.append('DMARC 记录缺失：无邮件认证策略')

    return {
        'records': records,
        'mail_security': {
            'spf': has_spf,
            'spf_record': spf_record,
            'dmarc': has_dmarc,
            'dmarc_record': dmarc_record,
        },
        'warnings': warnings,
    }


def try_zone_transfer(domain: str, timeout: int = 10) -> dict | None:
    """尝试 DNS 区域传送（AXFR）获取完整 zone 记录。

    流程: 查 NS → 解析 NS 的 IP → 对每个 NS 尝试 AXFR。
    绝大多数域名会拒绝 AXFR（返回 None），这是正常的。
    成功返回 {'ns', 'records': [{'name','type','value'}], 'count'}。
    """
    ns_list = get_nameservers(domain)
    if not ns_list:
        return None

    for ns_hostname in ns_list:
        # 解析 NS 的 IP（AXFR 需要连 IP）
        ns_ips = resolve_a_record(ns_hostname)
        if not ns_ips:
            continue

        for ns_ip in ns_ips:
            try:
                xfr = dns.query.xfr(ns_ip, domain, timeout=timeout, lifetime=timeout)
                zone = dns.zone.from_xfr(xfr)
                records = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        rtype = dns.rdatatype.to_text(rdataset.rdtype)
                        for rdata in rdataset:
                            records.append({
                                'name': str(name) if str(name) != '@' else domain,
                                'type': rtype,
                                'value': str(rdata).rstrip('.'),
                            })
                if records:
                    return {
                        'ns': ns_hostname,
                        'records': records,
                        'count': len(records),
                    }
            except (dns.exception.DNSException, OSError, TimeoutError):
                continue

    return None
