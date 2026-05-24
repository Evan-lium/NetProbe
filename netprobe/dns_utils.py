import socket

import dns.resolver
import dns.reversename


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
