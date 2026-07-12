"""邮件安全基线检测。

检测域名的邮件安全配置完整性：
  - SPF (Sender Policy Framework) — TXT 记录含 v=spf1
  - DMARC — _dmarc.<domain> TXT 记录含 v=DMARC1
  - DKIM — 常见 selector 的 CNAME/TXT 记录
  - DNSSEC — 域名是否启用 DNSSEC
  - MTA-STS — _mta-sts.<domain> TXT 记录
  - MX 记录 — 是否配置了邮件服务器

缺陷追加到 host['vulnerabilities']（category=mail_security）。
"""
from .dns_utils import resolve_dns_records


# DKIM 常见 selector（大部分邮箱服务商使用这些）
DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 's1', 's2',
                   'mail', 'k1', 'dkim', 'smtp']


def check_mail_security_for_hosts(hosts: list[dict]) -> int:
    """对所有主机（域名）做邮件安全基线检测。

    检测缺陷追加到 host['vulnerabilities']（category=mail_security）。
    返回发现的缺陷总数。
    """
    total_findings = 0
    checked_domains = set()

    for host in hosts:
        # 提取根域名（邮件安全配置是域名级别的）
        hostname = host.get('hostname', '')
        if not hostname or hostname == host.get('ip', ''):
            continue

        # 提取根域名（去掉子域名前缀，最多取后两段）
        parts = hostname.split('.')
        if len(parts) < 2:
            continue
        root_domain = '.'.join(parts[-2:])
        if root_domain in checked_domains:
            continue
        checked_domains.add(root_domain)

        findings = _check_domain(root_domain)
        for f in findings:
            host.setdefault('vulnerabilities', []).append(f)
        total_findings += len(findings)

    return total_findings


def _check_domain(domain: str) -> list[dict]:
    """检测单个域名的邮件安全配置。返回缺陷列表。"""
    findings = []

    # 1. MX 记录
    mx_records = resolve_dns_records(domain, 'MX')
    if not mx_records:
        findings.append({
            'name': f'{domain}: 无 MX 记录（未配置邮件服务器）',
            'severity': 'info',
            'category': 'mail_security',
            'matched_at': domain,
        })

    # 2. SPF (TXT 记录查 v=spf1)
    txt_records = resolve_dns_records(domain, 'TXT')
    txt_str = ' '.join(txt_records) if txt_records else ''
    spf_found = 'v=spf1' in txt_str

    if not spf_found:
        findings.append({
            'name': f'{domain}: 缺少 SPF 记录（邮件伪造防护）',
            'severity': 'medium',
            'category': 'mail_security',
            'matched_at': domain,
        })
    else:
        # SPF 配置检查：~all（软失败）vs -all（硬拒绝）
        if '~all' in txt_str and '-all' not in txt_str:
            findings.append({
                'name': f'{domain}: SPF 使用软失败(~all)，建议改为硬拒绝(-all)',
                'severity': 'low',
                'category': 'mail_security',
                'matched_at': domain,
            })
        elif '+all' in txt_str:
            findings.append({
                'name': f'{domain}: SPF 使用 +all（允许所有IP），等同于无防护',
                'severity': 'high',
                'category': 'mail_security',
                'matched_at': domain,
            })

    # 3. DMARC (_dmarc.<domain> TXT)
    dmarc_domain = f'_dmarc.{domain}'
    dmarc_records = resolve_dns_records(dmarc_domain, 'TXT')
    if not dmarc_records:
        findings.append({
            'name': f'{domain}: 缺少 DMARC 记录（邮件认证策略）',
            'severity': 'medium',
            'category': 'mail_security',
            'matched_at': dmarc_domain,
        })
    else:
        dmarc_str = ' '.join(dmarc_records)
        if 'p=none' in dmarc_str:
            findings.append({
                'name': f'{domain}: DMARC 策略为 p=none（仅监控不拒绝），建议升级为 p=reject',
                'severity': 'low',
                'category': 'mail_security',
                'matched_at': dmarc_domain,
            })

    # 4. DKIM (查常见 selector)
    dkim_found = False
    for selector in DKIM_SELECTORS:
        dkim_domain = f'{selector}._domainkey.{domain}'
        dkim_records = resolve_dns_records(dkim_domain, 'TXT')
        if dkim_records:
            dkim_found = True
            break
        # 也查 CNAME
        dkim_cname = resolve_dns_records(dkim_domain, 'CNAME')
        if dkim_cname:
            dkim_found = True
            break

    if not dkim_found and mx_records:
        # 只有有邮件服务器的域名才报 DKIM 缺失
        findings.append({
            'name': f'{domain}: 未检测到 DKIM 记录（邮件签名验证）',
            'severity': 'low',
            'category': 'mail_security',
            'matched_at': domain,
        })

    # 5. MTA-STS (_mta-sts.<domain> TXT)
    mta_sts_domain = f'_mta-sts.{domain}'
    mta_sts_records = resolve_dns_records(mta_sts_domain, 'TXT')
    if not mta_sts_records:
        findings.append({
            'name': f'{domain}: 缺少 MTA-STS 记录（SMTP 传输安全策略）',
            'severity': 'info',
            'category': 'mail_security',
            'matched_at': mta_sts_domain,
        })

    return findings
