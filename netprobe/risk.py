"""资产风险评分引擎 — 综合 5 维度计算 0-100 风险分。

评分模型（加权求和，单维度封顶）:
  敏感路径泄露   30%  high=15, medium=5 each（封顶 30）
  高危服务暴露   25%  每个{22,23,445,3389,3306,6379,27017,5432,11211}=+8（封顶 25）
  脆弱技术栈CVE  20%  命中 CVE 的(product,version) 每个 +10（封顶 20）
  SSL 证书问题   15%  过期=15；弱协议(TLSv1.0/1.1)=8；即将过期(<30天)=5
  威胁情报命中   10%  Hunter risk_level>=2 = 10

分档: >=70 高危 / 40-69 中危 / <40 低危
"""

import json
from datetime import datetime

# 高危端口集合（远程管理/数据库/缓存，暴露即风险）
HIGH_RISK_PORTS = {22, 23, 445, 3389, 3306, 6379, 27017, 5432, 11211}

# 弱 TLS 协议
WEAK_TLS_PROTOCOLS = {'TLSv1', 'TLSv1.0', 'TLSv1.1', 'SSLv3', 'SSLv2'}

# 单维度封顶
CAP_SENSITIVE = 30
CAP_HIGH_RISK_PORT = 25
CAP_CVE = 20
CAP_SSL = 15
CAP_THREAT = 10


def compute_risk_score(host: dict) -> dict:
    """计算单个 host 的风险评分。

    参数:
        host: 扫描结果中的 host dict（含 ports/sensitive/web_info 等）
    返回: {'score': int(0-100), 'factors': {各维度分值与明细}}
    """
    factors = {}
    cves_found = []

    # ── 维度 1: 敏感路径泄露 ──
    sensitive_score = 0
    sensitive_details = []
    for s in host.get('sensitive', []):
        severity = (s.get('severity') or '').lower()
        if severity == 'critical':
            points = 20
        elif severity == 'high':
            points = 15
        elif severity == 'medium':
            points = 5
        else:
            points = 0
        if points:
            sensitive_score += points
            sensitive_details.append({'path': s.get('path', ''), 'severity': severity, 'points': points})
    sensitive_score = min(sensitive_score, CAP_SENSITIVE)
    factors['sensitive'] = {'score': sensitive_score, 'details': sensitive_details}

    # ── 维度 2: 高危服务暴露 ──
    port_score = 0
    high_risk_ports_found = []
    for p in host.get('ports', []):
        port = p.get('port', 0)
        if port in HIGH_RISK_PORTS and p.get('state', 'open') == 'open':
            high_risk_ports_found.append({'port': port, 'service': p.get('service', '')})
            port_score += 8
    port_score = min(port_score, CAP_HIGH_RISK_PORT)
    factors['high_risk_ports'] = {'score': port_score, 'details': high_risk_ports_found}

    # ── 维度 3: 脆弱技术栈 CVE ──
    cve_score = 0
    cve_details = []
    # 从 ports 的 cpe/product+version 查 NVD
    seen_cpes = set()
    for p in host.get('ports', []):
        cpe = p.get('cpe', '')
        product = p.get('product', '')
        version = p.get('version', '')
        if not (product and version):
            continue
        # 用 product+version 作为查询关键词（CPE 格式不一定规范）
        query_key = f'{product} {version}'
        if query_key in seen_cpes:
            continue
        seen_cpes.add(query_key)
        cves = _query_cve_safe(cpe or query_key)
        if cves:
            cve_score += min(len(cves) * 10, 20)  # 单产品封顶 20
            for cve in cves[:2]:  # 每产品最多记 2 条
                cve_details.append({
                    'product': product,
                    'version': version,
                    'cve_id': cve.get('cve_id', ''),
                    'cvss_score': cve.get('cvss_score', 0),
                    'severity': cve.get('severity', ''),
                })
            cves_found.extend(cves)
    cve_score = min(cve_score, CAP_CVE)
    factors['cve'] = {'score': cve_score, 'details': cve_details}

    # ── 维度 4: SSL 证书问题 ──
    ssl_score = 0
    ssl_details = []
    for w in host.get('web_info', []):
        ssl = w.get('ssl')
        if not ssl:
            continue
        if ssl.get('expired'):
            ssl_score = max(ssl_score, CAP_SSL)
            ssl_details.append({'issue': '证书已过期', 'points': CAP_SSL})
            break
        protocol = ssl.get('protocol', '')
        if protocol in WEAK_TLS_PROTOCOLS:
            ssl_score = max(ssl_score, 8)
            ssl_details.append({'issue': f'弱协议 {protocol}', 'points': 8})
        # 即将过期（<30 天）
        not_after = ssl.get('not_after', '')
        if not_after:
            days_left = _days_until(not_after)
            if 0 <= days_left <= 30:
                ssl_score = max(ssl_score, 5)
                ssl_details.append({'issue': f'证书 {days_left} 天后过期', 'points': 5})
    factors['ssl'] = {'score': min(ssl_score, CAP_SSL), 'details': ssl_details}

    # ── 维度 5: 威胁情报命中 ──
    threat_score = 0
    threat_details = []
    risk_level = host.get('threat_risk_level', 0)
    if risk_level and int(risk_level) >= 2:
        threat_score = CAP_THREAT
        threat_details.append({'issue': f'威胁情报标记高危(risk_level={risk_level})', 'points': CAP_THREAT})
    factors['threat'] = {'score': threat_score, 'details': threat_details}

    # 汇总（满分 = 30+25+20+15+10 = 100）
    total = (
        factors['sensitive']['score']
        + factors['high_risk_ports']['score']
        + factors['cve']['score']
        + factors['ssl']['score']
        + factors['threat']['score']
    )

    return {'score': min(total, 100), 'factors': factors}


def risk_level(score: int) -> str:
    """分数 → 风险等级标签。"""
    if score >= 70:
        return 'high'
    elif score >= 40:
        return 'medium'
    return 'low'


def _query_cve_safe(keyword: str) -> list:
    """安全调用 NVD 查询（失败返回空，不阻塞扫描）。"""
    try:
        from .tools.nvd import query_nvd
        return query_nvd(keyword)
    except Exception:
        return []


def _days_until(date_str: str) -> int | None:
    """解析证书日期，返回距今天数。失败返回 None。"""
    for fmt in ('%b %d %H:%M:%S %Y %Z', '%Y-%m-%dT%H:%M:%S'):
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
            return (dt - datetime.now()).days
        except ValueError:
            continue
    return None
