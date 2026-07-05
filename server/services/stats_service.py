"""全局统计服务 — 跨扫描聚合仪表盘关键数据。"""

import json

from sqlalchemy import func

from ..db import SessionLocal
from ..models import Scan, Host, Port, WebInfo, Banner, SensitivePath, Vulnerability, WhoisRecord, JSFinding


def get_overview_stats() -> dict:
    """返回仪表盘全局概览统计。"""
    db = SessionLocal()
    try:
        # 基础计数
        scan_count = db.query(func.count(Scan.scan_id)).scalar() or 0
        # 总资产 = 唯一 (hostname, ip) 对
        asset_count = db.query(
            func.count(func.distinct(func.concat(Host.hostname, '|', Host.ip)))
        ).filter(Host.ip != "").scalar() or 0
        ip_count = db.query(func.count(func.distinct(Host.ip))).filter(Host.ip != "").scalar() or 0
        hostname_count = db.query(func.count(func.distinct(Host.hostname))).filter(Host.hostname != "").scalar() or 0
        # 端口去重（按 ip+port+proto，跨扫描的唯一端口）
        port_count = db.query(
            func.count(func.distinct(func.concat(Host.ip, '|', Port.port, '|', Port.proto)))
        ).select_from(Port).join(Host, Port.host_id == Host.host_id).filter(Host.ip != "").scalar() or 0
        # Web 站点去重（按 url）
        web_count = db.query(func.count(func.distinct(WebInfo.url))).scalar() or 0
        # 漏洞去重（按 host_ip+template_id+cve）
        vuln_count = db.query(
            func.count(func.distinct(func.concat(Host.ip, '|', Vulnerability.template_id, '|', Vulnerability.cve)))
        ).select_from(Vulnerability).join(Host, Vulnerability.host_id == Host.host_id).scalar() or 0
        # 敏感路径去重（按 host_ip+path）
        sensitive_count = db.query(
            func.count(func.distinct(func.concat(Host.ip, '|', SensitivePath.path)))
        ).select_from(SensitivePath).join(Host, SensitivePath.host_id == Host.host_id).scalar() or 0
        banner_count = db.query(
            func.count(func.distinct(func.concat(Host.ip, '|', Banner.port, '|', Banner.service)))
        ).select_from(Banner).join(Host, Banner.host_id == Host.host_id).scalar() or 0

        # 服务/协议类型（去重 service 字段）
        services = [
            r[0] for r in db.query(func.distinct(Port.service))
            .filter(Port.service != "").all()
        ]

        # 漏洞严重度分布
        vuln_by_severity = {}
        sev_rows = db.query(
            Vulnerability.severity, func.count(Vulnerability.vuln_id)
        ).group_by(Vulnerability.severity).all()
        for r in sev_rows:
            vuln_by_severity[r[0] or 'info'] = r[1]

        # 运行中任务
        running_count = db.query(func.count(Scan.scan_id)).filter(Scan.status == "running").scalar() or 0

        return {
            "scan_count": scan_count,
            "asset_count": asset_count,
            "ip_count": ip_count,
            "hostname_count": hostname_count,
            "port_count": port_count,
            "web_count": web_count,
            "vuln_count": vuln_count,
            "sensitive_count": sensitive_count,
            "banner_count": banner_count,
            "protocol_count": len(services),
            "services": services,
            "vuln_by_severity": vuln_by_severity,
            "running_count": running_count,
        }
    finally:
        db.close()


def get_asset_detail(hostname: str, ip: str) -> dict | None:
    """返回单个资产(IP+域名)的完整详情，用于资产清单展开行。

    聚合跨所有扫描的数据: 端口/服务/技术栈/漏洞/SSL/Banner/敏感路径。
    """
    db = SessionLocal()
    try:
        hosts = db.query(Host).filter(
            Host.hostname == hostname, Host.ip == ip
        ).all()
        if not hosts:
            return None

        host_ids = [h.host_id for h in hosts]
        scan_ids = sorted({h.scan_id for h in hosts})

        # 端口（去重）
        port_rows = db.query(Port).filter(Port.host_id.in_(host_ids)).all()
        seen_ports = set()
        ports = []
        for p in port_rows:
            key = (p.port, p.proto, p.service, p.product, p.version)
            if key not in seen_ports:
                seen_ports.add(key)
                ports.append({
                    "port": p.port, "proto": p.proto, "state": p.state,
                    "service": p.service, "product": p.product, "version": p.version,
                })

        # Web 站点 + 技术栈
        web_rows = db.query(WebInfo).filter(WebInfo.host_id.in_(host_ids)).all()
        web_info = []
        all_tech = []  # 保留完整 tech 对象（含 version/confidence），按 name 去重
        seen_tech = set()
        for w in web_rows:
            tech = json.loads(w.tech_json) if w.tech_json else []
            for t in tech:
                name = t.get("name")
                if name and name not in seen_tech:
                    seen_tech.add(name)
                    all_tech.append({
                        "name": name,
                        "version": t.get("version", ""),
                        "confidence": t.get("confidence"),
                        "category": t.get("category", ""),
                    })
            web_info.append({
                "url": w.url, "port": w.port, "status": w.status_code,
                "title": w.title,
                "tech": tech,
                "ssl": json.loads(w.ssl_json) if w.ssl_json and w.ssl_json != "null" else None,
                "cdn": w.cdn_detected or "",
                "favicon_hash": w.favicon_hash or "",
            })

        # 漏洞
        vuln_rows = db.query(Vulnerability).filter(Vulnerability.host_id.in_(host_ids)).all()
        vulnerabilities = [{
            "name": v.name, "severity": v.severity, "cve": v.cve,
            "cvss_score": v.cvss_score, "cwe": v.cwe, "category": v.category,
            "template_id": v.template_id,
        } for v in vuln_rows]

        # Banner
        banner_rows = db.query(Banner).filter(Banner.host_id.in_(host_ids)).all()
        banners = [{"port": b.port, "service": b.service, "banner": b.banner} for b in banner_rows]

        # 敏感路径
        sens_rows = db.query(SensitivePath).filter(SensitivePath.host_id.in_(host_ids)).all()
        sensitive = [{
            "path": s.path, "severity": s.severity, "description": s.description,
        } for s in sens_rows]

        # WHOIS/RDAP 注册信息 + IP ASN + DNS 记录（同表不同 type）
        whois_rows = db.query(WhoisRecord).filter(WhoisRecord.host_id.in_(host_ids)).all()
        whois = []
        dns_records = []
        for w in whois_rows:
            try:
                data = json.loads(w.data_json) if w.data_json else {}
            except json.JSONDecodeError:
                data = {}
            entry = {
                "type": w.type,
                "target": w.target,
                "queried_at": w.queried_at.isoformat() + "Z" if w.queried_at else "",
                "data": data,
            }
            if w.type == "dns":
                dns_records.append(entry)
            else:
                whois.append(entry)

        # JS 分析（API 端点 + 密钥泄露）
        js_rows = db.query(JSFinding).filter(JSFinding.host_id.in_(host_ids)).all()
        js_findings = []
        for j in js_rows:
            try:
                apis = json.loads(j.api_endpoints_json) if j.api_endpoints_json else []
            except json.JSONDecodeError:
                apis = []
            try:
                secrets = json.loads(j.secrets_json) if j.secrets_json else []
            except json.JSONDecodeError:
                secrets = []
            js_findings.append({
                "js_url": j.js_url,
                "api_endpoints": apis,
                "secrets": secrets,
            })

        # 单资产生命周期：遍历每次扫描，端口/技术栈相邻 diff
        timeline = _compute_asset_timeline(db, hosts)

        return {
            "hostname": hostname,
            "ip": ip,
            "scan_count": len(scan_ids),
            "scan_ids": scan_ids,
            "ports": ports,
            "web_info": web_info,
            "vulnerabilities": vulnerabilities,
            "banners": banners,
            "sensitive": sensitive,
            "whois": whois,
            "dns_records": dns_records,
            "js_findings": js_findings,
            "tech_stack": sorted(all_tech, key=lambda x: x.get("name", "")),
            "timeline": timeline,
            "port_count": len(ports),
            "web_count": len(web_info),
            "vuln_count": len(vulnerabilities),
        }
    finally:
        db.close()


def _compute_asset_timeline(db, hosts: list) -> list[dict]:
    """计算单个资产的端口/技术栈变化时间线。

    遍历该资产参与的每次扫描（按时间排序），相邻扫描 diff 端口集和技术栈集。
    返回 [{scan_id, started_at, ports_added, ports_removed, tech_added, tech_removed}, ...]
    """
    from ..utils import to_iso_z

    # host 按 scan 关联，取每次扫描的 host 记录
    host_by_scan = {h.scan_id: h for h in hosts}
    scan_ids = sorted(host_by_scan.keys())

    # 查这些扫描的时间，按时间排序
    from ..models import Scan
    scans = db.query(Scan).filter(Scan.scan_id.in_(scan_ids)).order_by(Scan.started_at.asc()).all()
    scan_order = [s.scan_id for s in scans]
    scan_time = {s.scan_id: s for s in scans}

    points = []
    prev_ports = None
    prev_tech = None

    for sid in scan_order:
        h = host_by_scan.get(sid)
        scan = scan_time.get(sid)
        if not h or not scan:
            continue

        # 本次扫描的端口集（port/proto）
        curr_ports = set()
        for p in db.query(Port).filter(Port.host_id == h.host_id).all():
            if p.state == "open":
                curr_ports.add(f"{p.port}/{p.proto}")

        # 本次扫描的技术栈集
        curr_tech = set()
        for w in db.query(WebInfo).filter(WebInfo.host_id == h.host_id).all():
            try:
                tech = json.loads(w.tech_json) if w.tech_json else []
                for t in tech:
                    name = t.get("name") if isinstance(t, dict) else t
                    if name:
                        curr_tech.add(name)
            except json.JSONDecodeError:
                pass

        if prev_ports is None:
            ports_added = len(curr_ports)
            ports_removed = 0
            tech_added = len(curr_tech)
            tech_removed = 0
        else:
            ports_added = len(curr_ports - prev_ports)
            ports_removed = len(prev_ports - curr_ports)
            tech_added = len(curr_tech - prev_tech)
            tech_removed = len(prev_tech - curr_tech)

        points.append({
            "scan_id": sid,
            "scan_name": scan.name or sid,
            "started_at": to_iso_z(scan.started_at) or "",
            "port_count": len(curr_ports),
            "ports_added": ports_added,
            "ports_removed": ports_removed,
            "tech_count": len(curr_tech),
            "tech_added": tech_added,
            "tech_removed": tech_removed,
        })
        prev_ports = curr_ports
        prev_tech = curr_tech

    return points
