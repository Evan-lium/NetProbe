"""全局统计服务 — 跨扫描聚合仪表盘关键数据。"""

import json

from sqlalchemy import func

from ..db import SessionLocal
from ..models import Scan, Host, Port, WebInfo, Banner, SensitivePath, Vulnerability


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
        all_tech = set()
        for w in web_rows:
            tech = json.loads(w.tech_json) if w.tech_json else []
            for t in tech:
                if t.get("name"):
                    all_tech.add(t["name"])
            web_info.append({
                "url": w.url, "port": w.port, "status": w.status_code,
                "title": w.title,
                "tech": [t.get("name", "") for t in tech if t.get("name")],
                "ssl": json.loads(w.ssl_json) if w.ssl_json and w.ssl_json != "null" else None,
                "cdn": w.cdn_detected or "",
                "favicon_hash": w.favicon_hash or "",
            })

        # 漏洞
        vuln_rows = db.query(Vulnerability).filter(Vulnerability.host_id.in_(host_ids)).all()
        vulnerabilities = [{
            "name": v.name, "severity": v.severity, "cve": v.cve,
            "cvss_score": v.cvss_score, "template_id": v.template_id,
        } for v in vuln_rows]

        # Banner
        banner_rows = db.query(Banner).filter(Banner.host_id.in_(host_ids)).all()
        banners = [{"port": b.port, "service": b.service, "banner": b.banner} for b in banner_rows]

        # 敏感路径
        sens_rows = db.query(SensitivePath).filter(SensitivePath.host_id.in_(host_ids)).all()
        sensitive = [{
            "path": s.path, "severity": s.severity, "description": s.description,
        } for s in sens_rows]

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
            "tech_stack": sorted(all_tech),
            "port_count": len(ports),
            "web_count": len(web_info),
            "vuln_count": len(vulnerabilities),
        }
    finally:
        db.close()
