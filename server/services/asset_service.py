"""资产聚合服务 — 跨扫描的主机/Web 汇总 + 反向搜索。"""

import json

from sqlalchemy import func

from ..db import SessionLocal
from ..models import Host, Port, WebInfo, Banner, WhoisRecord


def list_assets(q: str = "", sort: str = "last_seen") -> dict:
    """跨扫描资产聚合。"""
    db = SessionLocal()
    try:
        # 按 hostname+ip 聚合
        sub = (
            db.query(
                Host.hostname,
                Host.ip,
                func.min(Host.scan_id).label("first_scan_id"),
                func.max(Host.host_id).label("last_host_id"),
                func.max(Host.risk_score).label("risk_score"),
                func.count(Host.host_id).label("scan_count"),
            )
            .group_by(Host.hostname, Host.ip)
            .subquery()
        )

        rows = db.query(sub).all()

        items = []
        for row in rows:
            hostname = row.hostname or ""
            ip = row.ip or ""

            if q and q.lower() not in hostname.lower() and q.lower() not in ip.lower():
                continue

            # 查询端口数和 web 数
            port_count = (
                db.query(func.count(Port.port_id))
                .join(Host, Port.host_id == Host.host_id)
                .filter(Host.hostname == hostname, Host.ip == ip)
                .scalar()
                or 0
            )
            web_count = (
                db.query(func.count(WebInfo.web_id))
                .join(Host, WebInfo.host_id == Host.host_id)
                .filter(Host.hostname == hostname, Host.ip == ip)
                .scalar()
                or 0
            )

            items.append({
                "ip": ip,
                "hostname": hostname,
                "scan_count": row.scan_count,
                "port_count": port_count,
                "web_count": web_count,
                "risk_score": row.risk_score or 0,
            })

        # 排序
        if sort == "port_count":
            items.sort(key=lambda x: x["port_count"], reverse=True)
        elif sort == "scan_count":
            items.sort(key=lambda x: x["scan_count"], reverse=True)
        elif sort == "risk_score":
            items.sort(key=lambda x: x["risk_score"], reverse=True)
        else:
            items.sort(key=lambda x: x["hostname"])

        return {"items": items, "total": len(items)}
    finally:
        db.close()


def get_asset_by_ip(ip: str) -> dict | None:
    """反向搜索：给定 IP，返回该 IP 在所有扫描中的关联资产。

    聚合: distinct hostname 列表 + 所有端口 + 所有 Web 站点(含 SSL) +
    所有 Banner + WHOIS 记录 + 出现过的扫描列表。
    """
    db = SessionLocal()
    try:
        hosts = db.query(Host).filter(Host.ip == ip).all()
        if not hosts:
            return None

        host_ids = [h.host_id for h in hosts]
        hostnames = sorted({h.hostname for h in hosts if h.hostname})
        scan_ids = sorted({h.scan_id for h in hosts})

        # 端口聚合（去重）
        ports_rows = db.query(Port).filter(Port.host_id.in_(host_ids)).all()
        seen_ports = set()
        ports = []
        for p in ports_rows:
            key = (p.port, p.proto, p.state, p.service, p.product, p.version)
            if key not in seen_ports:
                seen_ports.add(key)
                ports.append({
                    "port": p.port, "proto": p.proto, "state": p.state,
                    "service": p.service, "product": p.product, "version": p.version,
                })

        # Web 站点（含 SSL/技术栈/favicon）
        web_rows = db.query(WebInfo).filter(WebInfo.host_id.in_(host_ids)).all()
        web_info = []
        for w in web_rows:
            web_info.append({
                "url": w.url, "port": w.port, "status": w.status_code,
                "title": w.title, "redirect": w.redirect,
                "headers": json.loads(w.headers_json) if w.headers_json else {},
                "tech": json.loads(w.tech_json) if w.tech_json else [],
                "ssl": json.loads(w.ssl_json) if w.ssl_json and w.ssl_json != "null" else None,
                "favicon_hash": w.favicon_hash or "",
            })

        # Banner
        banner_rows = db.query(Banner).filter(Banner.host_id.in_(host_ids)).all()
        banners = [{"port": b.port, "service": b.service, "banner": b.banner} for b in banner_rows]

        # WHOIS 记录
        whois_rows = db.query(WhoisRecord).filter(WhoisRecord.host_id.in_(host_ids)).all()
        whois = [{
            "type": wr.type, "target": wr.target,
            "data": json.loads(wr.data_json) if wr.data_json else {},
        } for wr in whois_rows]

        return {
            "ip": ip,
            "hostnames": hostnames,
            "scan_count": len(scan_ids),
            "scan_ids": scan_ids,
            "ports": ports,
            "web_info": web_info,
            "banners": banners,
            "whois": whois,
            "port_count": len(ports),
            "web_count": len(web_info),
            "risk_score": max((h.risk_score or 0) for h in hosts),
        }
    finally:
        db.close()
