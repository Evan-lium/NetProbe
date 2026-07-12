"""资产聚合服务 — 跨扫描的主机/Web 汇总 + 反向搜索。"""

import json

from sqlalchemy import func

from ..db import SessionLocal
from ..models import Host, Port, WebInfo, Banner, WhoisRecord, Vulnerability


def list_assets(q: str = "", sort: str = "last_seen") -> dict:
    """跨扫描资产聚合（单次 SQL，无 N+1）。

    返回每个资产的汇总数据 + 卡片预览（最新 Web 站点/端口/漏洞数），
    前端无需再逐个请求详情。
    """
    db = SessionLocal()
    try:
        # 端口数子查询：每个 host 的端口数
        port_cnt = (
            db.query(
                Port.host_id.label("h_id"),
                func.count(Port.port_id).label("cnt"),
            )
            .group_by(Port.host_id)
            .subquery()
        )
        # Web 数子查询
        web_cnt = (
            db.query(
                WebInfo.host_id.label("h_id"),
                func.count(WebInfo.web_id).label("cnt"),
            )
            .group_by(WebInfo.host_id)
            .subquery()
        )
        # 漏洞数子查询
        vuln_cnt = (
            db.query(
                Vulnerability.host_id.label("h_id"),
                func.count(Vulnerability.vuln_id).label("cnt"),
            )
            .group_by(Vulnerability.host_id)
            .subquery()
        )

        # 主聚合：按 hostname+ip 分组，JOIN 端口/Web/漏洞计数（单次查询）
        rows = (
            db.query(
                Host.hostname.label("hostname"),
                Host.ip.label("ip"),
                func.max(Host.risk_score).label("risk_score"),
                func.count(Host.host_id).label("scan_count"),
                func.sum(func.coalesce(port_cnt.c.cnt, 0)).label("port_count"),
                func.sum(func.coalesce(web_cnt.c.cnt, 0)).label("web_count"),
                func.sum(func.coalesce(vuln_cnt.c.cnt, 0)).label("vuln_count"),
            )
            .outerjoin(port_cnt, port_cnt.c.h_id == Host.host_id)
            .outerjoin(web_cnt, web_cnt.c.h_id == Host.host_id)
            .outerjoin(vuln_cnt, vuln_cnt.c.h_id == Host.host_id)
            .group_by(Host.hostname, Host.ip)
            .all()
        )

        # 批量预取每个资产的最新 Web 站点（1 次查询覆盖全部）
        # 取每个 hostname+ip 下 web_id 最大的那条（最新扫描）
        all_host_ids = []
        host_key_map = {}  # host_id → (hostname, ip)
        # 先收集过滤后的资产
        filtered = []
        ql = q.lower() if q else ""
        for row in rows:
            hostname = row.hostname or ""
            ip = row.ip or ""
            if ql and ql not in hostname.lower() and ql not in ip.lower():
                continue
            filtered.append(row)

        # 查这些资产的所有 host_id（一个 hostname+ip 可能有多条 host 记录）
        key_set = {(r.hostname or "", r.ip or "") for r in filtered}
        host_rows = db.query(Host.host_id, Host.hostname, Host.ip).all()
        # key → [host_id, ...]（一个 key 多个 host_id）
        key_to_hostids: dict[tuple, list[int]] = {}
        for hr in host_rows:
            k = (hr.hostname or "", hr.ip or "")
            if k in key_set:
                all_host_ids.append(hr.host_id)
                key_to_hostids.setdefault(k, []).append(hr.host_id)
        # host_id → key 反查
        for k, hids in key_to_hostids.items():
            for hid in hids:
                host_key_map[hid] = k

        # 批量查最新 WebInfo（每个 key 的所有 host_id 中 web_id 最大的那条）
        latest_web = {}  # (hostname, ip) → web_info dict
        if all_host_ids:
            web_rows = (
                db.query(WebInfo)
                .filter(WebInfo.host_id.in_(all_host_ids))
                .order_by(WebInfo.web_id.desc())
                .all()
            )
            for w in web_rows:
                k = host_key_map.get(w.host_id)
                if not k or k in latest_web:
                    continue  # 已有最新的，跳过
                tech = []
                try:
                    tech = json.loads(w.tech_json) if w.tech_json else []
                except json.JSONDecodeError:
                    pass
                headers = {}
                try:
                    headers = json.loads(w.headers_json) if w.headers_json else {}
                except json.JSONDecodeError:
                    pass
                latest_web[k] = {
                    "url": w.url, "port": w.port, "status": w.status_code,
                    "title": w.title or "",
                    "tech": tech[:10],
                    "server": headers.get("Server") or headers.get("server") or "",
                }

        # 批量查端口列表（每个 hostname+ip 去重后的端口）
        port_list = {}  # (hostname, ip) → [{port, proto}]
        if all_host_ids:
            port_rows = db.query(Port).filter(Port.host_id.in_(all_host_ids)).all()
            for p in port_rows:
                k = host_key_map.get(p.host_id)
                if k:
                    pl = port_list.setdefault(k, [])
                    entry = {"port": p.port, "proto": p.proto}
                    if entry not in pl:
                        pl.append(entry)

        items = []
        for row in filtered:
            hostname = row.hostname or ""
            ip = row.ip or ""
            k = (hostname, ip)
            web = latest_web.get(k)
            items.append({
                "ip": ip,
                "hostname": hostname,
                "scan_count": row.scan_count or 0,
                "port_count": int(row.port_count or 0),
                "web_count": int(row.web_count or 0),
                "vuln_count": int(row.vuln_count or 0),
                "risk_score": row.risk_score or 0,
                # 卡片预览数据（后端预聚合，前端无需逐个请求详情）
                "_preview": {
                    "firstSite": web,
                    "ports": port_list.get(k, [])[:12],
                    "primary": _pick_primary(web, port_list.get(k, [])),
                    "vulnCount": int(row.vuln_count or 0),
                } if web or port_list.get(k) else None,
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


def _pick_primary(web: dict | None, ports: list[dict]) -> dict | None:
    """卡片头部主端口：站点端口优先，否则第一个开放端口。"""
    if web and web.get("port"):
        proto = "https" if (web.get("url") or "").startswith("https://") else "http"
        return {"port": web["port"], "proto": proto}
    if ports:
        return {"port": ports[0]["port"], "proto": ports[0].get("proto", "tcp")}
    return None
