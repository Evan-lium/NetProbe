"""资产聚合服务 — 跨扫描的主机/Web 汇总。"""

from sqlalchemy import func

from ..db import SessionLocal
from ..models import Host, Port, WebInfo


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
            })

        # 排序
        if sort == "port_count":
            items.sort(key=lambda x: x["port_count"], reverse=True)
        elif sort == "scan_count":
            items.sort(key=lambda x: x["scan_count"], reverse=True)
        else:
            items.sort(key=lambda x: x["hostname"])

        return {"items": items, "total": len(items)}
    finally:
        db.close()
