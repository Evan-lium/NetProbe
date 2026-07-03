"""跨资产关联服务 — 从已有扫描数据中按维度聚合，发现共基础设施的资产簇。

6 类关联:
  by_ip      同 IP 多域名簇（hosts.ip 聚合）
  by_cert    同 SSL 证书簇（web_info.ssl_json 的 subject+issuer+not_after）
  by_tech    同技术栈簇（web_info.tech_json 的 name 集合签名）
  by_service 同服务指纹簇（ports.product + version）
  by_favicon 同 Favicon 哈希簇（web_info.favicon_hash，FOFA icon_hash 同款）
  by_banner  同 Banner 指纹簇（banners.banner 文本）

纯查询，无需新扫描。JSON 列（ssl_json/tech_json）在应用层解析。
仅返回成员数 ≥ 2 的簇（单元素不构成关联）。
"""

import json

from sqlalchemy import func

from ..db import SessionLocal
from ..models import Host, Port, WebInfo, Banner


def _member(hostname: str, ip: str) -> dict:
    """构造一个簇成员条目。"""
    return {"hostname": hostname or "", "ip": ip or ""}


def by_ip() -> list[dict]:
    """同 IP 多域名簇：按 ip 聚合，hostname 数 > 1 才返回。"""
    db = SessionLocal()
    try:
        rows = (
            db.query(Host.ip, func.count(func.distinct(Host.hostname)).label("hn"))
            .filter(Host.ip != "")
            .group_by(Host.ip)
            .having(func.count(func.distinct(Host.hostname)) > 1)
            .all()
        )
        clusters = []
        for row in rows:
            members = (
                db.query(Host.hostname.distinct(), Host.ip)
                .filter(Host.ip == row.ip)
                .all()
            )
            clusters.append({
                "type": "ip",
                "key": row.ip,
                "count": len({m[0] for m in members}),
                "members": [_member(m[0], m[1]) for m in members],
            })
        clusters.sort(key=lambda c: c["count"], reverse=True)
        return clusters
    finally:
        db.close()


def by_cert() -> list[dict]:
    """同 SSL 证书簇：按 (subject, issuer, not_after) 聚合。"""
    db = SessionLocal()
    try:
        # 取所有非 null 证书的 WebInfo（带 host 上下文）
        rows = (
            db.query(WebInfo.ssl_json, Host.hostname, Host.ip, WebInfo.url)
            .join(Host, WebInfo.host_id == Host.host_id)
            .filter(WebInfo.ssl_json != "null", WebInfo.ssl_json != None)  # noqa: E711
            .all()
        )
        # 应用层解析 + 按证书签名分组
        groups: dict[tuple, dict] = {}  # sig -> {members:{(h,ip):m}, expired, ...}
        for ssl_json, hostname, ip, url in rows:
            try:
                cert = json.loads(ssl_json)
            except (json.JSONDecodeError, TypeError):
                continue
            subject = (cert.get("subject") or "").strip()
            issuer = (cert.get("issuer") or "").strip()
            not_after = (cert.get("not_after") or "").strip()
            if not subject:
                continue
            sig = (subject, issuer, not_after)
            if sig not in groups:
                groups[sig] = {"members": {}, "expired": bool(cert.get("expired"))}
            groups[sig]["members"][(hostname or "", ip or "")] = {
                "hostname": hostname or "", "ip": ip or "", "url": url or "",
            }

        clusters = []
        for (subject, issuer, not_after), data in groups.items():
            uniq = list(data["members"].values())
            if len(uniq) < 2:
                continue
            clusters.append({
                "type": "cert",
                "key": subject,
                "issuer": issuer,
                "not_after": not_after,
                "expired": data["expired"],
                "count": len(uniq),
                "members": uniq,
            })
        clusters.sort(key=lambda c: c["count"], reverse=True)
        return clusters
    finally:
        db.close()


def by_tech() -> list[dict]:
    """同技术栈簇：按 tech name 集合签名聚合。"""
    db = SessionLocal()
    try:
        rows = (
            db.query(WebInfo.tech_json, Host.hostname, Host.ip)
            .join(Host, WebInfo.host_id == Host.host_id)
            .filter(WebInfo.tech_json != "[]", WebInfo.tech_json != None)  # noqa: E711
            .all()
        )
        groups: dict[tuple, dict] = {}  # sig -> {members, names}
        for tech_json, hostname, ip in rows:
            try:
                tech = json.loads(tech_json)
            except (json.JSONDecodeError, TypeError):
                continue
            names = sorted({(t.get("name") or "").strip() for t in tech if t.get("name")})
            if not names:
                continue
            sig = tuple(names)
            if sig not in groups:
                groups[sig] = {"names": names, "members": {}}
            groups[sig]["members"][(hostname or "", ip or "")] = True

        clusters = []
        for sig, data in groups.items():
            members = [{"hostname": h, "ip": i} for (h, i) in data["members"]]
            if len(members) < 2:
                continue
            clusters.append({
                "type": "tech",
                "key": " + ".join(data["names"]),
                "names": data["names"],
                "count": len(members),
                "members": members,
            })
        clusters.sort(key=lambda c: c["count"], reverse=True)
        return clusters
    finally:
        db.close()


def by_service() -> list[dict]:
    """同服务指纹簇：按 (product, version) 聚合。"""
    db = SessionLocal()
    try:
        rows = (
            db.query(Port.product, Port.version, Host.hostname, Host.ip)
            .join(Host, Port.host_id == Host.host_id)
            .filter(Port.product != "")
            .all()
        )
        groups: dict[tuple, dict] = {}
        for product, version, hostname, ip in rows:
            product = (product or "").strip()
            version = (version or "").strip()
            sig = (product, version)
            if sig not in groups:
                groups[sig] = {"members": {}}
            groups[sig]["members"][(hostname or "", ip or "")] = True

        clusters = []
        for (product, version), data in groups.items():
            members = [{"hostname": h, "ip": i} for (h, i) in data["members"]]
            if len(members) < 2:
                continue
            key = f"{product}" + (f" {version}" if version else "")
            clusters.append({
                "type": "service",
                "key": key,
                "product": product,
                "version": version,
                "count": len(members),
                "members": members,
            })
        clusters.sort(key=lambda c: c["count"], reverse=True)
        return clusters
    finally:
        db.close()


def by_favicon() -> list[dict]:
    """同 Favicon 哈希簇：按 web_info.favicon_hash 聚合（FOFA icon_hash 同款算法）。"""
    db = SessionLocal()
    try:
        rows = (
            db.query(WebInfo.favicon_hash, Host.hostname, Host.ip)
            .join(Host, WebInfo.host_id == Host.host_id)
            .filter(WebInfo.favicon_hash != "")
            .all()
        )
        groups: dict[str, dict] = {}
        for favicon_hash, hostname, ip in rows:
            fh = (favicon_hash or "").strip()
            if not fh:
                continue
            if fh not in groups:
                groups[fh] = {"members": {}}
            groups[fh]["members"][(hostname or "", ip or "")] = True

        clusters = []
        for fh, data in groups.items():
            members = [{"hostname": h, "ip": i} for (h, i) in data["members"]]
            if len(members) < 2:
                continue
            clusters.append({
                "type": "favicon",
                "key": fh,
                "count": len(members),
                "members": members,
            })
        clusters.sort(key=lambda c: c["count"], reverse=True)
        return clusters
    finally:
        db.close()


def by_banner() -> list[dict]:
    """同 Banner 指纹簇：按 (port, service) 聚合相似 Banner。"""
    db = SessionLocal()
    try:
        rows = (
            db.query(Banner.port, Banner.service, Banner.banner, Host.hostname, Host.ip)
            .join(Host, Banner.host_id == Host.host_id)
            .filter(Banner.banner != "")
            .all()
        )
        # 按 (port, service, banner前60字符) 聚合——完整 banner 常含版本号差异
        groups: dict[tuple, dict] = {}
        for port, service, banner, hostname, ip in rows:
            sig = (port, (service or "").strip(), (banner or "")[:60])
            if sig not in groups:
                groups[sig] = {"members": {}, "banner": banner, "service": service, "port": port}
            groups[sig]["members"][(hostname or "", ip or "")] = True

        clusters = []
        for sig, data in groups.items():
            members = [{"hostname": h, "ip": i} for (h, i) in data["members"]]
            if len(members) < 2:
                continue
            port, service, _ = sig
            key = f"{port} {service}".strip()
            clusters.append({
                "type": "banner",
                "key": key,
                "port": port,
                "service": service,
                "banner": data["banner"],
                "count": len(members),
                "members": members,
            })
        clusters.sort(key=lambda c: c["count"], reverse=True)
        return clusters
    finally:
        db.close()


def list_correlations(corr_type: str | None = None) -> dict:
    """汇总返回关联簇。corr_type 为 ip/cert/tech/service/favicon/banner 之一，None 返回全部。"""
    builders = {
        "ip": by_ip,
        "cert": by_cert,
        "tech": by_tech,
        "service": by_service,
        "favicon": by_favicon,
        "banner": by_banner,
    }
    if corr_type and corr_type in builders:
        result = {corr_type: builders[corr_type]()}
    else:
        result = {t: fn() for t, fn in builders.items()}

    # 统计
    total = sum(len(v) for v in result.values())
    return {"groups": result, "total": total}
