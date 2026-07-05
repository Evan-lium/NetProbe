"""历史查询服务 — 分页、搜索、详情。"""

import json

from ..db import SessionLocal
from ..models import Scan, Host, Port, WebInfo
from ..utils import to_iso_z


def _infer_scan_mode(options_json: str) -> str:
    """从 options_json 反推扫描模式（兼容老数据 + 新数据的显式 scan_mode）。

    quick: masscan + no_dns_brute + no_web
    deep:  nmap + timeout>=900
    normal: 其余
    """
    if not options_json:
        return "normal"
    try:
        opts = json.loads(options_json)
    except (json.JSONDecodeError, TypeError):
        return "normal"
    # 新数据直接有 scan_mode
    mode = opts.get("scan_mode", "")
    if mode in ("quick", "normal", "deep"):
        return mode
    # 老数据反推
    if opts.get("portscan_tool") == "masscan" and opts.get("no_dns_brute") and opts.get("no_web"):
        return "quick"
    if opts.get("portscan_tool") == "nmap" and opts.get("timeout", 0) >= 900:
        return "deep"
    return "normal"


def list_scans(page: int = 1, per_page: int = 20, q: str = "", status: str = "") -> dict:
    """分页查询扫描历史。"""
    db = SessionLocal()
    try:
        query = db.query(Scan)

        if q:
            query = query.filter(
                (Scan.target_raw.contains(q)) | (Scan.base_domain.contains(q))
            )
        if status:
            query = query.filter(Scan.status == status)

        total = query.count()
        items = (
            query.order_by(Scan.started_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )

        return {
            "items": [
                {
                    "scan_id": s.scan_id,
                    "name": s.name or "",
                    "target_raw": s.target_raw,
                    "base_domain": s.base_domain,
                    "status": s.status,
                    "host_count": s.host_count,
                    "port_count": s.port_count,
                    "web_count": s.web_count,
                    "sensitive_count": s.sensitive_count,
                    "error_msg": s.error_msg,
                    "started_at": to_iso_z(s.started_at),
                    "finished_at": to_iso_z(s.finished_at),
                    "duration_secs": s.duration_secs,
                    "scan_mode": _infer_scan_mode(s.options_json),
                }
                for s in items
            ],
            "total": total,
            "page": page,
            "per_page": per_page,
        }
    finally:
        db.close()


def get_scan_detail(scan_id: str) -> dict | None:
    """获取单次扫描详情（含主机/端口/Web站点完整数据）。"""
    import json as _json
    db = SessionLocal()
    try:
        s = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not s:
            return None

        # 查完整主机/端口/Web 数据
        hosts_data = []
        for h in db.query(Host).filter(Host.scan_id == scan_id).all():
            ports = [{"port": p.port, "proto": p.proto, "state": p.state,
                      "service": p.service, "product": p.product, "version": p.version}
                     for p in db.query(Port).filter(Port.host_id == h.host_id).all()]
            web_info = [{"url": w.url, "status": w.status_code, "title": w.title}
                        for w in db.query(WebInfo).filter(WebInfo.host_id == h.host_id).all()]
            hosts_data.append({
                "hostname": h.hostname,
                "ip": h.ip,
                "os": h.os_info or "",
                "ports": ports,
                "web_info": web_info,
            })

        return {
            "scan_id": s.scan_id,
            "name": s.name or "",
            "target_raw": s.target_raw,
            "base_domain": s.base_domain,
            "status": s.status,
            "host_count": s.host_count,
            "port_count": s.port_count,
            "web_count": s.web_count,
            "sensitive_count": s.sensitive_count,
            "error_msg": s.error_msg,
            "started_at": to_iso_z(s.started_at),
            "finished_at": to_iso_z(s.finished_at),
            "duration_secs": s.duration_secs,
            "hosts": hosts_data,
        }
    finally:
        db.close()


def delete_scan(scan_id: str) -> bool:
    """删除扫描记录（级联删除关联数据）。"""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            return False
        db.delete(scan)
        db.commit()
        return True
    finally:
        db.close()
