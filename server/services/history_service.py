"""历史查询服务 — 分页、搜索、详情。"""

from ..db import SessionLocal
from ..models import Scan


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
                    "started_at": s.started_at,
                    "finished_at": s.finished_at,
                    "duration_secs": s.duration_secs,
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
    """获取单次扫描概要。"""
    db = SessionLocal()
    try:
        s = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not s:
            return None
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
            "started_at": s.started_at,
            "finished_at": s.finished_at,
            "duration_secs": s.duration_secs,
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
