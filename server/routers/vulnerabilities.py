"""漏洞管理 API — 漏洞状态流转（生命周期管理）。

漏洞状态机:
  open → confirmed → fixing → fixed → verified → closed
                ↘ false_positive (误报)
  任意状态 → open (重新打开)
"""

from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from ..db import SessionLocal
from ..models import Vulnerability

router = APIRouter(tags=["vulnerabilities"])

# 允许的状态值
VALID_STATUSES = {
    "open",           # 新发现
    "confirmed",      # 已确认（非误报）
    "fixing",         # 修复中
    "fixed",          # 已修复
    "verified",       # 已验证修复
    "closed",         # 已关闭
    "false_positive", # 误报
}

# 状态标签（中英双语）
STATUS_LABELS = {
    "open": "待处理",
    "confirmed": "已确认",
    "fixing": "修复中",
    "fixed": "已修复",
    "verified": "已验证",
    "closed": "已关闭",
    "false_positive": "误报",
}


class VulnStatusUpdate(BaseModel):
    status: str
    note: Optional[str] = None


@router.patch("/vulnerabilities/{vuln_id}/status", summary="更新漏洞状态", description="漏洞生命周期流转：open→confirmed→fixing→fixed→verified→closed / false_positive")
def update_vuln_status(vuln_id: int, update: VulnStatusUpdate):
    """更新漏洞状态（生命周期流转）。"""
    if update.status not in VALID_STATUSES:
        raise HTTPException(400, f"无效状态，允许: {', '.join(sorted(VALID_STATUSES))}")

    db = SessionLocal()
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.vuln_id == vuln_id).first()
        if not vuln:
            raise HTTPException(404, "漏洞不存在")

        vuln.status = update.status
        vuln.updated_at = datetime.utcnow()
        if update.note is not None:
            vuln.note = update.note
        db.commit()

        return {
            "ok": True,
            "vuln_id": vuln_id,
            "status": vuln.status,
            "status_label": STATUS_LABELS.get(vuln.status, vuln.status),
            "note": vuln.note,
        }
    finally:
        db.close()


@router.get("/vulnerabilities/statuses", summary="获取漏洞状态列表", description="返回所有可用的漏洞状态值（前端下拉框用）")
def get_vuln_statuses():
    """返回所有可用状态（前端下拉框用）。"""
    return [
        {"value": k, "label": v}
        for k, v in STATUS_LABELS.items()
    ]


@router.get("/vulnerabilities/stats", summary="漏洞状态统计", description="返回漏洞按状态和严重性的分布统计（ASM 仪表盘用）")
def get_vuln_stats():
    """漏洞状态统计（仪表盘用）。"""
    from sqlalchemy import func
    db = SessionLocal()
    try:
        total = db.query(func.count(Vulnerability.vuln_id)).scalar() or 0
        by_status = {}
        rows = db.query(
            Vulnerability.status,
            func.count(Vulnerability.vuln_id),
        ).group_by(Vulnerability.status).all()
        for status, count in rows:
            by_status[status or "open"] = count

        by_severity = {}
        rows2 = db.query(
            Vulnerability.severity,
            func.count(Vulnerability.vuln_id),
        ).group_by(Vulnerability.severity).all()
        for sev, count in rows2:
            by_severity[sev] = count

        return {
            "total": total,
            "by_status": by_status,
            "by_severity": by_severity,
            "open_count": by_status.get("open", 0),
            "fixed_count": by_status.get("fixed", 0) + by_status.get("verified", 0) + by_status.get("closed", 0),
        }
    finally:
        db.close()
