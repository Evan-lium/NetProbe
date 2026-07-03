"""告警 API — 规则 CRUD + 触发历史。"""

from fastapi import APIRouter, HTTPException

from ..schemas.alert import AlertCreate
from ..services.alert_service import (
    create_alert, delete_alert, list_alerts, list_events,
)

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
def get_alerts():
    """列出全部告警规则。"""
    items = list_alerts()
    return {"items": items, "total": len(items)}


@router.post("/alerts")
def post_alert(req: AlertCreate):
    """创建告警规则。"""
    return create_alert(
        name=req.name,
        condition_type=req.condition_type,
        target=req.target,
        threshold=req.threshold,
        enabled=req.enabled,
    )


@router.delete("/alerts/{alert_id}")
def del_alert(alert_id: int):
    """删除告警规则。"""
    if not delete_alert(alert_id):
        raise HTTPException(404, "alert not found")
    return {"ok": True}


@router.get("/alerts/events")
def get_alert_events(limit: int = 50):
    """列出告警触发历史。"""
    items = list_events(limit)
    return {"items": items, "total": len(items)}
