"""定时扫描 API — CRUD + 启用切换 + 立即触发。"""

from fastapi import APIRouter, HTTPException

from ..schemas.schedule import ScheduleCreate, ScheduleToggle, ScheduleUpdate
from ..services.schedule_service import (
    create_schedule,
    delete_schedule,
    list_schedules,
    run_now,
    set_enabled,
    update_schedule,
)

router = APIRouter(tags=["schedules"])


@router.get("/schedules")
def get_schedules():
    """列出所有定时任务规则。"""
    items = list_schedules()
    return {"items": items, "total": len(items)}


@router.post("/schedules")
def post_schedule(req: ScheduleCreate):
    """创建定时任务（校验 cron 表达式）。"""
    try:
        return create_schedule(
            name=req.name,
            target_raw=req.target,
            cron_expr=req.cron_expr,
            options=req.options,
            enabled=req.enabled,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/schedules/{schedule_id}")
def put_schedule(schedule_id: int, req: ScheduleUpdate):
    """更新定时任务。"""
    try:
        result = update_schedule(
            schedule_id=schedule_id,
            name=req.name,
            target_raw=req.target,
            cron_expr=req.cron_expr,
            options=req.options,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    if result is None:
        raise HTTPException(404, "schedule not found")
    return result


@router.delete("/schedules/{schedule_id}")
def del_schedule(schedule_id: int):
    """删除定时任务。"""
    if not delete_schedule(schedule_id):
        raise HTTPException(404, "schedule not found")
    return {"ok": True}


@router.post("/schedules/{schedule_id}/toggle")
def toggle_schedule(schedule_id: int, req: ScheduleToggle):
    """启用/暂停切换。"""
    result = set_enabled(schedule_id, req.enabled)
    if result is None:
        raise HTTPException(404, "schedule not found")
    return result


@router.post("/schedules/{schedule_id}/run")
def run_schedule(schedule_id: int):
    """立即手动触发一次定时扫描。"""
    if not run_now(schedule_id):
        raise HTTPException(404, "schedule not found")
    return {"ok": True}
