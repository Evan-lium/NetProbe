"""任务管理 API — 列表、详情、取消、删除。"""

import json

from fastapi import APIRouter, HTTPException

from ..services.scan_service import (
    get_task,
    get_tasks,
    cancel_task,
    list_active_tasks,
)
from ..services.history_service import delete_scan
from ..db import SessionLocal
from ..models import Scan

router = APIRouter(tags=["tasks"])


@router.get("/tasks")
def list_tasks():
    """返回所有任务：内存中的运行任务 + DB 已完成任务。"""
    # 1. 内存中活跃任务
    active = list_active_tasks()
    active_ids = {t["id"] for t in active}

    # 2. DB 中不在内存的任务
    db = SessionLocal()
    try:
        db_scans = (
            db.query(Scan)
            .filter(~Scan.scan_id.in_(active_ids) if active_ids else True)
            .order_by(Scan.started_at.desc())
            .limit(50)
            .all()
        )
        for s in db_scans:
            active.append({
                "id": s.scan_id,
                "scan_id": s.scan_id,
                "name": s.name or "",
                "target": s.target_raw,
                "status": s.status,
                "host_count": s.host_count,
                "port_count": s.port_count,
                "web_count": s.web_count,
                "started_at": s.started_at.isoformat() if s.started_at else "",
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
                "duration_secs": s.duration_secs,
                "progress": "",
                "options": json.loads(s.options_json) if s.options_json else None,
                "error_msg": s.error_msg or "",
            })
    finally:
        db.close()

    # 按时间倒序排列（运行中的排最前面）
    active.sort(key=lambda t: (
        0 if t["status"] == "running" else 1,
        t.get("started_at", ""),
    ), reverse=False)

    return {"items": active, "total": len(active)}


@router.get("/tasks/{task_id}")
def get_task_detail(task_id: str):
    """获取任务详情（含 options 配置）。"""
    # 先查内存
    task = get_task(task_id)
    if task:
        elapsed = None
        if task["status"] == "running":
            from datetime import datetime
            elapsed = int((datetime.now() - task["created_at"]).total_seconds())
        return {
            "id": task_id,
            "scan_id": task_id,
            "name": task.get("name", ""),
            "target": task.get("target", ""),
            "status": task["status"],
            "host_count": len(task.get("hosts", [])),
            "port_count": 0,
            "web_count": 0,
            "started_at": task.get("created_at").isoformat() if task.get("created_at") else "",
            "finished_at": None,
            "duration_secs": elapsed,
            "progress": task.get("progress", ""),
            "options": task.get("options"),
            "error_msg": "",
        }

    # 回退到 DB
    db = SessionLocal()
    try:
        s = db.query(Scan).filter(Scan.scan_id == task_id).first()
        if not s:
            raise HTTPException(404, "task not found")
        return {
            "id": s.scan_id,
            "scan_id": s.scan_id,
            "name": s.name or "",
            "target": s.target_raw,
            "status": s.status,
            "host_count": s.host_count,
            "port_count": s.port_count,
            "web_count": s.web_count,
            "started_at": s.started_at.isoformat() if s.started_at else "",
            "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            "duration_secs": s.duration_secs,
            "progress": "",
            "options": json.loads(s.options_json) if s.options_json else None,
            "error_msg": s.error_msg or "",
        }
    finally:
        db.close()


@router.post("/tasks/{task_id}/cancel")
def cancel_scan(task_id: str):
    """取消运行中的扫描任务。"""
    if not cancel_task(task_id):
        raise HTTPException(400, "task not found or not running")
    return {"ok": True}


@router.delete("/tasks/{task_id}")
def delete_task(task_id: str):
    """删除任务（先取消再删）。"""
    task = get_task(task_id)
    if task and task["status"] == "running":
        cancel_task(task_id)

    # 从内存移除
    if task_id in get_tasks():
        del get_tasks()[task_id]

    # 从 DB 移除
    delete_scan(task_id)
    return {"ok": True}
