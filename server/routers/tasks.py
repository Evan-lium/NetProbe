"""任务管理 API — 列表、详情、取消、删除。"""

import json

from fastapi import APIRouter, HTTPException

from ..db import SessionLocal
from ..models import Scan, Host, Port, WebInfo, Vulnerability, SensitivePath
from ..services.scan_service import (
    get_task,
    get_tasks,
    cancel_task,
    list_active_tasks,
)
from ..services.history_service import delete_scan, _infer_scan_mode
from ..db import SessionLocal
from ..models import Scan
from ..utils import to_iso_z

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
                "started_at": to_iso_z(s.started_at) or "",
                "finished_at": to_iso_z(s.finished_at),
                "duration_secs": s.duration_secs,
                "progress": "",
                "options": json.loads(s.options_json) if s.options_json else None,
                "scan_mode": _infer_scan_mode(s.options_json),
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
            elapsed = int((datetime.utcnow() - task["created_at"]).total_seconds())
        return {
            "id": task_id,
            "scan_id": task_id,
            "name": task.get("name", ""),
            "target": task.get("target", ""),
            "status": task["status"],
            "host_count": len(task.get("hosts", [])),
            "port_count": 0,
            "web_count": 0,
            "started_at": to_iso_z(task.get("created_at")) or "",
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

        # 解析下发的目标（换行/逗号/空格分隔的原始输入拆分）
        targets = [t.strip() for t in (s.target_raw or "").replace(',', '\n').replace(' ', '\n').split('\n') if t.strip()]

        # 发现的主机概要（hostname + ip + 端口数 + 风险分）
        hosts = db.query(Host).filter(Host.scan_id == task_id).all()
        discovered_hosts = []
        from sqlalchemy import func as _f
        for h in hosts:
            port_n = db.query(_f.count(Port.port_id)).filter(Port.host_id == h.host_id).scalar() or 0
            web_n = db.query(_f.count(WebInfo.web_id)).filter(WebInfo.host_id == h.host_id).scalar() or 0
            vuln_n = db.query(_f.count(Vulnerability.vuln_id)).filter(Vulnerability.host_id == h.host_id).scalar() or 0
            discovered_hosts.append({
                "hostname": h.hostname or h.ip,
                "ip": h.ip,
                "port_count": port_n,
                "web_count": web_n,
                "vuln_count": vuln_n,
                "risk_score": h.risk_score or 0,
            })

        # 分项统计
        total_ports = sum(d["port_count"] for d in discovered_hosts)
        total_web = sum(d["web_count"] for d in discovered_hosts)
        total_vulns = sum(d["vuln_count"] for d in discovered_hosts)
        total_sensitive = db.query(_f.count(SensitivePath.id)).join(Host, SensitivePath.host_id == Host.host_id).filter(Host.scan_id == task_id).scalar() or 0

        return {
            "id": s.scan_id,
            "scan_id": s.scan_id,
            "name": s.name or "",
            "target": s.target_raw,
            "targets": targets,
            "base_domain": s.base_domain or "",
            "status": s.status,
            "host_count": s.host_count,
            "port_count": s.port_count,
            "web_count": s.web_count,
            "started_at": to_iso_z(s.started_at) or "",
            "finished_at": to_iso_z(s.finished_at),
            "duration_secs": s.duration_secs,
            "progress": "",
            "options": json.loads(s.options_json) if s.options_json else None,
            "error_msg": s.error_msg or "",
            # 扫描结果概要
            "discovered_hosts": discovered_hosts,
            "result_summary": {
                "host_count": len(discovered_hosts),
                "port_count": total_ports,
                "web_count": total_web,
                "vuln_count": total_vulns,
                "sensitive_count": total_sensitive,
            },
        }
    finally:
        db.close()


@router.get("/tasks/{task_id}/logs")
def get_task_logs(task_id: str):
    """获取任务的历史扫描日志（持久化在 DB progress_log）。

    解决：刷新页面/重启服务后 SSE 日志丢失，历史任务日志查看。
    """
    from ..services.scan_service import get_progress_log
    log_text = get_progress_log(task_id)
    return {"scan_id": task_id, "lines": log_text.split("\n") if log_text else []}


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
