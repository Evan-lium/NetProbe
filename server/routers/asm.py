"""ASM（攻击面管理）API — 持续监控总览。

聚合定时扫描状态 + 新资产发现趋势 + 资产变化追踪 + CT/DNS监控状态。
"""

import json
from fastapi import APIRouter

from ..db import SessionLocal
from ..models import Scan, Host, Port, Schedule, AlertEvent, AssetTag
from sqlalchemy import func

router = APIRouter(tags=["asm"])


@router.get("/asm/overview")
def asm_overview():
    """ASM 总览：监控目标 + 扫描趋势 + 资产变化 + 告警历史。"""
    db = SessionLocal()
    try:
        # 1. 监控目标（定时扫描任务）
        schedules = db.query(Schedule).all()
        targets = [{
            "id": s.id, "name": s.name or "", "target": s.target_raw,
            "cron": s.cron_expr, "enabled": bool(s.enabled),
            "last_run": s.last_run_at.isoformat() + "Z" if s.last_run_at else None,
            "next_run": s.next_run_at.isoformat() + "Z" if s.next_run_at else None,
        } for s in schedules]

        # 2. 扫描趋势（最近 20 次扫描的主机/端口/网站数）
        recent_scans = db.query(Scan).filter(Scan.status == "done").order_by(
            Scan.started_at.desc()
        ).limit(20).all()
        scan_trend = [{
            "scan_id": s.scan_id, "name": s.name or "",
            "started_at": s.started_at.isoformat() + "Z" if s.started_at else "",
            "host_count": s.host_count, "port_count": s.port_count,
            "web_count": s.web_count,
        } for s in reversed(recent_scans)]

        # 3. 资产总量趋势（按扫描累计）
        total_assets = db.query(func.count(func.distinct(func.concat(Host.hostname, '|', Host.ip)))).filter(Host.ip != "").scalar() or 0
        total_ports = db.query(func.count(func.distinct(func.concat(Host.ip, '|', Port.port, '|', Port.proto)))).select_from(Port).join(Host).filter(Host.ip != "").scalar() or 0

        # 4. 最近告警事件
        recent_alerts = db.query(AlertEvent).order_by(AlertEvent.triggered_at.desc()).limit(10).all()
        alerts = [{
            "id": a.id, "summary": a.summary,
            "triggered_at": a.triggered_at.isoformat() + "Z" if a.triggered_at else "",
        } for a in recent_alerts]

        # 5. 标签统计
        tag_rows = db.query(AssetTag).all()
        tag_stats: dict[str, int] = {}
        for t in tag_rows:
            tags = json.loads(t.tags) if t.tags else []
            for tag in tags:
                tag_stats[tag] = tag_stats.get(tag, 0) + 1

        # 6. 监控状态
        monitor_status = {
            "ct_monitor": True,      # CT 监控已内置到调度器
            "dns_monitor": True,     # DNS 变更监控已内置
            "cruise_mode": True,     # 巡航模式（定时扫描+diff告警）
            "schedule_count": len(schedules),
            "alert_rule_count": 0,   # 从 alert 表查
        }

        return {
            "targets": targets,
            "scan_trend": scan_trend,
            "total_assets": total_assets,
            "total_ports": total_ports,
            "recent_alerts": alerts,
            "tag_stats": tag_stats,
            "monitor_status": monitor_status,
        }
    finally:
        db.close()
