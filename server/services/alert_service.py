"""告警服务 — 规则 CRUD + 扫描完成后自动检查。

check_after_scan(task_id) 在 scan_service 写库成功后调用:
1. 查该 task 对应的 Scan 拿 base_domain
2. 找同 base_domain 的上一次 done 扫描
3. compute_diff(上次, 本次) 拿变更摘要
4. 逐条 enabled 规则匹配，命中则 send_notification + 写 alert_events
"""

import json
import logging
from datetime import datetime

from ..db import SessionLocal
from ..models import Scan, Alert, AlertEvent
from .notify_service import send_notification

logger = logging.getLogger(__name__)


def list_alerts() -> list[dict]:
    """列出全部告警规则。"""
    db = SessionLocal()
    try:
        rows = db.query(Alert).order_by(Alert.id.desc()).all()
        return [_serialize_alert(a) for a in rows]
    finally:
        db.close()


def create_alert(name: str, condition_type: str, target: str = "",
                 threshold: str = "", enabled: bool = True) -> dict:
    """创建告警规则。"""
    db = SessionLocal()
    try:
        alert = Alert(
            name=name, condition_type=condition_type,
            target=target, threshold=threshold, enabled=enabled,
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return _serialize_alert(alert)
    finally:
        db.close()


def delete_alert(alert_id: int) -> bool:
    """删除告警规则（级联删除触发历史）。"""
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return False
        db.delete(alert)
        db.commit()
        return True
    finally:
        db.close()


def list_events(limit: int = 50) -> list[dict]:
    """列出告警触发历史。"""
    db = SessionLocal()
    try:
        rows = db.query(AlertEvent).order_by(AlertEvent.triggered_at.desc()).limit(limit).all()
        return [{
            "id": e.id,
            "alert_id": e.alert_id,
            "scan_id": e.scan_id,
            "triggered_at": e.triggered_at.isoformat() if e.triggered_at else "",
            "summary": e.summary,
            "channels": json.loads(e.channels_json) if e.channels_json else [],
        } for e in rows]
    finally:
        db.close()


def check_after_scan(task_id: str):
    """扫描完成后检查告警规则（由 scan_service 调用）。

    找同目标上次扫描做 diff，逐条规则匹配，命中则通知 + 记录。
    """
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.scan_id == task_id).first()
        if not scan or scan.status != "done":
            return

        alerts = db.query(Alert).filter(Alert.enabled == True).all()  # noqa: E712
        if not alerts:
            return

        base_domain = scan.base_domain or scan.target_raw or ""

        # 找上一次同目标 done 扫描
        prev_scan = (
            db.query(Scan)
            .filter(
                Scan.status == "done",
                Scan.scan_id != task_id,
                Scan.base_domain.contains(base_domain) if base_domain else True,
            )
            .order_by(Scan.started_at.desc())
            .first()
        )

        # 无历史扫描时，仅检查 cert_expiry / high_risk_path 这类「绝对条件」
        diff_summary = None
        if prev_scan:
            try:
                from .diff_service import compute_diff
                diff = compute_diff(prev_scan.scan_id, task_id)
                diff_summary = diff.get("summary", {})
            except Exception as e:
                logger.warning("alert diff failed: %s", e)

        # 取本次扫描数据用于绝对条件检查
        from ..routers.result import get_result
        try:
            current = get_result(task_id)
        except Exception:
            current = {"hosts": []}

        for alert in alerts:
            # 目标过滤
            if alert.target and base_domain and alert.target not in base_domain:
                continue
            try:
                hit = _match_rule(alert, diff_summary, current)
            except Exception as e:
                logger.warning("alert rule %s match failed: %s", alert.id, e)
                continue
            if hit:
                _trigger_alert(db, alert, task_id, hit)

    except Exception as e:
        logger.exception("check_after_scan failed: %s", e)
    finally:
        db.close()


def _match_rule(alert: Alert, diff_summary: dict | None, current: dict) -> str | None:
    """匹配单条规则，命中返回摘要文本，未命中返回 None。"""

    if alert.condition_type == "new_port":
        if diff_summary and diff_summary.get("ports_added", 0) > 0:
            return f"发现 {diff_summary['ports_added']} 个新增开放端口"

    elif alert.condition_type == "new_subdomain":
        if diff_summary and diff_summary.get("hosts_added", 0) > 0:
            return f"发现 {diff_summary['hosts_added']} 个新增主机/子域名"

    elif alert.condition_type == "high_risk_path":
        # 检查本次扫描是否有 high/critical 敏感路径（绝对条件，不依赖 diff）
        count = 0
        for h in current.get("hosts", []):
            for s in h.get("sensitive", []):
                if (s.get("severity") or "").lower() in ("high", "critical"):
                    count += 1
        if count > 0:
            return f"发现 {count} 条高危敏感路径"

    elif alert.condition_type == "cert_expiry":
        # 检查 SSL 证书过期或即将过期
        days = int(alert.threshold) if alert.threshold.isdigit() else 30
        count = 0
        for h in current.get("hosts", []):
            for w in h.get("web_info", []):
                ssl = w.get("ssl")
                if not ssl:
                    continue
                if ssl.get("expired"):
                    count += 1
        if count > 0:
            return f"发现 {count} 个站点的 SSL 证书已过期"

    elif alert.condition_type == "tech_change":
        if diff_summary and diff_summary.get("tech_changed", 0) > 0:
            return f"发现 {diff_summary['tech_changed']} 处技术栈变化"

    return None


def _trigger_alert(db, alert: Alert, scan_id: str, summary: str):
    """触发告警：发送通知 + 写历史 + 更新最后触发时间。"""
    result = send_notification(
        title=f"NetProbe 告警: {alert.name}",
        message=summary,
        details={"alert_id": alert.id, "scan_id": scan_id, "rule": alert.condition_type},
    )

    event = AlertEvent(
        alert_id=alert.id,
        scan_id=scan_id,
        triggered_at=datetime.utcnow(),
        summary=summary,
        channels_json=json.dumps([result], ensure_ascii=False),
    )
    db.add(event)

    alert.last_triggered_at = datetime.utcnow()
    db.commit()
    logger.info("alert %d triggered: %s", alert.id, summary)


def _serialize_alert(a: Alert) -> dict:
    return {
        "id": a.id,
        "name": a.name,
        "condition_type": a.condition_type,
        "target": a.target or "",
        "threshold": a.threshold or "",
        "enabled": bool(a.enabled),
        "created_at": a.created_at.isoformat() if a.created_at else "",
        "last_triggered_at": a.last_triggered_at.isoformat() if a.last_triggered_at else None,
    }
