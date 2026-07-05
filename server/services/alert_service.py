"""告警服务 — 规则 CRUD + 扫描完成后自动检查。

check_after_scan(task_id) 在 scan_service 写库成功后调用:
1. 查该 task 对应的 Scan 拿 base_domain
2. 找同 base_domain 的上一次 done 扫描
3. compute_diff(上次, 本次) 拿变更摘要 + 完整 diff（用于通知明细）
4. 逐条 enabled 规则匹配，命中则构造 (summary, details) 调 send_notification
   details.type 决定通知文案模板（new_subdomain/new_port/new_vuln/scan_done）
"""

import json
import logging
from datetime import datetime

from ..db import SessionLocal
from ..models import Scan, Alert, AlertEvent
from ..utils import to_iso_z
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
            "triggered_at": to_iso_z(e.triggered_at) or "",
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
        diff_full = None
        if prev_scan:
            try:
                from .diff_service import compute_diff
                diff_full = compute_diff(prev_scan.scan_id, task_id)
                diff_summary = diff_full.get("summary", {})
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
                hit = _match_rule(alert, diff_summary, diff_full, current)
            except Exception as e:
                logger.warning("alert rule %s match failed: %s", alert.id, e)
                continue
            if hit:
                summary, details = hit
                _trigger_alert(db, alert, task_id, summary, details)

    except Exception as e:
        logger.exception("check_after_scan failed: %s", e)
    finally:
        db.close()


def _match_rule(alert: Alert, diff_summary: dict | None,
                diff_full: dict | None, current: dict) -> tuple[str, dict] | None:
    """匹配单条规则，命中返回 (摘要文本, details)，未命中返回 None。

    details.type 决定通知文案模板（new_subdomain/new_port/new_vuln/scan_done），
    详见 notify_service._render_message。details 同时携带 items 列表供展示。
    """

    if alert.condition_type == "new_port":
        if diff_summary and diff_summary.get("ports_added", 0) > 0:
            # 从完整 diff 汇总新增端口（格式 "ip:port" 或 "port/proto"）
            items = []
            if diff_full:
                for h in diff_full.get("hosts", []):
                    for p in h.get("ports", {}).get("added", []):
                        port = p.get("port", "")
                        host = h.get("hostname") or h.get("ip") or ""
                        items.append(f"{host}:{port}" if host else str(port))
            count = diff_summary.get("ports_added", len(items))
            summary = f"发现 {count} 个新增开放端口"
            return summary, {"type": "new_port", "count": count, "items": items}

    elif alert.condition_type == "new_subdomain":
        if diff_summary and diff_summary.get("hosts_added", 0) > 0:
            # 从完整 diff 取新增主机 hostname 列表
            items = []
            if diff_full:
                for h in diff_full.get("hosts", []):
                    if h.get("status") == "added":
                        hn = h.get("hostname") or h.get("ip") or ""
                        if hn:
                            items.append(hn)
            count = diff_summary.get("hosts_added", len(items))
            summary = f"发现 {count} 个新增主机/子域名"
            return summary, {"type": "new_subdomain", "count": count, "items": items}

    elif alert.condition_type == "high_risk_path":
        # 检查本次扫描是否有 high/critical 敏感路径（绝对条件，不依赖 diff）
        count = 0
        for h in current.get("hosts", []):
            for s in h.get("sensitive", []):
                if (s.get("severity") or "").lower() in ("high", "critical"):
                    count += 1
        if count > 0:
            summary = f"发现 {count} 条高危敏感路径"
            return summary, {"type": "new_vuln", "count": count, "items": []}

    elif alert.condition_type == "new_vuln":
        # 检查本次扫描的 critical/high 漏洞（nuclei）
        items = []
        for h in current.get("hosts", []):
            for v in h.get("vulnerabilities", []):
                sev = (v.get("severity") or "").lower()
                if sev in ("critical", "high"):
                    items.append({
                        "name": v.get("name") or v.get("template_id") or "",
                        "severity": sev,
                        "url": v.get("url") or v.get("matched_at") or "",
                    })
        if items:
            summary = f"发现 {len(items)} 条高危漏洞"
            return summary, {"type": "new_vuln", "count": len(items), "items": items}

    elif alert.condition_type == "cert_expiry":
        # 检查 SSL 证书过期或即将过期（threshold 天数内）
        days = int(alert.threshold) if alert.threshold.isdigit() else 30
        expired_count = 0
        expiring_count = 0
        for h in current.get("hosts", []):
            for w in h.get("web_info", []):
                ssl_info = w.get("ssl")
                if not ssl_info:
                    continue
                if ssl_info.get("expired"):
                    expired_count += 1
                else:
                    # 检查即将过期（not_after 距今 < threshold 天）
                    not_after = ssl_info.get("not_after", "")
                    if not_after:
                        remaining = _days_until(not_after)
                        if remaining is not None and 0 <= remaining <= days:
                            expiring_count += 1
        total = expired_count + expiring_count
        if total > 0:
            parts = []
            if expired_count:
                parts.append(f"{expired_count} 个已过期")
            if expiring_count:
                parts.append(f"{expiring_count} 个 {days} 天内过期")
            summary = f"SSL 证书问题: {'、'.join(parts)}"
            return summary, {
                "type": "scan_done",
                "stats": {"已过期": expired_count, f"{days}天内过期": expiring_count},
            }

    elif alert.condition_type == "tech_change":
        if diff_summary and diff_summary.get("tech_changed", 0) > 0:
            summary = f"发现 {diff_summary['tech_changed']} 处技术栈变化"
            return summary, {
                "type": "scan_done",
                "stats": {"技术栈变化": diff_summary["tech_changed"]},
            }

    elif alert.condition_type == "domain_expiry":
        # 域名到期检查（绝对条件，不依赖 diff；从 whois_records 表解析 expiration_date）
        days = int(alert.threshold) if alert.threshold.isdigit() else 30
        try:
            from .domain_monitor import check_domain_expiry
            domains = check_domain_expiry()
        except Exception as e:
            logger.warning("domain_expiry check failed: %s", e)
            domains = []
        # 只关心即将过期 / 已过期（阈值用规则 threshold 覆盖默认 30 天）
        urgent = [d for d in domains
                  if d["status"] == "expired" or d["days_remaining"] < days]
        if urgent:
            expired = [d for d in urgent if d["status"] == "expired"]
            expiring = [d for d in urgent if d["status"] != "expired"]
            parts = []
            if expired:
                parts.append(f"{len(expired)} 个已过期")
            if expiring:
                parts.append(f"{len(expiring)} 个 {days} 天内到期")
            summary = f"域名到期预警: {'、'.join(parts)}"
            items = [
                {"severity": "critical" if d["status"] == "expired" else "high",
                 "name": f"{d['domain']} (剩余 {d['days_remaining']} 天)"}
                for d in urgent[:5]
            ]
            return summary, {
                "type": "new_vuln",
                "count": len(urgent),
                "items": items,
            }

    return None


def _trigger_alert(db, alert: Alert, scan_id: str, summary: str, details: dict):
    """触发告警：发送通知 + 写历史 + 更新最后触发时间。

    details 携带事件类型与明细，notify_service 据此选择差异化文案模板。
    """
    payload = {
        "alert_id": alert.id,
        "scan_id": scan_id,
        "rule": alert.condition_type,
        **details,
    }
    result = send_notification(
        title=f"NetProbe 告警: {alert.name}",
        message=summary,
        details=payload,
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


def _days_until(date_str: str) -> int | None:
    """解析证书日期，返回距今天数。失败返回 None。"""
    from datetime import datetime
    for fmt in ('%b %d %H:%M:%S %Y %Z', '%Y-%m-%dT%H:%M:%S'):
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
            return (dt - datetime.utcnow()).days
        except ValueError:
            continue
    return None


def _serialize_alert(a: Alert) -> dict:
    return {
        "id": a.id,
        "name": a.name,
        "condition_type": a.condition_type,
        "target": a.target or "",
        "threshold": a.threshold or "",
        "enabled": bool(a.enabled),
        "created_at": to_iso_z(a.created_at) or "",
        "last_triggered_at": to_iso_z(a.last_triggered_at),
    }
