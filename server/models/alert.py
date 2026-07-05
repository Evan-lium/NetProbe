from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text

from ..db import Base


class Alert(Base):
    """告警规则定义。"""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    # 条件类型: new_port / new_subdomain / new_vuln / high_risk_path /
    #           cert_expiry / domain_expiry / tech_change
    condition_type = Column(String(32), nullable=False)
    target = Column(String(255), default="")  # 匹配的扫描目标(base_domain)，空=全部
    threshold = Column(String(64), default="")  # 条件阈值，如 cert_expiry 的天数
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_triggered_at = Column(DateTime, nullable=True)


class AlertEvent(Base):
    """告警触发历史记录。"""

    __tablename__ = "alert_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(32), default="")
    triggered_at = Column(DateTime, default=datetime.utcnow)
    summary = Column(Text, default="")  # 触发摘要
    channels_json = Column(Text, default="[]")  # 推送结果 [{channel, success, error}]
