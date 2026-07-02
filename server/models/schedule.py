from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from ..db import Base


class Schedule(Base):
    """定时扫描任务规则。"""

    __tablename__ = "schedules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), default="")
    target_raw = Column(Text, nullable=False)
    options_json = Column(Text, default="{}")  # 复用 ScanRequest 的纯配置（剥离下划线字段）
    cron_expr = Column(String(64), nullable=False)  # 标准 5 段 cron，如 "0 2 * * *"
    enabled = Column(Boolean, default=True)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
