from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.orm import relationship

from ..db import Base


class Scan(Base):
    __tablename__ = "scans"

    scan_id = Column(String(32), primary_key=True)
    name = Column(String(255), default="")
    target_raw = Column(Text, nullable=False)
    base_domain = Column(String(255), default="")
    status = Column(String(16), default="running")  # running / done / error
    options_json = Column(Text, default="{}")
    host_count = Column(Integer, default=0)
    port_count = Column(Integer, default=0)
    web_count = Column(Integer, default=0)
    sensitive_count = Column(Integer, default=0)
    error_msg = Column(Text, default="")
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    duration_secs = Column(Integer, nullable=True)

    hosts = relationship("Host", backref="scan", cascade="all, delete-orphan")
