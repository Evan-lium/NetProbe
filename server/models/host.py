from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from ..db import Base


class Host(Base):
    __tablename__ = "hosts"

    host_id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(32), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    target = Column(String(255), default="")
    hostname = Column(String(255), default="", index=True)
    ip = Column(String(64), default="", index=True)
    os_info = Column(Text, default="")
    sort_order = Column(Integer, default=0)
    risk_score = Column(Integer, default=0)
    risk_factors_json = Column(Text, default="{}")

    ports = relationship("Port", backref="host", cascade="all, delete-orphan")
    banners = relationship("Banner", backref="host", cascade="all, delete-orphan")
    web_info_list = relationship("WebInfo", backref="host", cascade="all, delete-orphan")
    sensitive_paths = relationship("SensitivePath", backref="host", cascade="all, delete-orphan")
    js_findings = relationship("JSFinding", backref="host", cascade="all, delete-orphan")


class Port(Base):
    __tablename__ = "ports"

    port_id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("hosts.host_id", ondelete="CASCADE"), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    proto = Column(String(8), default="tcp")
    state = Column(String(16), default="open")
    service = Column(String(64), default="")
    product = Column(String(128), default="")
    version = Column(String(64), default="")
    cpe = Column(String(255), default="")


class Banner(Base):
    __tablename__ = "banners"

    banner_id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("hosts.host_id", ondelete="CASCADE"), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    service = Column(String(64), default="")
    banner = Column(Text, default="")
