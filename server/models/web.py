from sqlalchemy import Column, ForeignKey, Integer, String, Text

from ..db import Base


class WebInfo(Base):
    __tablename__ = "web_info"

    web_id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("hosts.host_id", ondelete="CASCADE"), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    url = Column(Text, nullable=False)
    status_code = Column(Integer, nullable=True)
    title = Column(Text, default="")
    redirect = Column(Text, default="")
    headers_json = Column(Text, default="{}")
    tech_json = Column(Text, default="[]")
    ssl_json = Column(Text, default="null")


class SensitivePath(Base):
    __tablename__ = "sensitive_paths"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("hosts.host_id", ondelete="CASCADE"), nullable=False, index=True)
    path = Column(Text, nullable=False)
    description = Column(Text, default="")
    severity = Column(String(16), default="info")
    status_code = Column(Integer, nullable=True)


class JSFinding(Base):
    __tablename__ = "js_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("hosts.host_id", ondelete="CASCADE"), nullable=False, index=True)
    js_url = Column(Text, nullable=False)
    api_endpoints_json = Column(Text, default="[]")
    secrets_json = Column(Text, default="[]")
