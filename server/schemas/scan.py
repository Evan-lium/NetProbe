from typing import Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=500, description="扫描目标（域名/IP/CIDR，多个用换行分隔）")
    name: str = Field(default="", max_length=255, description="任务名称")
    no_dns_brute: bool = False
    no_web: bool = False
    no_validate: bool = False
    timeout: int = Field(default=300, ge=30, le=3600)
    subdomain_tool: str = "auto"
    portscan_tool: str = "auto"
    web_tool: str = "auto"
    dns_tool: str = "auto"
    port_preset: str = Field(default="common", description="端口预设: common / top1000 / all / custom")
    custom_ports: str = Field(default="", description="自定义端口（port_preset=custom 时使用）")


class ScanResponse(BaseModel):
    task_id: str
    status: str = "running"


class ScanResult(BaseModel):
    task_id: str
    status: str
    base_domain: str = ""
    hosts: list[dict] = []
