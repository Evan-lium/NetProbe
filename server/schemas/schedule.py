from typing import Any

from pydantic import BaseModel, Field


class ScheduleCreate(BaseModel):
    """创建定时任务请求。options 为扫描配置（同 ScanRequest 的相关字段）。"""
    name: str = Field(default="", max_length=255, description="任务名称")
    target: str = Field(..., min_length=1, max_length=500, description="扫描目标")
    cron_expr: str = Field(..., description="标准 5 段 cron 表达式，如 '0 2 * * *'")
    options: dict[str, Any] = Field(default_factory=dict, description="扫描配置（同 ScanRequest 字段）")
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    """更新定时任务请求。所有字段可选。"""
    name: str | None = Field(default=None, max_length=255)
    target: str | None = Field(default=None, min_length=1, max_length=500)
    cron_expr: str | None = None
    options: dict[str, Any] | None = None


class ScheduleToggle(BaseModel):
    enabled: bool
