from pydantic import BaseModel, Field


class AlertCreate(BaseModel):
    name: str = Field(..., max_length=255, description="告警规则名称")
    condition_type: str = Field(..., description="条件类型: new_port/new_subdomain/high_risk_path/cert_expiry/tech_change")
    target: str = Field(default="", description="匹配目标(base_domain)，空=全部")
    threshold: str = Field(default="", description="条件阈值，如 cert_expiry 天数")
    enabled: bool = True
