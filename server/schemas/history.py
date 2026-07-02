from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class HistoryItem(BaseModel):
    scan_id: str
    target_raw: str
    base_domain: str
    status: str
    host_count: int
    port_count: int
    web_count: int
    sensitive_count: int
    error_msg: str
    started_at: datetime
    finished_at: Optional[datetime]
    duration_secs: Optional[int]

    class Config:
        from_attributes = True


class HistoryList(BaseModel):
    items: list[HistoryItem]
    total: int
    page: int
    per_page: int
