from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class AssetSummary(BaseModel):
    ip: str
    hostname: str
    first_seen: datetime
    last_seen: datetime
    scan_count: int
    port_count: int
    web_count: int


class AssetList(BaseModel):
    items: list[AssetSummary]
    total: int
