"""设置 API — GET/PUT /api/settings."""

import json
import os

from fastapi import APIRouter
from pydantic import BaseModel

from ..config import DATA_DIR

router = APIRouter(tags=["settings"])

_SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

_DEFAULTS = {
    "layout": "sidebar",  # sidebar | topnav
    "theme": "light",  # light | dark
    "api_keys": {
        "shodan": "",
        "fofa_email": "",
        "fofa_key": "",
        "hunter_key": "",
        "censys_id": "",
        "censys_secret": "",
    },
}


def _load() -> dict:
    if os.path.isfile(_SETTINGS_FILE):
        with open(_SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        # 补齐缺失的默认字段
        for k, v in _DEFAULTS.items():
            if k not in data:
                data[k] = v
        return data
    return dict(_DEFAULTS)


def _save(data: dict):
    with open(_SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


class SettingsUpdate(BaseModel):
    layout: str | None = None
    theme: str | None = None
    api_keys: dict | None = None


@router.get("/settings")
def get_settings():
    """获取系统设置。"""
    return _load()


@router.put("/settings")
def update_settings(body: SettingsUpdate):
    """更新系统设置。"""
    data = _load()
    updates = body.model_dump(exclude_unset=True)
    data.update(updates)
    _save(data)
    return data
