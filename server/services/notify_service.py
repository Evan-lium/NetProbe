"""通知服务 — Webhook 推送告警消息。

读取 data/settings.json 的 notifications.webhook 配置，向用户配置的 Webhook
端点 POST JSON 告警消息。所有发送均容错（网络失败不阻塞扫描流程）。
"""

import json
import logging
import os

import requests

from ..config import DATA_DIR

logger = logging.getLogger(__name__)

_SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
REQUEST_TIMEOUT = 10


def _load_notifications_config() -> dict:
    """从 settings.json 读取 notifications 配置。"""
    if not os.path.isfile(_SETTINGS_FILE):
        return {}
    try:
        with open(_SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("notifications") or {}
    except (json.JSONDecodeError, OSError):
        return {}


def send_webhook(url: str, payload: dict, headers: dict | None = None) -> dict:
    """向指定 Webhook URL 发送 JSON POST 请求。

    返回 {success: bool, error: str}
    """
    if not url:
        return {"success": False, "error": "webhook url 未配置"}
    try:
        resp = requests.post(
            url, json=payload,
            headers={"Content-Type": "application/json", **(headers or {})},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code < 400:
            return {"success": True, "error": ""}
        return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except requests.RequestException as e:
        return {"success": False, "error": str(e)[:200]}


def send_notification(title: str, message: str, details: dict | None = None) -> dict:
    """统一通知入口：读 settings.json 配置，向 Webhook 推送告警。

    返回 {success, channel, error}
    """
    config = _load_notifications_config()
    webhook = config.get("webhook") or {}
    url = (webhook.get("url") or "").strip()
    if not url:
        return {"success": False, "channel": "webhook", "error": "webhook 未配置"}

    payload = {
        "title": title,
        "message": message,
        "source": "NetProbe",
        "details": details or {},
    }
    result = send_webhook(url, payload, webhook.get("headers"))
    return {"success": result["success"], "channel": "webhook", "error": result["error"]}
