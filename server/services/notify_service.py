"""通知服务 — 多渠道告警消息推送。

支持的渠道（按 settings.json 的 notifications 配置启用）:
- webhook:    通用 Webhook（POST JSON）
- dingtalk:   钉钉群机器人
- wecom:      企业微信群机器人
- feishu:     飞书群机器人
- telegram:   Telegram Bot
- email:      邮件（SMTP）

所有发送均容错（网络失败不阻塞扫描流程），返回 {success, channel, error}。
send_notification() 是统一入口，遍历所有已配置的渠道并行发送。
"""

import json
import logging
import os
from smtplib import SMTP, SMTP_SSL
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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


# ── 各渠道发送函数 ──────────────────────────────────────────

def send_webhook(url: str, payload: dict, headers: dict | None = None) -> dict:
    """通用 Webhook：POST JSON。"""
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


def send_dingtalk(access_token: str, secret: str, title: str, message: str) -> dict:
    """钉钉群机器人。

    钉钉安全设置: 关键词(消息含"NetProbe") 或 加签(secret)。
    文档: https://open.dingtalk.com/document/robots/custom-robot-access
    """
    if not access_token:
        return {"success": False, "error": "钉钉 access_token 未配置"}
    import time
    import hashlib
    import hmac
    import base64
    import urllib.parse

    url = f"https://oapi.dingtalk.com/robot/send?access_token={access_token}"
    headers = {"Content-Type": "application/json"}
    # 加签模式
    if secret:
        timestamp = str(round(time.time() * 1000))
        string_to_sign = f"{timestamp}\n{secret}"
        hmac_code = hmac.new(
            secret.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        url += f"&timestamp={timestamp}&sign={sign}"

    # 钉钉 markdown 消息（标题含"NetProbe"通过关键词校验）
    payload = {
        "msgtype": "markdown",
        "markdown": {
            "title": f"NetProbe: {title}",
            "text": f"### NetProbe 告警\n\n**{title}**\n\n{message}",
        },
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
        data = resp.json()
        if data.get("errcode") == 0:
            return {"success": True, "error": ""}
        return {"success": False, "error": f"钉钉返回: {data}"}
    except (requests.RequestException, json.JSONDecodeError) as e:
        return {"success": False, "error": str(e)[:200]}


def send_wecom(key: str, title: str, message: str) -> dict:
    """企业微信群机器人。

    文档: https://developer.work.weixin.qq.com/document/path/91770
    """
    if not key:
        return {"success": False, "error": "企业微信 key 未配置"}
    url = f"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={key}"
    payload = {
        "msgtype": "markdown",
        "markdown": {"content": f"## NetProbe 告警\n**{title}**\n{message}"},
    }
    try:
        resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        data = resp.json()
        if data.get("errcode") == 0:
            return {"success": True, "error": ""}
        return {"success": False, "error": f"企微返回: {data}"}
    except (requests.RequestException, json.JSONDecodeError) as e:
        return {"success": False, "error": str(e)[:200]}


def send_feishu(webhook_url: str, secret: str, title: str, message: str) -> dict:
    """飞书群机器人。

    文档: https://open.feishu.cn/document/ukTMukTMukTM/ucTM5YjL3ETO24yNxkjN
    webhook_url 为完整地址（含 token），secret 为可选的签名校验。
    """
    if not webhook_url:
        return {"success": False, "error": "飞书 webhook 未配置"}
    import time
    import hashlib
    import hmac
    import base64

    payload = {
        "msg_type": "text",
        "content": {"text": f"【NetProbe 告警】{title}\n{message}"},
    }
    # 签名校验
    if secret:
        timestamp = int(time.time())
        string_to_sign = f"{timestamp}\n{secret}"
        hmac_code = hmac.new(
            string_to_sign.encode("utf-8"), digestmod=hashlib.sha256
        ).digest()
        sign = base64.b64encode(hmac_code).decode("utf-8")
        payload["timestamp"] = str(timestamp)
        payload["sign"] = sign
    try:
        resp = requests.post(webhook_url, json=payload, timeout=REQUEST_TIMEOUT)
        data = resp.json()
        if data.get("code") == 0 or data.get("StatusCode") == 0:
            return {"success": True, "error": ""}
        return {"success": False, "error": f"飞书返回: {data}"}
    except (requests.RequestException, json.JSONDecodeError) as e:
        return {"success": False, "error": str(e)[:200]}


def send_telegram(bot_token: str, chat_id: str, message: str) -> dict:
    """Telegram Bot。

    文档: https://core.telegram.org/bots/api#sendmessage
    """
    if not bot_token or not chat_id:
        return {"success": False, "error": "Telegram bot_token 或 chat_id 未配置"}
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": f"🚨 *NetProbe 告警*\n\n{message}",
        "parse_mode": "Markdown",
    }
    try:
        resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        data = resp.json()
        if data.get("ok"):
            return {"success": True, "error": ""}
        return {"success": False, "error": f"Telegram 返回: {data.get('description', data)}"}
    except (requests.RequestException, json.JSONDecodeError) as e:
        return {"success": False, "error": str(e)[:200]}


def send_email(smtp_host: str, smtp_port: int, username: str, password: str,
               from_addr: str, to_addrs: list[str], subject: str, body: str,
               use_ssl: bool = True) -> dict:
    """邮件通知（SMTP）。

    支持_SSL（465）和 STARTTLS（587）。
    """
    if not smtp_host or not to_addrs:
        return {"success": False, "error": "SMTP 主机或收件人未配置"}
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[NetProbe] {subject}"
        msg["From"] = from_addr or username
        msg["To"] = ", ".join(to_addrs)
        # 纯文本 + HTML 双份
        msg.attach(MIMEText(body, "plain", "utf-8"))
        html = f"<html><body><h3>NetProbe 告警</h3><p><b>{subject}</b></p><pre>{body}</pre></body></html>"
        msg.attach(MIMEText(html, "html", "utf-8"))

        smtp_cls = SMTP_SSL if use_ssl else SMTP
        with smtp_cls(smtp_host, smtp_port, timeout=REQUEST_TIMEOUT) as server:
            if username and password:
                server.login(username, password)
            server.sendmail(from_addr or username, to_addrs, msg.as_string())
        return {"success": True, "error": ""}
    except Exception as e:
        return {"success": False, "error": str(e)[:200]}


# ── 统一入口 ──────────────────────────────────────────────

def _render_message(title: str, message: str, details: dict | None) -> str:
    """根据 details.type 选择差异化文案模板，未匹配则回退原始 message。

    支持 4 种事件类型:
    - new_subdomain: 列出新增的子域名（最多 5 个）
    - new_port:      列出新开放端口
    - new_vuln:      列出 critical/high 漏洞（最多 5 个）
    - scan_done:     扫描完成汇总统计
    """
    if not details or not details.get("type"):
        return message

    dtype = details["type"]

    if dtype == "new_subdomain":
        items = details.get("items") or []
        if items:
            lines = [f"• {x}" for x in items[:5]]
            more = f"\n（共 {details.get('count', len(items))} 个，仅展示前 5 个）" if details.get("count", 0) > 5 else ""
            body = "\n".join(lines) + more
            return f"发现 {details.get('count', len(items))} 个新增子域名:\n{body}"
        return message

    if dtype == "new_port":
        items = details.get("items") or []
        if items:
            return f"发现 {details.get('count', len(items))} 个新增开放端口:\n• " + "\n• ".join(items[:20])
        return message

    if dtype == "new_vuln":
        items = details.get("items") or []
        if items:
            lines = [f"• [{v.get('severity', '?').upper()}] {v.get('name', '')}" for v in items[:5]]
            more = f"\n（共 {details.get('count', len(items))} 条，仅展示前 5 条）" if details.get("count", 0) > 5 else ""
            body = "\n".join(lines) + more
            return f"发现 {details.get('count', len(items))} 条高危漏洞:\n{body}"
        return message

    if dtype == "scan_done":
        stats = details.get("stats") or {}
        lines = [f"• {k}: {v}" for k, v in stats.items()]
        return f"扫描完成统计:\n" + "\n".join(lines) if lines else message

    return message


def send_notification(title: str, message: str, details: dict | None = None) -> dict:
    """统一通知入口：遍历所有已配置的渠道发送告警。

    details.type 不为空时，用 _render_message 生成 4 类事件差异化文案；
    否则直接用 message。返回 {success, channel, error}（任一渠道成功即 success=True）。
    """
    config = _load_notifications_config()
    results = []

    # 差异化文案渲染（按事件类型选择模板，未匹配回退原始 message）
    rendered = _render_message(title, message, details)

    # 构造通用 payload（供 webhook 使用）
    base_payload = {
        "title": title,
        "message": rendered,
        "source": "NetProbe",
        "details": details or {},
    }

    # 1. Webhook
    wh = config.get("webhook") or {}
    wh_url = (wh.get("url") or "").strip()
    if wh_url:
        r = send_webhook(wh_url, base_payload, wh.get("headers"))
        r["channel"] = "webhook"
        results.append(r)

    # 2. 钉钉
    dt = config.get("dingtalk") or {}
    if (dt.get("access_token") or "").strip():
        r = send_dingtalk(dt["access_token"].strip(), dt.get("secret", ""), title, rendered)
        r["channel"] = "dingtalk"
        results.append(r)

    # 3. 企业微信
    wc = config.get("wecom") or {}
    if (wc.get("key") or "").strip():
        r = send_wecom(wc["key"].strip(), title, rendered)
        r["channel"] = "wecom"
        results.append(r)

    # 4. 飞书
    fs = config.get("feishu") or {}
    if (fs.get("webhook") or "").strip():
        r = send_feishu(fs["webhook"].strip(), fs.get("secret", ""), title, rendered)
        r["channel"] = "feishu"
        results.append(r)

    # 5. Telegram
    tg = config.get("telegram") or {}
    if (tg.get("bot_token") or "").strip() and (tg.get("chat_id") or "").strip():
        r = send_telegram(tg["bot_token"].strip(), tg["chat_id"].strip(), rendered)
        r["channel"] = "telegram"
        results.append(r)

    # 6. 邮件
    em = config.get("email") or {}
    if (em.get("smtp_host") or "").strip() and em.get("to_addrs"):
        r = send_email(
            em["smtp_host"].strip(),
            int(em.get("smtp_port", 465)),
            em.get("username", ""),
            em.get("password", ""),
            em.get("from_addr", ""),
            em["to_addrs"] if isinstance(em["to_addrs"], list) else [em["to_addrs"]],
            title,
            rendered,
            use_ssl=em.get("use_ssl", True),
        )
        r["channel"] = "email"
        results.append(r)

    # 汇总：任一成功即 success
    if not results:
        return {"success": False, "channel": "none", "error": "无已配置的通知渠道"}
    success_any = any(r["success"] for r in results)
    # 返回第一个失败的原因（如有），便于排查
    first_err = next((r["error"] for r in results if not r["success"]), "")
    channels = ", ".join(r["channel"] for r in results)
    return {
        "success": success_any,
        "channel": channels,
        "error": first_err,
        "details": results,
    }
