"""域名到期监控 — 解析 WHOIS/RDAP 记录，提醒即将过期的域名。

check_domain_expiry() 遍历 whois_records 表里所有 type='domain' 的记录，解析其中的
expiration_date（RDAP eventDate，ISO 8601 格式，兼容多种写法），按剩余天数判定状态:
  - days_remaining < 0     → 'expired'   已过期
  - days_remaining < 30    → 'expiring'  即将过期
  - else                   → 'ok'

返回 [{domain, expiry_date, days_remaining, status}]。

日期解析容错：兼容 ISO 8601（含/不含时区）、'YYYY-MM-DD'、'MMM DD YYYY' 等多种格式。
数据源是已有的 whois_records 表（扫描时由 netprobe.tools.whois 写入），不发起新查询。
"""

import json
import logging
import re
from datetime import datetime, timezone

from ..db import SessionLocal
from ..models import WhoisRecord

logger = logging.getLogger(__name__)

# 即将过期阈值（天）
EXPIRING_THRESHOLD_DAYS = 30


def check_domain_expiry() -> list[dict]:
    """检查所有域名的到期状态。

    从 whois_records 表取所有 type='domain' 记录，按 target 去重（保留最新一条），
    解析 expiration_date 计算剩余天数与状态。

    返回: [{domain, expiry_date, days_remaining, status}]
          解析失败的域名不返回（无法判定过期日的跳过）。
    """
    db = SessionLocal()
    try:
        rows = (
            db.query(WhoisRecord)
            .filter(WhoisRecord.type == "domain")
            .order_by(WhoisRecord.id.desc())
            .all()
        )
    finally:
        db.close()

    # 按 target 去重（同域名多次扫描会有多条记录，取最新一条——已按 id desc 排序）
    latest_by_domain: dict[str, WhoisRecord] = {}
    for row in rows:
        target = (row.target or "").strip().lower()
        if target and target not in latest_by_domain:
            latest_by_domain[target] = row

    results = []
    now = datetime.now(timezone.utc)
    for domain, row in latest_by_domain.items():
        try:
            data = json.loads(row.data_json) if row.data_json else {}
        except (json.JSONDecodeError, TypeError):
            continue
        expiry_raw = data.get("expiration_date") or ""
        if not expiry_raw:
            continue
        expiry_dt = _parse_date(expiry_raw)
        if not expiry_dt:
            continue
        # 统一为带时区的 UTC 进行比较
        if expiry_dt.tzinfo is None:
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
        delta = expiry_dt - now
        days_remaining = delta.days

        if days_remaining < 0:
            status = "expired"
        elif days_remaining < EXPIRING_THRESHOLD_DAYS:
            status = "expiring"
        else:
            status = "ok"

        results.append({
            "domain": domain,
            "expiry_date": expiry_raw,
            "days_remaining": days_remaining,
            "status": status,
        })

    # 按剩余天数升序（最紧急的在前）
    results.sort(key=lambda x: x["days_remaining"])
    return results


def _parse_date(date_str: str) -> datetime | None:
    """容错解析多种格式的日期字符串为 datetime。

    兼容:
      - ISO 8601: '2025-12-31T23:59:59Z' / '2025-12-31T23:59:59+00:00'
      - 纯日期:   '2025-12-31'
      - RDAP 旧式: '2025-12-31T23:59:59.000Z'
      - 英文月名:  'Dec 31, 2025' / '31-Dec-2025' / '2025/12/31'
    """
    if not date_str:
        return None
    s = date_str.strip()
    # 优先用 fromisoformat（Python 3.11+ 支持 'Z' 后缀，这里手动替换以兼容低版本）
    iso = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(iso)
    except ValueError:
        pass
    # 尝试一组常见格式
    formats = (
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%b %d, %Y",       # Dec 31, 2025
        "%d-%b-%Y",        # 31-Dec-2025
        "%d %b %Y",        # 31 Dec 2025
        "%Y-%m-%d %H:%M:%S",
    )
    for fmt in formats:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    # 兜底：用正则提取 YYYY-MM-DD 片段
    m = re.search(r"(\d{4})-(\d{1,2})-(\d{1,2})", s)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            pass
    return None
