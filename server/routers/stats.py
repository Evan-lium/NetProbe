"""统计 API — 仪表盘全局概览 + 指纹库统计。"""

import json
from pathlib import Path
from collections import Counter

from fastapi import APIRouter, HTTPException

from ..services.stats_service import get_overview_stats, get_asset_detail

router = APIRouter(tags=["stats"])

_FP_PATH = Path(__file__).parent.parent.parent / "netprobe" / "data" / "fingerprints.json"
_SP_PATH = Path(__file__).parent.parent.parent / "netprobe" / "data" / "sensitive_paths.json"
_TAKEOVER_PATH = Path(__file__).parent.parent.parent / "netprobe" / "data" / "takeover_fingerprints.json"


@router.get("/stats")
def get_stats():
    """返回仪表盘全局概览统计。"""
    return get_overview_stats()


@router.get("/stats/asset")
def get_asset_stats(hostname: str, ip: str):
    """返回单个资产的完整详情（资产清单展开行）。"""
    result = get_asset_detail(hostname, ip)
    if result is None:
        raise HTTPException(404, "asset not found")
    return result


@router.get("/stats/fingerprints")
def get_fingerprint_stats():
    """返回系统指纹库统计（各分类规则数 + 总数 + 版本提取数）。"""
    result = {"fingerprints": {}, "total": 0, "with_version": 0}

    # Web 指纹
    try:
        fps = json.load(open(_FP_PATH, encoding="utf-8"))
        cats = Counter(fp.get("category", "Other") for fp in fps)
        with_ver = sum(1 for fp in fps for p in fp.get("patterns", []) if "version" in p)
        result["fingerprints"] = {
            "total": len(fps),
            "with_version": with_ver,
            "categories": dict(cats.most_common()),
        }
    except (OSError, json.JSONDecodeError):
        result["fingerprints"] = {"total": 0, "with_version": 0, "categories": {}}

    # 敏感路径
    try:
        sps = json.load(open(_SP_PATH, encoding="utf-8"))
        sp_cats = Counter(sp.get("severity", "info") for sp in sps)
        result["sensitive_paths"] = {
            "total": len(sps),
            "categories": dict(sp_cats.most_common()),
        }
    except (OSError, json.JSONDecodeError):
        result["sensitive_paths"] = {"total": 0, "categories": {}}

    # 子域接管指纹
    try:
        tks = json.load(open(_TAKEOVER_PATH, encoding="utf-8"))
        result["takeover"] = {"total": len(tks) if isinstance(tks, list) else len(tks.keys())}
    except (OSError, json.JSONDecodeError):
        result["takeover"] = {"total": 0}

    # 端口数
    try:
        from netprobe.scanner import COMMON_PORTS
        result["ports"] = {"common": len(set(COMMON_PORTS))}
    except Exception:
        result["ports"] = {"common": 0}

    return result
