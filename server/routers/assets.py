"""资产 API — GET /api/assets."""

from fastapi import APIRouter, Query

from ..services.asset_service import list_assets

router = APIRouter(tags=["assets"])


@router.get("/assets")
def assets_list(q: str = "", sort: str = Query("last_seen")):
    """跨扫描资产汇总。"""
    return list_assets(q, sort)
