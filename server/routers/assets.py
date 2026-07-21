"""资产 API — GET /api/assets."""

from fastapi import APIRouter, Query

from ..services.asset_service import list_assets

router = APIRouter(tags=["assets"])


@router.get("/assets", summary="资产清单", description="跨扫描资产聚合，按 hostname+ip 去重，返回站点预览/端口/漏洞数/最后扫描时间")
def assets_list(q: str = "", sort: str = Query("last_seen")):
    """跨扫描资产汇总。"""
    return list_assets(q, sort)
