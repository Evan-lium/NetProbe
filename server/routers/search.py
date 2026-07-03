"""反向搜索 API — 给定 IP 反查所有关联域名、证书、端口、技术栈。"""

from fastapi import APIRouter, HTTPException

from ..services.asset_service import get_asset_by_ip

router = APIRouter(tags=["search"])


@router.get("/search/reverse")
def reverse_search(ip: str):
    """反向搜索：给定 IP，返回该 IP 在所有扫描中的关联资产。

    参数: ?ip=1.2.3.4
    """
    if not ip or not ip.strip():
        raise HTTPException(400, "query param 'ip' is required")
    result = get_asset_by_ip(ip.strip())
    if result is None:
        raise HTTPException(404, "no assets found for this IP")
    return result
