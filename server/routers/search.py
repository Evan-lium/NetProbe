"""反向搜索 API — 给定 IP 反查所有关联域名、证书、端口、技术栈。"""

from fastapi import APIRouter, HTTPException

from ..services.asset_service import get_asset_by_ip
from ..services.correlation_service import search_by_favicon_external

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


@router.get("/search/favicon")
def search_favicon(hash: str, source: str = "fofa"):
    """用 favicon hash 对接外部空间搜索引擎（FOFA/Shodan）反查同源资产。

    参数:
      hash:   mmh3 favicon hash（FOFA icon_hash 同款）
      source: 'fofa'（默认）或 'shodan'

    返回: {source, query, count, results}。无 API key 时 count=0。
    """
    if not hash or not hash.strip():
        raise HTTPException(400, "query param 'hash' is required")
    src = (source or "fofa").strip().lower()
    if src not in ("fofa", "shodan"):
        raise HTTPException(400, "source must be 'fofa' or 'shodan'")
    return search_by_favicon_external(hash.strip(), src)
