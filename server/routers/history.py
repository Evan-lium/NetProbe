"""历史 API — GET /api/history, GET/DELETE /api/history/:id."""

from fastapi import APIRouter, HTTPException, Query

from ..services.history_service import list_scans, get_scan_detail, delete_scan

router = APIRouter(tags=["history"])


@router.get("/history")
def history_list(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    q: str = "",
    status: str = "",
):
    """扫描历史列表（分页 + 搜索）。"""
    return list_scans(page, per_page, q, status)


@router.get("/history/{scan_id}")
def history_detail(scan_id: str):
    """单次扫描详情。"""
    detail = get_scan_detail(scan_id)
    if not detail:
        raise HTTPException(404, "scan not found")
    return detail


@router.delete("/history/{scan_id}")
def history_delete(scan_id: str):
    """删除扫描记录。"""
    if not delete_scan(scan_id):
        raise HTTPException(404, "scan not found")
    return {"ok": True}
