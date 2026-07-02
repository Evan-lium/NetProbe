"""工具检测 API — GET /api/tools."""

from fastapi import APIRouter

from netprobe.tools.registry import get_available_tools

router = APIRouter(tags=["tools"])


@router.get("/tools")
def tools_status():
    """返回外部工具可用性。"""
    return get_available_tools()
