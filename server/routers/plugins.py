"""插件管理 API — 列出/启用/禁用检测插件。"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(tags=["plugins"])


@router.get("/plugins", summary="列出所有插件", description="返回所有已注册的检测插件信息（含启用状态/分类/阶段）")
def list_plugins():
    """列出所有已注册的插件。"""
    import sys, os
    # 确保 netprobe 包在 sys.path 上（uvicorn 运行时可能不在）
    _root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if _root not in sys.path:
        sys.path.insert(0, _root)
    from netprobe.plugins.registry import list_plugins_info
    plugins = list_plugins_info()
    return {"items": plugins, "total": len(plugins)}


class PluginToggle(BaseModel):
    enabled: bool


@router.patch("/plugins/{name}/toggle", summary="启用/禁用插件", description="切换插件的启用状态，持久化到 data/plugin_states.json")
def toggle_plugin(name: str, toggle: PluginToggle):
    """启用/禁用插件。"""
    import sys, os
    _root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if _root not in sys.path:
        sys.path.insert(0, _root)
    from netprobe.plugins.registry import get_plugin, set_enabled
    plugin = get_plugin(name)
    if not plugin:
        raise HTTPException(404, f"插件 '{name}' 不存在")
    if not plugin.is_available():
        raise HTTPException(400, f"插件 '{name}' 依赖未满足，无法启用")

    set_enabled(name, toggle.enabled)
    return {"ok": True, "name": name, "enabled": toggle.enabled}
