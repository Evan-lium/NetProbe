"""认证 API — 登录/登出/改密码/当前用户/用户管理。"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from ..services.auth_service import (
    login, change_password, get_current_user,
    list_users, create_user, update_user, delete_user,
)
from ..models import User

router = APIRouter(tags=["auth"])
security = HTTPBearer(auto_error=False)


# ── 请求模型 ──────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    is_admin: bool = False
    role: str = ""


class UpdateUserRequest(BaseModel):
    password: str | None = None
    is_admin: bool | None = None
    role: str | None = None


# ── 辅助：要求管理员 ─────────────────────────────────────

def _require_admin(credentials: HTTPAuthorizationCredentials) -> User:
    """解析 token 并要求管理员权限，返回 User 对象。"""
    if not credentials:
        raise HTTPException(status_code=401, detail="未登录")
    user = get_current_user(credentials.credentials)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return user


# ── 认证路由 ──────────────────────────────────────────────

@router.post("/auth/login", summary="用户登录", description="用户名密码登录，返回 JWT token")
def user_login(req: LoginRequest):
    """用户登录，返回 JWT token。"""
    return login(req.username, req.password)


@router.get("/auth/me")
def get_me(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """获取当前登录用户信息。"""
    if not credentials:
        raise HTTPException(status_code=401, detail="未登录")
    user = get_current_user(credentials.credentials)
    return {
        "id": user.id, "username": user.username,
        "is_admin": user.is_admin,
        "role": user.role or ("admin" if user.is_admin else "viewer"),
    }


@router.get("/auth/roles", summary="获取角色列表", description="返回 RBAC 角色及其权限列表")
def get_roles(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """返回可用角色列表（前端下拉用）。"""
    from ..models.user import ROLES, ROLE_PERMISSIONS
    return [
        {"value": k, "label": v, "permissions": sorted(ROLE_PERMISSIONS.get(k, set()))}
        for k, v in ROLES.items()
    ]


@router.post("/auth/change-password")
def user_change_password(req: ChangePasswordRequest, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """修改密码。"""
    if not credentials:
        raise HTTPException(status_code=401, detail="未登录")
    user = get_current_user(credentials.credentials)
    ok = change_password(user.id, req.old_password, req.new_password)
    if not ok:
        raise HTTPException(status_code=400, detail="旧密码错误")
    return {"success": True, "message": "密码修改成功"}


# ── 用户管理（仅管理员）─────────────────────────────────

@router.get("/auth/users")
def get_users(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """获取用户列表（仅管理员）。"""
    _require_admin(credentials)
    return {"items": list_users(), "total": len(list_users())}


@router.post("/auth/users")
def post_user(req: CreateUserRequest, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """创建用户（仅管理员）。"""
    _require_admin(credentials)
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="密码至少 6 位")
    user = create_user(req.username, req.password, req.is_admin, req.role)
    return {"id": user.id, "username": user.username, "is_admin": user.is_admin, "role": user.role}


@router.put("/auth/users/{user_id}")
def put_user(user_id: int, req: UpdateUserRequest, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """编辑用户——改密码/角色（仅管理员）。"""
    _require_admin(credentials)
    if req.password is not None and len(req.password) < 6:
        raise HTTPException(status_code=400, detail="密码至少 6 位")
    ok = update_user(user_id, req.password, req.is_admin, req.role)
    if not ok:
        raise HTTPException(status_code=404, detail="用户不存在")
    return {"success": True}


@router.delete("/auth/users/{user_id}")
def del_user(user_id: int, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """删除用户（仅管理员）。"""
    admin = _require_admin(credentials)
    ok = delete_user(user_id, admin.id)
    if not ok:
        raise HTTPException(status_code=404, detail="用户不存在")
    return {"success": True}

