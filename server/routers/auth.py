"""认证 API — 登录/登出/改密码/当前用户。"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from ..services.auth_service import login, change_password, get_current_user
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


# ── 路由 ──────────────────────────────────────────────────

@router.post("/auth/login")
def user_login(req: LoginRequest):
    """用户登录，返回 JWT token。"""
    return login(req.username, req.password)


@router.get("/auth/me")
def get_me(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """获取当前登录用户信息。"""
    if not credentials:
        raise HTTPException(status_code=401, detail="未登录")
    user = get_current_user(credentials.credentials)
    return {"id": user.id, "username": user.username, "is_admin": user.is_admin}


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
