"""认证服务 — JWT 签发/验证 + 密码哈希 + 用户管理。

首次启动自动创建默认管理员（admin/admin），登录后建议改密码。
"""

from datetime import datetime, timedelta

import jwt
import bcrypt
from fastapi import HTTPException, status

from ..config import SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRE_DAYS
from ..db import SessionLocal
from ..models import User


def hash_password(plain: str) -> str:
    """bcrypt 哈希密码。"""
    pwd_bytes = plain.encode("utf-8")[:72]
    return bcrypt.hashpw(pwd_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """校验密码。"""
    pwd_bytes = plain.encode("utf-8")[:72]
    return bcrypt.checkpw(pwd_bytes, hashed.encode("utf-8"))


def create_token(user: User) -> str:
    """签发 JWT token（有效期 7 天）。"""
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "is_admin": user.is_admin,
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRE_DAYS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def get_current_user(token: str) -> User:
    """解析 JWT token，返回用户对象。token 无效则抛 401。"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="token 无效或已过期",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = int(payload.get("sub", 0))
        if not user_id:
            raise credentials_exception
    except (jwt.InvalidTokenError, ValueError):
        raise credentials_exception

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise credentials_exception
        return user
    finally:
        db.close()


def login(username: str, password: str) -> dict:
    """用户登录，返回 {token, user}。失败抛 401。"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user or not verify_password(password, user.password_hash):
            raise HTTPException(status_code=401, detail="用户名或密码错误")
        # 更新最后登录时间
        user.last_login = datetime.utcnow()
        db.commit()
        token = create_token(user)
        return {
            "token": token,
            "user": {"id": user.id, "username": user.username, "is_admin": user.is_admin},
        }
    finally:
        db.close()


def change_password(user_id: int, old_password: str, new_password: str) -> bool:
    """修改密码。旧密码不匹配返回 False。"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not verify_password(old_password, user.password_hash):
            return False
        user.password_hash = hash_password(new_password)
        db.commit()
        return True
    finally:
        db.close()


def create_user(username: str, password: str, is_admin: bool = False) -> User:
    """创建新用户。用户名已存在则抛 400。"""
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            raise HTTPException(status_code=400, detail="用户名已存在")
        user = User(username=username, password_hash=hash_password(password), is_admin=is_admin)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


def init_admin():
    """首次启动时自动创建默认管理员（admin/admin）。

    在 app startup 调用，如果 users 表为空则创建。
    """
    db = SessionLocal()
    try:
        count = db.query(User).count()
        if count == 0:
            admin = User(
                username="admin",
                password_hash=hash_password("admin"),
                is_admin=True,
            )
            db.add(admin)
            db.commit()
            print("[*] 已创建默认管理员: admin/admin（请尽快修改密码）")
    finally:
        db.close()
