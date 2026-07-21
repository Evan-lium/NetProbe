from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import DATA_DIR
from .db import SessionLocal, init_db
from .routers import include_all_routers
from .models import Scan
from .services.schedule_service import init_scheduler, shutdown_scheduler


def create_app() -> FastAPI:
    app = FastAPI(
        title="NetProbe API",
        description="""
## 开源一体化资产探测与攻击面管理（ASM）平台

### 认证
所有 `/api/*` 端点需 Bearer JWT 认证（`POST /api/auth/login` 豁免）。
SSE 流 `/api/stream/{id}` 和下载 `/api/download/{id}/{fmt}` 用 `?token=` query 参数。

### 权限（RBAC）
| 角色 | 权限 |
|------|------|
| admin | 全部 |
| scanner | scan, view, edit, download_report, manage_vulns |
| auditor | view, download_report, manage_vulns |
| viewer | view |

### 默认账号
首次启动自动创建 `admin / admin`（请尽快修改密码）。
        """,
        version="3.8.1",
        openapi_tags=[
            {"name": "auth", "description": "认证 / 用户管理 / RBAC 角色"},
            {"name": "scan", "description": "启动扫描 / SSE 实时进度"},
            {"name": "tasks", "description": "任务列表 / 取消 / 删除"},
            {"name": "result", "description": "扫描结果 / 报告下载"},
            {"name": "history", "description": "扫描历史"},
            {"name": "assets", "description": "跨扫描资产汇总"},
            {"name": "asset-tags", "description": "资产标签 / 分组"},
            {"name": "plugins", "description": "插件管理 / 启用禁用"},
            {"name": "vulnerabilities", "description": "漏洞生命周期管理"},
            {"name": "scan-engines", "description": "扫描引擎配置"},
            {"name": "schedules", "description": "定时扫描（cron）"},
            {"name": "alerts", "description": "告警规则 / 触发历史"},
            {"name": "asm", "description": "攻击面管理总览"},
            {"name": "correlations", "description": "资产关联查询"},
            {"name": "stats", "description": "统计 / 资产详情"},
            {"name": "search", "description": "资产检索（IP/favicon/github）"},
            {"name": "settings", "description": "API Key / 通知 / 配置"},
            {"name": "tools", "description": "外部工具可用性"},
        ],
    )

    # CORS (dev only)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # JWT 认证中间件 — 保护 /api 路由（login/注册/文档豁免）
    @app.middleware("http")
    async def jwt_auth_middleware(request: Request, call_next):
        path = request.url.path

        # 豁免路径：登录/静态文件/文档/SSE 流
        # SSE 用 EventSource，浏览器原生 API 无法设置 Authorization 头，
        # 改为通过 query 参数 ?token=xxx 鉴权（在 stream 路由内部验证）
        if (path == "/api/auth/login"
            or path.startswith("/api/auth/me")
            or path.startswith("/api/stream/")
            or path.startswith("/api/download/")
            or not path.startswith("/api")
            or path in ("/docs", "/openapi.json", "/redoc")):
            return await call_next(request)

        # 检查 Authorization 头
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                from .services.auth_service import get_current_user
                # 验证 token（失败会抛 401）
                get_current_user(token)
                return await call_next(request)
            except Exception:
                return JSONResponse(status_code=401, content={"detail": "token 无效或已过期"})

        # 无 token
        return JSONResponse(status_code=401, content={"detail": "未登录，请先登录"})

    # Init DB + 调度器 on startup
    @app.on_event("startup")
    def on_startup():
        init_db()
        from .services.auth_service import init_admin
        init_admin()  # 首次启动创建默认管理员 admin/admin
        _cleanup_zombie_scans()
        init_scheduler()

    @app.on_event("shutdown")
    def on_shutdown():
        shutdown_scheduler()

    # Register API routes
    include_all_routers(app)

    import os

    # 托管截图静态文件（扫描时 Playwright 截图存到 data/screenshots/）
    project_root = os.path.dirname(os.path.dirname(__file__))
    screenshot_dir = os.path.join(project_root, "data", "screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)
    app.mount("/screenshots", StaticFiles(directory=screenshot_dir), name="screenshots")

    # Serve Vue build in production
    dist_dir = os.path.join(project_root, "frontend", "dist")
    if os.path.isdir(dist_dir):
        app.mount("/", StaticFiles(directory=dist_dir, html=True), name="static")

    return app


def _cleanup_zombie_scans():
    """把 DB 里卡在 running 的 Scan 标记为 error（进程重启中断）。"""
    db = SessionLocal()
    try:
        zombies = db.query(Scan).filter(Scan.status == "running").all()
        for z in zombies:
            z.status = "error"
            z.error_msg = "进程重启中断"
        if zombies:
            db.commit()
    finally:
        db.close()
