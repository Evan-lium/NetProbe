from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import DATA_DIR
from .db import SessionLocal, init_db
from .routers import include_all_routers
from .models import Scan
from .services.schedule_service import init_scheduler, shutdown_scheduler


def create_app() -> FastAPI:
    app = FastAPI(title="NetProbe", version="3.0")

    # CORS (dev only)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Init DB + 调度器 on startup
    @app.on_event("startup")
    def on_startup():
        init_db()
        _cleanup_zombie_scans()  # 把上次进程中断留下的 running 记录标记为 error
        init_scheduler()  # 启动 APScheduler 并重建定时任务

    @app.on_event("shutdown")
    def on_shutdown():
        shutdown_scheduler()

    # Register API routes
    include_all_routers(app)

    # Serve Vue build in production
    import os

    dist_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist")
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
