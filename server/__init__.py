from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import DATA_DIR
from .db import init_db
from .routers import include_all_routers


def create_app() -> FastAPI:
    app = FastAPI(title="NetProbe", version="3.0")

    # CORS (dev only)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Init DB on startup
    @app.on_event("startup")
    def on_startup():
        init_db()

    # Register API routes
    include_all_routers(app)

    # Serve Vue build in production
    import os

    dist_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist")
    if os.path.isdir(dist_dir):
        app.mount("/", StaticFiles(directory=dist_dir, html=True), name="static")

    return app
