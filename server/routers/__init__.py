from fastapi import FastAPI

from .scan import router as scan_router
from .result import router as result_router
from .history import router as history_router
from .assets import router as assets_router
from .settings import router as settings_router
from .tools import router as tools_router
from .tasks import router as tasks_router
from .schedules import router as schedules_router
from .correlations import router as correlations_router
from .search import router as search_router


def include_all_routers(app: FastAPI):
    app.include_router(scan_router, prefix="/api")
    app.include_router(result_router, prefix="/api")
    app.include_router(history_router, prefix="/api")
    app.include_router(assets_router, prefix="/api")
    app.include_router(settings_router, prefix="/api")
    app.include_router(tools_router, prefix="/api")
    app.include_router(tasks_router, prefix="/api")
    app.include_router(schedules_router, prefix="/api")
    app.include_router(correlations_router, prefix="/api")
    app.include_router(search_router, prefix="/api")
