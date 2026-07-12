"""扫描 API — POST /api/scan, GET /api/stream/:id."""

import json

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse, JSONResponse

from ..schemas.scan import ScanRequest, ScanResponse
from ..services.scan_service import get_task, start_scan

router = APIRouter(tags=["scan"])


@router.post("/scan", response_model=ScanResponse)
def create_scan(req: ScanRequest):
    """启动扫描任务。"""
    task_id = start_scan(req.target, req.model_dump())
    return ScanResponse(task_id=task_id)


@router.get("/stream/{task_id}")
def stream_task(task_id: str, token: str = Query(default="")):
    """SSE 实时进度流。

    鉴权：EventSource 无法设置 Authorization 头，改用 query 参数 ?token=xxx。
    中间件已豁免 /api/stream/ 路径，这里自行验证 token。

    - 任务在内存：先推 DB 历史日志（解决刷新丢失），再接实时队列
    - 任务不在内存（重启/旧任务）：推 DB 历史日志后结束，不报 404
    """
    # 验证 token（EventSource 通过 query 参数传递）
    if token:
        try:
            from ..services.auth_service import get_current_user
            get_current_user(token)
        except Exception:
            return JSONResponse(status_code=401, content={"detail": "token 无效或已过期"})
    else:
        return JSONResponse(status_code=401, content={"detail": "未登录，请先登录"})

    from ..services.scan_service import get_progress_log
    task = get_task(task_id)
    historical_log = get_progress_log(task_id)

    def event_generator():
        # 1. 先推送历史日志（刷新/重连时补齐已发生的进度）
        if historical_log:
            for line in historical_log.split("\n"):
                line = line.strip()
                if line:
                    yield f"data: {json.dumps({'event': 'progress', 'text': line}, ensure_ascii=False)}\n\n"

        # 2. 任务不在内存（已结束/重启）：推完历史直接静默结束（不加假 done 行）
        if not task:
            return

        # 3. 任务在内存：继续实时推送
        q = task["queue"]
        # 如果任务已结束，补发结束事件
        if task.get("status") in ("done", "error", "cancelled"):
            yield f"data: {json.dumps({'event': task['status'], 'text': '扫描已结束'}, ensure_ascii=False)}\n\n"
            return

        while True:
            try:
                data = q.get(timeout=25)
            except Exception:
                # 队列超时，检查任务是否已结束
                if task.get("status") in ("done", "error", "cancelled"):
                    break
                # 发心跳保活，防止长扫描被代理/Nginx 掐断
                yield f"data: {json.dumps({'event': 'heartbeat'}, ensure_ascii=False)}\n\n"
                continue
            yield f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
            if data.get("event") in ("done", "error", "cancelled"):
                break

    return StreamingResponse(event_generator(), media_type="text/event-stream")
