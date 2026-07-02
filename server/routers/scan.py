"""扫描 API — POST /api/scan, GET /api/stream/:id."""

import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from ..schemas.scan import ScanRequest, ScanResponse
from ..services.scan_service import get_task, start_scan

router = APIRouter(tags=["scan"])


@router.post("/scan", response_model=ScanResponse)
def create_scan(req: ScanRequest):
    """启动扫描任务。"""
    task_id = start_scan(req.target, req.model_dump())
    return ScanResponse(task_id=task_id)


@router.get("/stream/{task_id}")
def stream_task(task_id: str):
    """SSE 实时进度流。"""
    task = get_task(task_id)
    if not task:
        raise HTTPException(404, "task not found")

    def event_generator():
        q = task["queue"]
        while True:
            try:
                data = q.get(timeout=60)
            except Exception:
                # 队列超时，检查任务是否已结束
                if task.get("status") in ("done", "error"):
                    break
                continue
            yield f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
            if data.get("event") in ("done", "error"):
                break

    return StreamingResponse(event_generator(), media_type="text/event-stream")
