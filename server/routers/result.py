"""结果 API — GET /api/result/:id, GET /api/download/:id/:fmt."""

import json
import os
import tempfile

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from ..db import SessionLocal
from ..models import Scan, Host, Port, Banner, WebInfo, SensitivePath, JSFinding
from ..services.scan_service import get_task
from ..services.diff_service import compute_diff
from netprobe.formatter import save_results

router = APIRouter(tags=["result"])


@router.get("/result/diff")
def diff_results(a: str, b: str):
    """对比两次扫描结果，返回结构化差异。

    必须注册在 /result/{scan_id} 之前，否则 'diff' 会被当作 scan_id。
    """
    if not a or not b:
        raise HTTPException(400, "query params 'a' and 'b' are required")
    return compute_diff(a, b)


@router.get("/result/{scan_id}")
def get_result(scan_id: str):
    """获取扫描结果（优先从内存，回退到 DB）。"""
    # 内存中的实时任务
    task = get_task(scan_id)
    if task and task.get("hosts"):
        return {
            "scan_id": scan_id,
            "status": task["status"],
            "base_domain": task.get("base_domain", ""),
            "hosts": task["hosts"],
        }

    # 从 DB 查询
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            raise HTTPException(404, "scan not found")

        hosts = []
        for host in scan.hosts if hasattr(scan, "hosts") else []:
            host_data = {
                "hostname": host.hostname,
                "ip": host.ip,
                "os": host.os_info,
                "risk_score": host.risk_score or 0,
                "risk_factors": json.loads(host.risk_factors_json) if host.risk_factors_json else {},
                "ports": [
                    {"port": p.port, "proto": p.proto, "state": p.state,
                     "service": p.service, "product": p.product, "version": p.version,
                     "cpe": p.cpe or ""}
                    for p in host.ports
                ],
                "banners": [
                    {"port": b.port, "service": b.service, "banner": b.banner}
                    for b in host.banners
                ],
                "web_info": [
                    {
                        "port": w.port, "url": w.url, "status": w.status_code,
                        "title": w.title, "redirect": w.redirect,
                        "headers": json.loads(w.headers_json) if w.headers_json else {},
                        "tech": json.loads(w.tech_json) if w.tech_json else [],
                        "ssl": json.loads(w.ssl_json) if w.ssl_json and w.ssl_json != "null" else None,
                    }
                    for w in host.web_info_list
                ],
                "sensitive": [
                    {"path": s.path, "description": s.description,
                     "severity": s.severity, "status_code": s.status_code}
                    for s in host.sensitive_paths
                ],
                "js_findings": [
                    {
                        "js_url": j.js_url,
                        "api_endpoints": json.loads(j.api_endpoints_json) if j.api_endpoints_json else [],
                        "secrets": json.loads(j.secrets_json) if j.secrets_json else [],
                    }
                    for j in host.js_findings
                ],
            }
            hosts.append(host_data)

        return {
            "scan_id": scan_id,
            "status": scan.status,
            "base_domain": scan.base_domain,
            "hosts": hosts,
        }
    finally:
        db.close()


@router.get("/download/{scan_id}/{fmt}")
def download_result(scan_id: str, fmt: str):
    """下载报告 (txt/csv/json/pdf)。"""
    if fmt not in ("txt", "csv", "json", "pdf"):
        raise HTTPException(400, "fmt must be one of: txt, csv, json, pdf")

    # 获取数据
    result = get_result(scan_id)
    hosts = result.get("hosts", [])
    base_domain = result.get("base_domain", scan_id)

    if not hosts:
        raise HTTPException(404, "no scan results to export")

    # 生成临时文件
    suffix = f".{fmt}"
    fd, filepath = tempfile.mkstemp(suffix=suffix, prefix=f"netprobe_{scan_id}_")
    os.close(fd)

    try:
        save_results(hosts, filepath, fmt, base_domain)
        media_types = {
            "txt": "text/plain",
            "csv": "text/csv",
            "json": "application/json",
            "pdf": "application/pdf",
        }
        filename = f"netprobe_{scan_id}.{fmt}"
        return FileResponse(filepath, media_type=media_types[fmt], filename=filename)
    except Exception:
        if os.path.exists(filepath):
            os.unlink(filepath)
        raise HTTPException(500, f"failed to generate {fmt} report")
