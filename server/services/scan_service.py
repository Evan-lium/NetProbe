"""扫描任务管理服务 — 线程、SSE 队列、双写 DB、取消机制。"""

import json
import os
import queue
import threading
import uuid
from datetime import datetime

from netprobe.engine import parse_targets, scan_all_targets
from netprobe.formatter import save_results

from ..config import DATA_DIR
from ..db import SessionLocal
from ..models import Scan, Host, Port, Banner, WebInfo, SensitivePath, JSFinding, WhoisRecord

# 全局任务存储（内存 + DB 双写）
_tasks: dict[str, dict] = {}
_TASK_MAX_AGE = 3600

# settings.json api_keys 字段 → os.environ 环境变量名 的映射
# netprobe 工具（fofa/hunter/shodan）读取环境变量，UI 填的 key 存在 settings.json，
# 此映射在每次扫描前把两者打通。
_API_KEY_ENV_MAP = {
    "fofa_email": "FOFA_EMAIL",
    "fofa_key": "FOFA_KEY",
    "hunter_key": "HUNTER_KEY",
    "shodan": "SHODAN_API_KEY",
    "censys_id": "CENSYS_ID",
    "censys_secret": "CENSYS_SECRET",
}

_SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")


def _inject_api_keys():
    """从 data/settings.json 读取 api_keys 并注入 os.environ，让 UI 配置的 key 对扫描引擎生效。"""
    if not os.path.isfile(_SETTINGS_FILE):
        return
    try:
        with open(_SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return
    api_keys = data.get("api_keys") or {}
    for settings_key, env_name in _API_KEY_ENV_MAP.items():
        value = (api_keys.get(settings_key) or "").strip()
        if value:
            os.environ[env_name] = value


def get_tasks() -> dict[str, dict]:
    return _tasks


def get_task(task_id: str) -> dict | None:
    return _tasks.get(task_id)


def is_cancelled(task_id: str) -> bool:
    """检查任务是否已取消。"""
    task = _tasks.get(task_id)
    if not task:
        return True
    return task.get("cancel_event", threading.Event()).is_set()


def register_process(task_id: str, proc):
    """注册子进程以便取消时终止。"""
    task = _tasks.get(task_id)
    if task:
        task["processes"].append(proc)


def unregister_process(task_id: str, proc):
    """移除已完成的子进程。"""
    task = _tasks.get(task_id)
    if task and proc in task["processes"]:
        task["processes"].remove(proc)


def cancel_task(task_id: str) -> bool:
    """取消运行中的扫描任务。"""
    task = _tasks.get(task_id)
    if not task or task["status"] != "running":
        return False

    # 发送取消信号
    task["cancel_event"].set()

    # 终止所有跟踪的子进程
    for proc in list(task.get("processes", [])):
        try:
            proc.terminate()
        except Exception:
            pass

    # 更新内存状态
    task["status"] = "cancelled"

    # 发送取消事件到 SSE 队列
    q = task["queue"]
    try:
        q.put_nowait({"event": "cancelled", "text": "任务已取消"})
    except queue.Full:
        pass

    # 更新 DB
    _update_scan_status(task_id, "cancelled", "用户取消")
    return True


def list_active_tasks() -> list[dict]:
    """返回内存中所有任务的序列化列表。"""
    result = []
    for tid, t in _tasks.items():
        elapsed = (datetime.now() - t.get("created_at", datetime.now())).total_seconds()
        result.append({
            "id": tid,
            "scan_id": tid,
            "name": t.get("name", ""),
            "target": t.get("target", ""),
            "status": t["status"],
            "host_count": len(t.get("hosts", [])),
            "port_count": 0,
            "web_count": 0,
            "started_at": t.get("created_at", datetime.now()).isoformat(),
            "finished_at": None,
            "duration_secs": int(elapsed) if t["status"] == "running" else None,
            "progress": t.get("progress", ""),
            "options": t.get("options"),
            "error_msg": "",
        })
    return result


def _cleanup_old_tasks():
    now = datetime.now()
    expired = [
        tid for tid, t in _tasks.items()
        if t.get("status") in ("done", "error", "cancelled")
        and (now - t.get("created_at", now)).total_seconds() > _TASK_MAX_AGE
    ]
    for tid in expired:
        del _tasks[tid]


def start_scan(raw_targets: str, options: dict) -> str:
    """启动扫描任务，返回 task_id。"""
    task_id = uuid.uuid4().hex[:12]
    cancel_event = threading.Event()

    # 把 UI 配置的 API key 注入环境变量，让 netprobe 工具（fofa/hunter/shodan）能读到
    _inject_api_keys()

    _tasks[task_id] = {
        "id": task_id,
        "target": raw_targets,
        "name": options.get("name", ""),
        "status": "running",
        "queue": queue.Queue(maxsize=500),
        "hosts": [],
        "base_domain": "",
        "created_at": datetime.now(),
        "cancel_event": cancel_event,
        "options": options.copy(),
        "processes": [],
        "progress": "",
    }
    _cleanup_old_tasks()

    # 注入回调到 options
    options["_cancel_check"] = cancel_event.is_set
    options["_task_id"] = task_id

    def _process_callback(action, proc):
        if action == "start":
            register_process(task_id, proc)
        elif action == "end":
            unregister_process(task_id, proc)

    options["_process_callback"] = _process_callback

    # 写入 DB (running 状态)
    db = SessionLocal()
    try:
        serializable_opts = {k: v for k, v in options.items() if not k.startswith("_")}
        scan = Scan(
            scan_id=task_id,
            name=options.get("name", ""),
            target_raw=raw_targets,
            status="running",
            options_json=json.dumps(serializable_opts, ensure_ascii=False),
            started_at=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()
    finally:
        db.close()

    thread = threading.Thread(
        target=_run_scan_task,
        args=(task_id, raw_targets, options),
        daemon=True,
    )
    thread.start()
    return task_id


def _run_scan_task(task_id: str, raw_targets: str, options: dict):
    """后台线程执行扫描。"""
    task = _tasks[task_id]
    q = task["queue"]

    def emit(event, **data):
        payload = {"event": event, **data}
        try:
            q.put_nowait(payload)
        except queue.Full:
            pass
        if event in ("done", "error"):
            task["status"] = event
        # 记录最近进度
        if event == "progress" and "text" in data:
            task["progress"] = data["text"]

    try:
        targets = parse_targets(raw_targets)
        hosts = scan_all_targets(targets, options, emit)

        # 检查是否被取消
        if task["cancel_event"].is_set():
            task["status"] = "cancelled"
            _update_scan_status(task_id, "cancelled", "用户取消")
            return

        if hosts:
            labels = list({h.get("hostname", "") for h in hosts})
            label = "+".join(labels[:3])
            if len(labels) > 3:
                label += f"+{len(labels) - 3}more"
            task["hosts"] = hosts
            task["base_domain"] = label
            emit("done", hosts=hosts, base_domain=label)
        else:
            label = raw_targets.strip().split("\n")[0][:50]
            task["base_domain"] = label
            emit("done", hosts=[], base_domain=label)

        # 双写 DB
        _write_results_to_db(task_id, hosts, label)
    except Exception as e:
        if not task["cancel_event"].is_set():
            emit("error", text=f"扫描异常: {e}")
            task["status"] = "error"
            _update_scan_status(task_id, "error", str(e))


def _write_results_to_db(scan_id: str, hosts: list[dict], base_domain: str):
    """将扫描结果写入 SQLite。"""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            return

        scan.base_domain = base_domain
        scan.status = "done"
        scan.finished_at = datetime.utcnow()
        scan.duration_secs = int((scan.finished_at - scan.started_at).total_seconds())

        total_hosts = 0
        total_ports = 0
        total_web = 0
        total_sensitive = 0

        for h in hosts:
            host = Host(
                scan_id=scan_id,
                target=h.get("hostname", ""),
                hostname=h.get("hostname", ""),
                ip=h.get("ip", ""),
                os_info=h.get("os", ""),
                sort_order=total_hosts,
                risk_score=h.get("risk_score", 0),
                risk_factors_json=json.dumps(h.get("risk_factors", {}), ensure_ascii=False),
            )
            db.add(host)
            db.flush()  # get host_id

            for p in h.get("ports", []):
                db.add(Port(
                    host_id=host.host_id,
                    port=p.get("port", 0),
                    proto=p.get("proto", "tcp"),
                    state=p.get("state", "open"),
                    service=p.get("service", ""),
                    product=p.get("product", ""),
                    version=p.get("version", ""),
                    cpe=p.get("cpe", ""),
                ))
                total_ports += 1

            for b in h.get("banners", []):
                db.add(Banner(
                    host_id=host.host_id,
                    port=b.get("port", 0),
                    service=b.get("service", ""),
                    banner=b.get("banner", ""),
                ))

            for w in h.get("web_info", []):
                db.add(WebInfo(
                    host_id=host.host_id,
                    port=w.get("port", 0),
                    url=w.get("url", ""),
                    status_code=w.get("status"),
                    title=w.get("title", ""),
                    redirect=w.get("redirect", ""),
                    headers_json=json.dumps(w.get("headers", {}), ensure_ascii=False),
                    tech_json=json.dumps(w.get("tech", []), ensure_ascii=False),
                    ssl_json=json.dumps(w.get("ssl"), ensure_ascii=False) if w.get("ssl") else "null",
                    favicon_hash=w.get("favicon_hash", ""),
                    cdn_detected=w.get("cdn", ""),
                ))
                total_web += 1

            for s in h.get("sensitive", []):
                db.add(SensitivePath(
                    host_id=host.host_id,
                    path=s.get("path", ""),
                    description=s.get("description", ""),
                    severity=s.get("severity", "info"),
                    status_code=s.get("status_code"),
                ))
                total_sensitive += 1

            for j in h.get("js_findings", []):
                db.add(JSFinding(
                    host_id=host.host_id,
                    js_url=j.get("js_url", ""),
                    api_endpoints_json=json.dumps(j.get("api_endpoints", []), ensure_ascii=False),
                    secrets_json=json.dumps(j.get("secrets", []), ensure_ascii=False),
                ))

            # WHOIS/RDAP 记录
            for w in h.get("_whois", []):
                db.add(WhoisRecord(
                    host_id=host.host_id,
                    type=w.get("type", ""),
                    target=w.get("target", ""),
                    data_json=json.dumps(w.get("data", {}), ensure_ascii=False),
                ))

            total_hosts += 1

        scan.host_count = total_hosts
        scan.port_count = total_ports
        scan.web_count = total_web
        scan.sensitive_count = total_sensitive
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[!] DB write error for {scan_id}: {e}")
    finally:
        db.close()


def _update_scan_status(scan_id: str, status: str, error_msg: str = ""):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if scan:
            scan.status = status
            scan.error_msg = error_msg
            scan.finished_at = datetime.utcnow()
            scan.duration_secs = int((scan.finished_at - scan.started_at).total_seconds())
            db.commit()
    finally:
        db.close()
