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
from ..models import Scan, Host, Port, Banner, WebInfo, SensitivePath, JSFinding, WhoisRecord, Vulnerability, ScanEngine


def _load_engine_config(engine_id: int) -> dict | None:
    """加载扫描引擎的 config（含 stages/工具/参数）。"""
    db = SessionLocal()
    try:
        engine = db.query(ScanEngine).filter(ScanEngine.id == engine_id).first()
        if not engine or not engine.config_json:
            return None
        return json.loads(engine.config_json)
    except (json.JSONDecodeError, Exception):
        return None
    finally:
        db.close()
from ..utils import to_iso_z

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
        elapsed = (datetime.utcnow() - t.get("created_at", datetime.utcnow())).total_seconds()
        result.append({
            "id": tid,
            "scan_id": tid,
            "name": t.get("name", ""),
            "target": t.get("target", ""),
            "status": t["status"],
            "host_count": len(t.get("hosts", [])),
            "port_count": 0,
            "web_count": 0,
            "started_at": to_iso_z(t.get("created_at")),
            "finished_at": None,
            "duration_secs": int(elapsed) if t["status"] == "running" else None,
            "progress": t.get("progress", ""),
            "options": t.get("options"),
            "error_msg": "",
        })
    return result


def _cleanup_old_tasks():
    now = datetime.utcnow()
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

    # 如果指定了扫描引擎，加载引擎 config 作为默认值
    # 注意：用户表单显式传入的字段优先，引擎 config 只填充用户没传的字段
    engine_id = options.get("engine_id")
    if engine_id:
        engine_config = _load_engine_config(engine_id)
        if engine_config:
            for k, v in engine_config.items():
                if k == "stages":
                    # stages 总是用引擎的（用户通过勾选框覆盖时已传到 options.stages）
                    if "stages" not in options:
                        options["stages"] = v
                elif v not in (None, "", []) and k not in options:
                    # 只填充用户没传的字段（用户表单值优先）
                    options[k] = v

    _tasks[task_id] = {
        "id": task_id,
        "target": raw_targets,
        "name": options.get("name", ""),
        "status": "running",
        "queue": queue.Queue(maxsize=500),
        "hosts": [],
        "base_domain": "",
        "created_at": datetime.utcnow(),
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
            # 持久化进度日志到 DB（刷新/重启后可查看）
            _append_progress_log(task_id, data["text"])
        elif event in ("done", "error", "cancelled") and "text" in data:
            _append_progress_log(task_id, data["text"])

    try:
        targets = parse_targets(raw_targets)
        hosts = scan_all_targets(targets, options, emit)

        # 检查是否被取消
        if task["cancel_event"].is_set():
            task["status"] = "cancelled"
            _update_scan_status(task_id, "cancelled", "用户取消")
            _flush_progress_log(task_id)  # 取消时也刷盘
            return

        if hosts:
            labels = list({h.get("hostname", "") for h in hosts})
            label = "+".join(labels[:3])
            if len(labels) > 3:
                label += f"+{len(labels) - 3}more"
            task["hosts"] = hosts
            task["base_domain"] = label
        else:
            label = raw_targets.strip().split("\n")[0][:50]
            task["base_domain"] = label

        # 先写 DB（更新 scan 表的 host_count/port_count/web_count），再 emit done
        # 这样前端收到 done 事件刷新列表时，数字已写入
        _write_results_to_db(task_id, hosts, label)

        emit("done", hosts=hosts, base_domain=label)
        _flush_progress_log(task_id)  # 刷盘剩余日志

        # 扫描完成后检查告警规则（延迟 import 避免循环依赖）
        try:
            from .alert_service import check_after_scan
            check_after_scan(task_id)
        except Exception as e:
            print(f"[!] 告警检查失败: {e}")
    except Exception as e:
        if not task["cancel_event"].is_set():
            emit("error", text=f"扫描异常: {e}")
            task["status"] = "error"
            _update_scan_status(task_id, "error", str(e))
        _flush_progress_log(task_id)  # 异常时也刷盘


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
                    screenshot_path=w.get("screenshot_path", ""),
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

            # 目录爆破结果复用 SensitivePath 表（severity=info，description 标注 dir_brute）
            for d in h.get("_dir_findings", []):
                desc = f"[dir_brute] {d.get('description', '')}".strip()
                # 把响应体大小也记进 description 辅助判断
                size = d.get("size", 0)
                if size:
                    desc = f"{desc} size={size}" if desc else f"[dir_brute] size={size}"
                db.add(SensitivePath(
                    host_id=host.host_id,
                    path=d.get("path", ""),
                    description=desc or "[dir_brute]",
                    severity="info",
                    status_code=d.get("status"),
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

            # DNS 全类型记录（存 whois_records 表，type='dns'）
            dns_data = h.get("_dns_records")
            if dns_data:
                db.add(WhoisRecord(
                    host_id=host.host_id,
                    type="dns",
                    target=dns_data.get("domain", ""),
                    data_json=json.dumps(dns_data, ensure_ascii=False),
                ))

            # 漏洞扫描结果（nuclei）
            for v in h.get("vulnerabilities", []):
                db.add(Vulnerability(
                    host_id=host.host_id,
                    template_id=v.get("template_id", ""),
                    name=v.get("name", ""),
                    severity=v.get("severity", "info"),
                    cve=v.get("cve", ""),
                    cvss_score=v.get("cvss_score", ""),
                    cwe=v.get("cwe", ""),
                    category=v.get("category", ""),
                    url=v.get("url", ""),
                    matched_at=v.get("matched_at", ""),
                    extracted_data_json=json.dumps(v.get("extracted_data", {}), ensure_ascii=False),
                ))

            # 安全头检查 → vulnerabilities（category=security_header）
            for sh in h.get("_security_findings", []):
                db.add(Vulnerability(
                    host_id=host.host_id,
                    name=sh.get("header", ""),
                    severity=sh.get("severity", "medium"),
                    category="security_header",
                    extracted_data_json=json.dumps(sh, ensure_ascii=False),
                ))
            # CORS 检测 → vulnerabilities（category=cors）
            for cf in h.get("_cors_findings", []):
                db.add(Vulnerability(
                    host_id=host.host_id,
                    name=f"CORS {cf.get('origin','')} — {cf.get('issue','')}",
                    severity=cf.get("severity", "medium"),
                    category="cors",
                    extracted_data_json=json.dumps(cf, ensure_ascii=False),
                ))
            # 管理后台 → vulnerabilities（category=admin_panel）
            for ap in h.get("_admin_panels", []):
                db.add(Vulnerability(
                    host_id=host.host_id,
                    name=f"管理后台: {ap.get('title','')} ({ap.get('url','')})",
                    severity="info",
                    category="admin_panel",
                    url=ap.get("url", ""),
                    extracted_data_json=json.dumps(ap, ensure_ascii=False),
                ))
            # 真实 IP → vulnerabilities（category=origin_ip）
            origin = h.get("_origin_ips")
            if origin and origin.get("candidates"):
                for cand in origin["candidates"][:5]:
                    db.add(Vulnerability(
                        host_id=host.host_id,
                        name=f"CDN真实IP候选: {cand.get('ip','')} (来源: {cand.get('source','')})",
                        severity="info",
                        category="origin_ip",
                        extracted_data_json=json.dumps(cand, ensure_ascii=False),
                    ))
            # robots.txt / sitemap.xml → vulnerabilities（category=robots）
            for rf in h.get("_robots_findings", []):
                robots = rf.get("robots", {})
                sitemap_n = len(rf.get("sitemap_paths", []))
                disallow_n = len(robots.get("disallow_paths", []))
                db.add(Vulnerability(
                    host_id=host.host_id,
                    name=f"robots/sitemap: {rf.get('url','')} (Disallow:{disallow_n} Sitemap路径:{sitemap_n})",
                    severity="info",
                    category="robots",
                    url=rf.get("url", ""),
                    extracted_data_json=json.dumps(rf, ensure_ascii=False),
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


# 进度日志内存缓冲：避免每条日志都写 DB（SQLite 写锁会阻塞 API 读请求）
# 每个 scan_id 维护一个缓冲区 + 最后写入时间
_progress_buffers: dict[str, dict] = {}  # scan_id → {lines: [], last_flush: float}
_PROGRESS_FLUSH_INTERVAL = 3.0  # 秒：最多每 3 秒刷一次 DB
_PROGRESS_FLUSH_THRESHOLD = 20  # 条：攒满 20 条立即刷


def _append_progress_log(scan_id: str, text: str):
    """把进度日志追加到内存缓冲区，批量写入 DB。

    扫描过程中每条日志只追加到内存，每 3 秒或满 20 条才写一次 DB，
    避免 SQLite 写锁频繁阻塞前端的 API 读请求。
    """
    if not text:
        return
    import time as _time
    buf = _progress_buffers.get(scan_id)
    if buf is None:
        buf = {'lines': [], 'last_flush': _time.time()}
        _progress_buffers[scan_id] = buf
    buf['lines'].append(text)
    now = _time.time()
    # 攒够条数或超时才刷盘
    if len(buf['lines']) >= _PROGRESS_FLUSH_THRESHOLD or (now - buf['last_flush']) >= _PROGRESS_FLUSH_INTERVAL:
        _flush_progress_log(scan_id)


def _flush_progress_log(scan_id: str):
    """把内存缓冲的日志批量写入 DB。"""
    import time as _time
    buf = _progress_buffers.get(scan_id)
    if not buf or not buf['lines']:
        return
    lines_to_write = buf['lines']
    buf['lines'] = []
    buf['last_flush'] = _time.time()

    batch_text = '\n'.join(lines_to_write) + '\n'
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if scan:
            existing = scan.progress_log or ""
            new_log = existing + batch_text
            if len(new_log) > 100_000:
                all_lines = new_log.split("\n")
                new_log = "\n".join(all_lines[-500:])
            scan.progress_log = new_log
            db.commit()
    except Exception:
        pass
    finally:
        db.close()


def get_progress_log(scan_id: str) -> str:
    """读取持久化的扫描进度日志。"""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        return scan.progress_log or "" if scan else ""
    finally:
        db.close()
