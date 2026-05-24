"""NetProbe Web 服务 — Flask 路由 + 任务管理。"""

import json
import os
import queue
import threading
import uuid
from datetime import datetime

from flask import Flask, Response, jsonify, render_template, request, send_file

from netprobe.engine import parse_targets, scan_all_targets
from netprobe.formatter import save_results
from netprobe.tools.registry import get_available_tools

app = Flask(__name__)
tasks: dict[str, dict] = {}
_TASK_MAX_AGE = 3600


def _cleanup_old_tasks():
    """清理超时的已完成任务，防止内存泄漏。"""
    now = datetime.now()
    expired = [
        tid for tid, t in tasks.items()
        if t.get('status') in ('done', 'error')
        and (now - t.get('created_at', now)).total_seconds() > _TASK_MAX_AGE
    ]
    for tid in expired:
        del tasks[tid]


def _run_scan_task(task_id: str, raw_targets: str, options: dict):
    """在后台线程中执行扫描。"""
    task = tasks[task_id]
    q = task['queue']

    def emit(event, **data):
        payload = {'event': event, **data}
        try:
            q.put_nowait(payload)
        except queue.Full:
            pass
        if event in ('done', 'error'):
            task['status'] = event

    try:
        targets = parse_targets(raw_targets)
        hosts = scan_all_targets(targets, options, emit)

        if hosts:
            labels = list({h.get('hostname', '') for h in hosts})
            label = '+'.join(labels[:3])
            if len(labels) > 3:
                label += f'+{len(labels)-3}more'
            task['hosts'] = hosts
            task['base_domain'] = label
            emit('done', hosts=hosts, base_domain=label)
    except Exception as e:
        emit('error', text=f'扫描异常: {e}')
        task['status'] = 'error'


# ── 路由 ──────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/tools')
def api_tools():
    return jsonify(get_available_tools())


@app.route('/api/scan', methods=['POST'])
def api_scan():
    body = request.get_json(force=True)
    raw_targets = body.get('target', '').strip()
    if not raw_targets:
        return jsonify({'error': '目标不能为空'}), 400

    task_id = uuid.uuid4().hex[:12]
    tasks[task_id] = {
        'id': task_id,
        'target': raw_targets,
        'status': 'running',
        'queue': queue.Queue(maxsize=500),
        'hosts': [],
        'base_domain': '',
        'created_at': datetime.now(),
    }
    _cleanup_old_tasks()

    options = {
        'no_dns_brute': body.get('no_dns_brute', False),
        'no_web': body.get('no_web', False),
        'no_validate': body.get('no_validate', False),
        'timeout': body.get('timeout', 300),
        'subdomain_tool': body.get('subdomain_tool', 'auto'),
        'portscan_tool': body.get('portscan_tool', 'auto'),
        'web_tool': body.get('web_tool', 'auto'),
        'dns_tool': body.get('dns_tool', 'auto'),
    }

    thread = threading.Thread(
        target=_run_scan_task, args=(task_id, raw_targets, options), daemon=True,
    )
    thread.start()
    return jsonify({'task_id': task_id})


@app.route('/api/stream/<task_id>')
def api_stream(task_id):
    task = tasks.get(task_id)
    if not task:
        return jsonify({'error': '任务不存在'}), 404

    def generate():
        q = task['queue']
        while True:
            try:
                data = q.get(timeout=60)
                yield f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
                if data.get('event') in ('done', 'error'):
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'event': 'heartbeat'})}\n\n"
                if task['status'] in ('done', 'error'):
                    break

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/result/<task_id>')
def api_result(task_id):
    task = tasks.get(task_id)
    if not task:
        return jsonify({'error': '任务不存在'}), 404
    return jsonify({
        'task_id': task_id,
        'status': task['status'],
        'base_domain': task.get('base_domain', ''),
        'hosts': task.get('hosts', []),
    })


@app.route('/api/download/<task_id>/<fmt>')
def api_download(task_id, fmt):
    task = tasks.get(task_id)
    if not task or task['status'] != 'done':
        return jsonify({'error': '结果未就绪'}), 404

    hosts = task.get('hosts', [])
    base_domain = task.get('base_domain', 'result')
    date_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'{base_domain}_{date_str}.{fmt}'

    filepath = os.path.join(os.path.dirname(__file__), 'output', filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    save_results(hosts, filepath, fmt, base_domain)

    resp = send_file(filepath, as_attachment=True, download_name=filename)
    try:
        os.remove(filepath)
    except OSError:
        pass
    return resp


if __name__ == '__main__':
    print('[*] NetProbe v2.0 - 域名探测 Web 服务启动中...')
    print('[*] 访问 http://127.0.0.1:5000')
    app.run(host='0.0.0.0', port=5000, debug=False)
