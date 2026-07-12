"""端口弱口令爆破 — 对开放的服务端口做弱口令检测。

不依赖 hydra 等外部二进制，纯 Python 实现 SSH / MySQL / Redis / FTP / PostgreSQL
登录验证。各协议库均为可选（paramiko / pymysql 未安装则跳过该协议，不影响其他）。

容错策略：任何协议/网络异常均不抛出，返回空结果；库缺失打印提示但不中断。
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ── 协议→默认端口映射 ─────────────────────────────────────────
SERVICE_BY_PORT = {
    21: 'ftp',
    22: 'ssh',
    3306: 'mysql',
    5432: 'postgresql',
    6379: 'redis',
}

# 高危服务端口（在这些端口上自动触发爆破）
HIGH_RISK_PORTS = set(SERVICE_BY_PORT.keys())

# 网络连接超时（秒）；协议握手通常很快，给短超时避免拖慢
_CONNECT_TIMEOUT = 6
# 单个协议登录尝试的并发数
_MAX_WORKERS = 8

# ── 内置常见用户名 / 密码表（top 10×10，覆盖最常见弱口令）──
COMMON_USERS = [
    'root', 'admin', 'test', 'user', 'guest',
    'ubuntu', 'mysql', 'postgres', 'redis', 'ftp',
]

COMMON_PASSWORDS = [
    '', '123456', 'password', 'admin', 'root',
    '123456789', '12345678', '1234567890', 'admin123', 'root123',
]


# ── 协议级登录验证 ─────────────────────────────────────────────
# 每个函数返回 True 表示登录成功（弱口令命中），False/异常表示失败

def _try_ssh(ip: str, port: int, user: str, password: str) -> bool:
    """用 paramiko 尝试 SSH 登录。paramiko 未安装返回 False。"""
    try:
        import paramiko
    except ImportError:
        return False
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            ip, port=port, username=user, password=password,
            timeout=_CONNECT_TIMEOUT, allow_agent=False, look_for_keys=False,
        )
        return True
    except Exception:
        return False
    finally:
        try:
            client.close()
        except Exception:
            pass


def _try_mysql(ip: str, port: int, user: str, password: str) -> bool:
    """用 pymysql 尝试 MySQL 登录。pymysql 未安装时回退到 socket 握手探测。"""
    try:
        import pymysql
    except ImportError:
        return _try_mysql_handshake(ip, port, user, password)
    try:
        conn = pymysql.connect(
            host=ip, port=port, user=user, password=password,
            connect_timeout=_CONNECT_TIMEOUT,
        )
        conn.close()
        return True
    except Exception:
        return False


def _try_mysql_handshake(ip: str, port: int, user: str, password: str) -> bool:
    """无 pymysql 时的兜底：发送 MySQL 协议登录包判断服务响应。

    注：手工拼 MySQL 认证包易因版本/加密失败，这里仅作端口活性兜底，
    实际弱口令确认依赖 pymysql；纯 socket 时返回 False（不误报）。
    """
    return False


def _try_redis(ip: str, port: int, user: str, password: str) -> bool:
    """检测 Redis：无密码可访问或弱密码 AUTH 通过均视为风险。

    返回 True 表示（无密码或弱密码）成功访问。
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(_CONNECT_TIMEOUT)
    try:
        sock.connect((ip, port))
        # 先尝试无密码 PING
        sock.sendall(b'*1\r\n$4\r\nPING\r\n')
        resp = sock.recv(256)
        if b'+PONG' in resp:
            return True
        # 需要密码 → 尝试 AUTH（Redis 6+ 用 ACL 时 user 有意义，旧版忽略 user）
        auth_cmd = f'*2\r\n$4\r\nAUTH\r\n${len(password)}\r\n{password}\r\n' if not user else \
                   f'*3\r\n$4\r\nAUTH\r\n${len(user)}\r\n{user}\r\n${len(password)}\r\n{password}\r\n'
        sock.sendall(auth_cmd.encode())
        resp2 = sock.recv(256)
        if b'+OK' in resp2:
            return True
        return False
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _try_ftp(ip: str, port: int, user: str, password: str) -> bool:
    """用标准库 ftplib 尝试 FTP 登录。"""
    import ftplib
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=_CONNECT_TIMEOUT)
        ftp.login(user, password)
        ftp.quit()
        return True
    except Exception:
        return False


def _try_postgresql(ip: str, port: int, user: str, password: str) -> bool:
    """发送 PostgreSQL 启动消息做活性探测。

    无 psycopg2 时手工实现 StartupMessage + 认证响应判断较复杂且密码需 MD5/SCRAM，
    这里仅做弱口令确认需要 psycopg2；纯 socket 时返回 False（不误报）。
    """
    try:
        import psycopg2  # noqa: F401
    except ImportError:
        return False
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=ip, port=port, user=user, password=password,
            connect_timeout=_CONNECT_TIMEOUT,
        )
        conn.close()
        return True
    except Exception:
        return False


# service → 验证函数
_LOGIN_FUNCS = {
    'ssh': _try_ssh,
    'mysql': _try_mysql,
    'redis': _try_redis,
    'ftp': _try_ftp,
    'postgresql': _try_postgresql,
}


# ── 核心：单服务爆破 ───────────────────────────────────────────

def brute_force_service(ip: str, port: int, service: str,
                        users: list[str] | None = None,
                        passwords: list[str] | None = None) -> list[dict]:
    """对单个服务的开放端口做弱口令爆破。

    参数:
        ip:       目标 IP
        port:     目标端口
        service:  协议类型 (ssh/mysql/redis/ftp/postgresql)
        users:    用户名列表（默认 COMMON_USERS）
        passwords: 密码列表（默认 COMMON_PASSWORDS）

    返回: [{'port', 'service', 'username', 'password', 'note'}, ...]
          成功命中的凭证。Redis 无密码时 note 标注 'no-auth'。
    """
    login = _LOGIN_FUNCS.get(service)
    if login is None:
        return []

    users = users or COMMON_USERS
    passwords = passwords or COMMON_PASSWORDS

    # Redis 特殊处理：先单独探测「无密码可访问」（独立风险项）
    findings: list[dict] = []
    if service == 'redis':
        if _try_redis(ip, port, '', ''):
            findings.append({
                'port': port, 'service': service,
                'username': '', 'password': '', 'note': 'no-auth',
            })
            # 无密码已可访问，无需再试弱口令
            return findings

    # 生成 user×password 组合，并发尝试；命中即停（同协议不继续浪费请求）
    creds = [(u, p) for u in users for p in passwords]
    hit = {'found': False}

    def _attempt(u, p):
        if hit['found']:
            return None
        try:
            if login(ip, port, u, p):
                return (u, p)
        except Exception:
            return None
        return None

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = [pool.submit(_attempt, u, p) for u, p in creds]
        for future in as_completed(futures):
            res = future.result()
            if res:
                hit['found'] = True
                u, p = res
                findings.append({
                    'port': port, 'service': service,
                    'username': u, 'password': p, 'note': 'weak_password',
                })
                break  # 命中一个弱口令即足够证明风险

    return findings


# ── 批量：对所有 hosts 的开放端口做爆破 ───────────────────────

def _normalize_port(port) -> int | None:
    """port 字段可能是 int 或 {'port': int, ...} dict，统一取端口号。"""
    try:
        if isinstance(port, dict):
            return int(port.get('port', 0)) or None
        return int(port) or None
    except (TypeError, ValueError):
        return None


def brute_force_for_hosts(hosts: list[dict], options: dict | None = None) -> None:
    """遍历所有 host 的 ports，对高危服务端口自动触发弱口令爆破。

    结果写入:
      host['_brute_findings'] = [所有尝试命中项]
      host['vulnerabilities'] 追加 severity=high / type=weak_password 的项
      Redis 无密码单独 severity=medium

    受 options['_stage_enabled']['vuln'] 同类开关控制（这里由调用方决定是否调用，
    本函数本身全量执行以保持简单）。
    """
    options = options or {}

    def _host_task(host):
        host_findings = []
        seen_services = set()
        for p in host.get('ports', []):
            port = _normalize_port(p)
            if port is None:
                continue
            service = SERVICE_BY_PORT.get(port)
            if not service:
                continue
            # 同协议（同端口）只跑一次
            key = (port, service)
            if key in seen_services:
                continue
            seen_services.add(key)
            try:
                findings = brute_force_service(host.get('ip', ''), port, service)
            except Exception:
                findings = []
            for f in findings:
                host_findings.append(f)
                vuln = {
                    'name': f'弱口令: {service.upper()} {host.get("ip", "")}:{port}',
                    'severity': 'medium' if f.get('note') == 'no-auth' else 'high',
                    'type': 'weak_password',
                    'category': 'weak_password',
                    'service': service,
                    'port': port,
                    'username': f.get('username', ''),
                    'password': f.get('password', ''),
                    'note': f.get('note', ''),
                }
                host.setdefault('vulnerabilities', []).append(vuln)
        return host, host_findings

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(_host_task, h) for h in hosts]
        for future in as_completed(futures):
            try:
                host, host_findings = future.result()
                host['_brute_findings'] = host_findings
            except Exception:
                # 单个 host 失败不影响其他
                continue
