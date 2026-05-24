"""Banner 抓取 — 对非 HTTP 服务获取 banner 指纹信息。"""

import socket
import struct

# 支持 banner 抓取的服务端口和协议
BANNER_PORTS = {
    21: ('ftp', b'220'),
    22: ('ssh', None),
    25: ('smtp', b'220'),
    110: ('pop3', b'+OK'),
    143: ('imap', b'* OK'),
    3306: ('mysql', None),
    5432: ('postgresql', None),
    6379: ('redis', None),
    27017: ('mongodb', None),
}

BANNER_TIMEOUT = 5


def grab_banner(ip: str, port: int) -> dict:
    """对指定 IP:端口抓取 banner。

    返回 {'port': int, 'service': str, 'banner': str}
    """
    service = BANNER_PORTS.get(port, (str(port), None))[0]
    service = service if isinstance(service, str) else str(port)

    banner = ''
    try:
        with socket.create_connection((ip, port), timeout=BANNER_TIMEOUT) as sock:
            # 某些服务需要等待 banner（FTP、SSH、SMTP 会主动发送）
            # MySQL/Redis 等需要发送探针
            if port == 3306:
                # MySQL 握手包
                data = sock.recv(4096)
                banner = _parse_mysql_banner(data)
            elif port == 6379:
                sock.sendall(b'INFO\r\n')
                data = sock.recv(4096)
                banner = _parse_redis_info(data)
            elif port == 27017:
                try:
                    import bson as _bson
                except ImportError:
                    banner = 'MongoDB'
                    return {'port': port, 'service': service, 'banner': banner}
                ismaster = _bson.BSON.encode({'ismaster': 1, 'helloOk': True})
                header = struct.pack('<iiii', 16 + len(ismaster), 0, 0, 1)
                sock.sendall(header + ismaster)
                data = sock.recv(4096)
                banner = _parse_mongo_info(data)
            else:
                # FTP/SSH/SMTP/POP3/IMAP 会主动发送 banner
                data = sock.recv(4096)
                if data:
                    banner = data.decode('utf-8', errors='replace').strip()[:500]
    except (socket.timeout, socket.error, OSError):
        pass

    return {'port': port, 'service': service, 'banner': banner}


def grab_banners_for_host(ip: str, open_ports: list[int]) -> list[dict]:
    """对主机的所有开放端口批量抓取 banner。"""
    results = []
    for port in open_ports:
        # 跳过 Web 端口（已由 web_probe 处理）
        if port in (80, 443, 8080, 8443, 8000, 3000, 5000, 9000,
                    8888, 9090, 7001, 8880, 8001, 8002, 10000, 4000, 6000):
            continue
        info = grab_banner(ip, port)
        if info.get('banner'):
            results.append(info)
    return results


def _parse_mysql_banner(data: bytes) -> str:
    """解析 MySQL 握手包中的版本信息。"""
    try:
        if len(data) < 5:
            return ''
        # MySQL 协议：前几个字节是包长度和编号，第 5 字节开始是版本字符串
        version_end = data.find(b'\0', 5)
        if version_end > 0:
            version = data[5:version_end].decode('utf-8', errors='replace')
            return f'MySQL {version}'
    except Exception:
        pass
    return data.decode('utf-8', errors='replace').strip()[:200]


def _parse_redis_info(data: bytes) -> str:
    """解析 Redis INFO 响应。"""
    try:
        text = data.decode('utf-8', errors='replace')
        for line in text.splitlines():
            if line.startswith('redis_version:'):
                return f'Redis {line.split(":")[1].strip()}'
        return 'Redis (version unknown)'
    except Exception:
        return ''


def _parse_mongo_info(data: bytes) -> str:
    """解析 MongoDB ismaster 响应。"""
    try:
        import bson as _bson
        if len(data) < 16:
            return ''
        msg_len = struct.unpack('<i', data[0:4])[0]
        body = data[16:msg_len]
        doc = _bson.BSON(body).decode()
        version = doc.get('version', '')
        if version:
            return f'MongoDB {version}'
        return 'MongoDB'
    except Exception:
        return 'MongoDB'
