"""FOFA 网络空间搜索引擎 API 集成。"""

import base64
import json
import os

import requests

FOFA_API = 'https://fofa.info/api/v1/search/all'
REQUEST_TIMEOUT = 30


def query_fofa(domain: str, timeout: int = 30) -> list[dict]:
    """通过 FOFA API 查询域名相关资产。

    需要配置环境变量: FOFA_EMAIL 和 FOFA_KEY

    返回: [{'hostname': str, 'ip': str, 'port': int, 'protocol': str, 'source': 'fofa'}, ...]
    """
    email = os.environ.get('FOFA_EMAIL', '')
    key = os.environ.get('FOFA_KEY', '')
    if not email or not key:
        return []

    try:
        query = base64.b64encode(f'domain="{domain}"'.encode()).decode()
        params = {
            'email': email,
            'key': key,
            'qbase64': query,
            'size': 100,
            'fields': 'host,ip,port,protocol',
        }
        resp = requests.get(FOFA_API, params=params, timeout=timeout)
        data = resp.json()

        if data.get('error') and data.get('errmsg'):
            return []

        results = []
        seen = set()
        for row in data.get('results', []):
            host, ip, port, protocol = row[0], row[1], row[2], row[3]
            hostname = host.split('://')[-1].split(':')[0].lower().rstrip('.')
            if hostname not in seen:
                seen.add(hostname)
                results.append({
                    'hostname': hostname,
                    'ip': ip,
                    'port': int(port) if port else 0,
                    'protocol': protocol,
                    'source': 'fofa',
                })

        return results

    except (requests.RequestException, json.JSONDecodeError, ValueError, IndexError):
        return []
