"""Hunter (奇安信) 网络空间搜索引擎 API 集成。"""

import json
import os

import requests

HUNTER_API = 'https://hunter.qianxin.com/openApi/search'
REQUEST_TIMEOUT = 30


def query_hunter(domain: str, timeout: int = 30) -> list[dict]:
    """通过 Hunter API 查询域名相关资产。

    需要配置环境变量: HUNTER_KEY

    返回: [{'hostname': str, 'ip': str, 'port': int, 'source': 'hunter'}, ...]
    """
    key = os.environ.get('HUNTER_KEY', '')
    if not key:
        return []

    try:
        params = {
            'api-key': key,
            'search': f'domain.suffix="{domain}"',
            'page': 1,
            'page_size': 100,
        }
        resp = requests.get(HUNTER_API, params=params, timeout=timeout)
        data = resp.json()

        if data.get('code') != 200:
            return []

        results = []
        seen = set()
        for item in data.get('data', {}).get('arr', []):
            hostname = item.get('domain', '').lower().rstrip('.')
            ip = item.get('ip', '')
            port = item.get('port', 0)
            if not hostname:
                continue
            if hostname not in seen:
                seen.add(hostname)
                results.append({
                    'hostname': hostname,
                    'ip': ip,
                    'port': int(port) if port else 0,
                    'source': 'hunter',
                    # 威胁情报: Hunter risk_level (1-3, 越高越危险)
                    'risk_level': int(item.get('risk_level', 0)) if item.get('risk_level') else 0,
                })

        return results

    except (requests.RequestException, json.JSONDecodeError, ValueError):
        return []
