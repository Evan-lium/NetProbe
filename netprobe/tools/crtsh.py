"""crt.sh 证书透明度日志查询 — 被动子域名收集。"""

import json
import requests

CRTSH_URL = 'https://crt.sh/?q=%25.{}&output=json'
REQUEST_TIMEOUT = 30


def query_crtsh(domain: str, timeout: int = 30) -> list[dict]:
    """从 crt.sh 证书透明度日志中查询域名的子域名。

    返回: [{'hostname': str, 'source': 'crt.sh'}, ...]
    """
    try:
        url = CRTSH_URL.format(domain)
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return []

        entries = resp.json()
        if not isinstance(entries, list):
            return []

        seen = set()
        results = []
        for entry in entries:
            name_value = entry.get('name_value', '')
            for name in name_value.split('\n'):
                name = name.strip().lower().rstrip('.')
                # 跳过通配符和空值
                if not name or name.startswith('*'):
                    continue
                # 只保留属于目标域名的
                if name == domain or name.endswith('.' + domain):
                    if name not in seen:
                        seen.add(name)
                        results.append({'hostname': name, 'source': 'crt.sh'})

        return results

    except (requests.RequestException, json.JSONDecodeError, ValueError):
        return []
