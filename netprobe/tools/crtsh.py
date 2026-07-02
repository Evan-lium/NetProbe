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


def query_crtsh_certificates(domain: str, timeout: int = 30) -> list[dict]:
    """从 crt.sh 拉取证书透明度日志，保留完整证书元数据。

    相比 query_crtsh（仅返回 hostname、丢弃通配符），本函数:
    - 保留证书层信息（issuer / not_before / not_after / serial）
    - 不跳过通配符（标记 wildcard=True），通配符证书是重要关联线索
    - 把 name_value 里的 SAN（\\n 分隔）完整展开

    返回: [{'hostname', 'source': 'crt.sh', 'issuer', 'not_before', 'not_after',
            'serial', 'wildcard'}, ...]（按 hostname 去重）
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
            issuer = (entry.get('issuer_name') or '').strip()
            not_before = (entry.get('not_before') or '').strip()
            not_after = (entry.get('not_after') or '').strip()
            serial = (entry.get('serial_number') or '').strip()

            for name in name_value.split('\n'):
                name = name.strip().lower().rstrip('.')
                if not name:
                    continue
                # 只保留属于目标域名的
                if name != domain and not name.endswith('.' + domain):
                    continue
                wildcard = name.startswith('*')
                # 通配符记录作为线索保留，但去重键用规范化名
                dedup_key = name
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                results.append({
                    'hostname': name,
                    'source': 'crt.sh',
                    'issuer': issuer,
                    'not_before': not_before,
                    'not_after': not_after,
                    'serial': serial,
                    'wildcard': wildcard,
                })

        return results

    except (requests.RequestException, json.JSONDecodeError, ValueError):
        return []
