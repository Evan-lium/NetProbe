"""子域名接管检测 — 检测 CNAME 指向已失效 SaaS 服务的 dangling DNS 记录。

流程: 对每个 hostname 查 CNAME → 若指向已知 SaaS 域 → HTTP 探测确认
「服务不存在」特征 → 标记为可接管。

参考 sensitive_probe.py 的规则库加载模式 + netprobe/dns_utils.resolve_dns_records。
"""

import json
import os

import requests

from .dns_utils import resolve_dns_records

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
_FINGERPRINTS_FILE = os.path.join(_DATA_DIR, 'takeover_fingerprints.json')
_REQUEST_TIMEOUT = 8


def _load_fingerprints() -> list[dict]:
    """加载 SaaS 服务接管指纹库。"""
    try:
        with open(_FINGERPRINTS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []


def detect_takeover_for_hosts(hosts: list[dict]) -> int:
    """对主机列表做子域名接管检测。

    命中可接管的子域名会追加到 host['sensitive'] 列表（severity=high），
    返回发现的可接管子域名数量。
    """
    fingerprints = _load_fingerprints()
    if not fingerprints:
        return 0

    found = 0
    for host in hosts:
        hostname = host.get('hostname', '')
        if not hostname:
            continue

        # 查 CNAME
        cnames = resolve_dns_records(hostname, 'CNAME')
        if not cnames:
            continue

        for cname in cnames:
            cname_lower = cname.lower().rstrip('.')
            # 匹配 SaaS 服务
            matched = None
            for fp in fingerprints:
                pattern = fp.get('cname_pattern', '').lower()
                if pattern and pattern in cname_lower:
                    matched = fp
                    break

            if not matched:
                continue

            # HTTP 探测确认「服务不存在」
            if _confirm_takeover(hostname, matched):
                host.setdefault('sensitive', []).append({
                    'path': f'{hostname} (CNAME → {cname_lower})',
                    'description': f'子域名接管风险: {matched["service"]} 服务已失效，CNAME 指向未注册资源',
                    'severity': matched.get('severity', 'high'),
                    'status_code': matched.get('http_status', 404),
                })
                found += 1

    return found


def _confirm_takeover(hostname: str, fingerprint: dict) -> bool:
    """HTTP 探测确认 SaaS 服务「不存在」特征。"""
    indicator = fingerprint.get('http_indicator', '')
    if not indicator:
        return False

    for scheme in ('https', 'http'):
        try:
            resp = requests.get(
                f'{scheme}://{hostname}',
                timeout=_REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=False,
                headers={'User-Agent': 'Mozilla/5.0'},
            )
            # 匹配状态码或响应体特征
            if resp.status_code == fingerprint.get('http_status', 404):
                if indicator.lower() in resp.text.lower():
                    return True
            # 即使状态码不匹配，响应体含特征也判定
            if indicator.lower() in resp.text.lower()[:5000]:
                return True
        except requests.RequestException:
            continue

    return False
