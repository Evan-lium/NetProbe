"""CDN 检测 — 通过 HTTP 头特征 + IP 网段库识别资产是否位于 CDN 之后。

两种检测方式:
1. HTTP 头特征: CF-Ray(Cloudflare) / X-Amz-Cf-Id(AWS) / X-Akamai-Transformed 等
2. IP 网段匹配: 检查 host IP 是否落在主流 CDN 的 CIDR 范围内
"""

import ipaddress
import json
import os

# CDN HTTP 头特征 → CDN 名称映射
CDN_HEADERS = {
    'cf-ray': 'Cloudflare',
    'cf-cache-status': 'Cloudflare',
    'x-amz-cf-id': 'AWS CloudFront',
    'x-amz-cf-pop': 'AWS CloudFront',
    'x-akamai-transformed': 'Akamai',
    'x-fastly-request-id': 'Fastly',
    'x-sucuri-id': 'Sucuri',
    'server': None,  # 单独处理（server 头内容多变）
}

# Server 头值特征 → CDN 名称
SERVER_CDN_HINTS = {
    'cloudflare': 'Cloudflare',
    'akamaighost': 'Akamai',
    'sucuri': 'Sucuri',
    'cloudfront': 'AWS CloudFront',
}

# 懒加载的 CDN IP 段库
_cdn_networks = None


def _load_cdn_networks() -> list[tuple[str, ipaddress.IPv4Network]]:
    """加载 cdn_cidrs.json，返回 (cdn_name, network) 列表。"""
    global _cdn_networks
    if _cdn_networks is not None:
        return _cdn_networks

    _cdn_networks = []
    data_path = os.path.join(os.path.dirname(__file__), 'data', 'cdn_cidrs.json')
    try:
        with open(data_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for cdn_name, cidrs in data.items():
            if cdn_name.startswith('_'):
                continue
            for cidr in cidrs:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    _cdn_networks.append((cdn_name, net))
                except ValueError:
                    continue
    except (OSError, json.JSONDecodeError):
        pass
    return _cdn_networks


def detect_cdn_by_headers(headers: dict) -> str:
    """从 HTTP 响应头检测 CDN。返回 CDN 名称或空串。"""
    if not headers:
        return ''
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # 特征头
    for header, cdn in CDN_HEADERS.items():
        if cdn and header in lower_headers:
            return cdn

    # Server 头
    server = (lower_headers.get('server') or '').lower()
    for hint, cdn in SERVER_CDN_HINTS.items():
        if hint in server:
            return cdn

    return ''


def detect_cdn_by_ip(ip: str) -> str:
    """检查 IP 是否落在已知 CDN 网段内。返回 CDN 名称或空串。"""
    if not ip:
        return ''
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ''

    for cdn_name, network in _load_cdn_networks():
        if addr in network:
            return cdn_name
    return ''


def detect_cdn(ip: str, headers: dict) -> str:
    """综合检测 CDN（HTTP 头优先，回退 IP 网段）。返回 CDN 名称或空串。"""
    cdn = detect_cdn_by_headers(headers)
    if cdn:
        return cdn
    return detect_cdn_by_ip(ip)
