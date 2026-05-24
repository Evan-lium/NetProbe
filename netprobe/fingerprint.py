"""Web 技术栈指纹识别 — 基于本地指纹库分析 HTTP 响应。"""

import json
import re
from pathlib import Path

# ── 指纹规则 ──────────────────────────────────────────
# 每条规则: {name, category, patterns: [{type, pattern}]}
# type: header / html / cookie / meta / script_src / status_code
# pattern: 字符串(包含匹配) 或 正则表达式(以 re: 开头)

_DATA_DIR = Path(__file__).parent / 'data'

with open(_DATA_DIR / 'fingerprints.json', encoding='utf-8') as f:
    FINGERPRINTS = json.load(f)


def detect_technologies(resp_headers: dict, html: str, cookies: str) -> list[dict]:
    """从 HTTP 响应中检测 Web 技术栈。

    参数:
        resp_headers: HTTP 响应头 dict (小写 key)
        html: HTML 正文
        cookies: Set-Cookie 头的值

    返回: [{'name': str, 'category': str}, ...]
    """
    html_lower = html.lower() if html else ''
    headers_lower = {k.lower(): v.lower() for k, v in resp_headers.items()} if resp_headers else {}
    cookies_lower = cookies.lower() if cookies else ''

    # 提取 script src
    script_srcs = []
    if html:
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            script_srcs.append(m.group(1).lower())

    # 提取 meta 标签
    meta_content = ''
    if html:
        meta_tags = re.findall(r'<meta[^>]+content=["\']([^"\']*)["\']', html, re.IGNORECASE)
        meta_content = ' '.join(meta_tags).lower()
        meta_names = re.findall(r'<meta[^>]+name=["\']([^"\']*)["\']', html, re.IGNORECASE)
        meta_content += ' ' + ' '.join(meta_names).lower()
        # generator meta
        gen_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']*)["\']', html, re.IGNORECASE)
        if gen_match:
            meta_content += ' ' + gen_match.group(1).lower()

    detected = []
    seen = set()

    for fp in FINGERPRINTS:
        for pat in fp['patterns']:
            if _match_pattern(pat, headers_lower, html_lower, cookies_lower, script_srcs, meta_content):
                key = fp['name']
                if key not in seen:
                    seen.add(key)
                    detected.append({'name': fp['name'], 'category': fp['category']})
                break

    return detected


def _match_pattern(pat, headers, html, cookies, script_srcs, meta) -> bool:
    ptype = pat['type']
    pattern = pat['pattern']
    is_regex = pattern.startswith('re:')
    search_str = pattern[3:] if is_regex else pattern.lower()

    if ptype == 'header':
        for k, v in headers.items():
            combined = f'{k}: {v}'
            if is_regex:
                if re.search(search_str, combined, re.IGNORECASE):
                    return True
            elif search_str in combined:
                return True
        return False

    if ptype == 'html':
        if is_regex:
            return bool(re.search(search_str, html, re.IGNORECASE))
        return search_str in html

    if ptype == 'cookie':
        if is_regex:
            return bool(re.search(search_str, cookies, re.IGNORECASE))
        return search_str in cookies

    if ptype == 'meta':
        if is_regex:
            return bool(re.search(search_str, meta, re.IGNORECASE))
        return search_str in meta

    if ptype == 'script_src':
        for src in script_srcs:
            if is_regex:
                if re.search(search_str, src, re.IGNORECASE):
                    return True
            elif search_str in src:
                return True
        return False

    return False
