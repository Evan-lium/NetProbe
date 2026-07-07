"""Web 技术栈指纹识别 — 基于本地指纹库分析 HTTP 响应。

支持:
- 6 种 pattern 类型: header / html / cookie / meta / script_src / status_code
- 正则匹配 (pattern 以 re: 开头)
- 版本号提取 (pattern 可选 version 字段，正则提取)
- 置信度评分 (按 pattern 来源类型加权)
- implies 关联推断 (Wappalyzer 风格: 命中 WordPress → 推断 PHP)
"""

import json
import re
from pathlib import Path

# ── 指纹规则 ──────────────────────────────────────────
# 每条规则: {name, category, patterns: [{type, pattern, version?}]}
# type: header / html / cookie / meta / script_src / status_code
# pattern: 字符串(包含匹配) 或 正则表达式(以 re: 开头)
# version (可选): 版本提取正则(以 re: 开头)，第 1 捕获组为版本号

_DATA_DIR = Path(__file__).parent / 'data'

with open(_DATA_DIR / 'fingerprints.json', encoding='utf-8') as f:
    FINGERPRINTS = json.load(f)

# ── implies 索引：name → (implies_list, category) ──
# Wappalyzer 风格的关联推断：识别到某技术后，按其 implies 字段补全关联技术。
# 例: WordPress implies ["PHP"] —— 命中 WordPress 后额外推断出 PHP。
_IMPLIES_INDEX: dict[str, tuple[list[str], str]] = {
    fp['name']: (fp.get('implies', []) or [], fp['category'])
    for fp in FINGERPRINTS
}

# implies 推断出的技术置信度（低于直接命中的 60-90，体现「非直接证据」）
IMPLY_CONFIDENCE = 50

# ── pattern 类型 → 置信度（命中来源越接近服务端真实标识，置信度越高）──
# header:  服务端显式声明 (Server/X-Powered-By)，最可靠
# cookie:  框架特征 session 名 (JSESSIONID/PHPSESSID)，可靠
# meta:    generator meta 标签，较可靠（可伪造但少见）
# script_src: JS 库路径，较可靠
# status_code: HTTP 状态码特征，一般
# html:    页面内容匹配，最易误报（可能只是提到产品名）
PATTERN_CONFIDENCE = {
    'header': 90,
    'cookie': 85,
    'meta': 80,
    'script_src': 75,
    'status_code': 70,
    'html': 60,
}


def detect_technologies(
    resp_headers: dict,
    html: str,
    cookies: str,
    status_code: int = 0,
) -> list[dict]:
    """从 HTTP 响应中检测 Web 技术栈。

    参数:
        resp_headers: HTTP 响应头 dict (key 大小写不限)
        html: HTML 正文
        cookies: Set-Cookie 头的值
        status_code: HTTP 状态码（用于 status_code pattern）

    返回: [{'name': str, 'category': str, 'version': str, 'confidence': int}, ...]
          version 为空串表示未提取到；confidence 为 0-100。
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
        # generator meta（含版本的高价值来源）
        gen_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']*)["\']', html, re.IGNORECASE)
        if gen_match:
            meta_content += ' ' + gen_match.group(1).lower()

    # 预提取各 pattern 类型对应的"原始文本"（用于版本正则提取，需保留大小写）
    raw_texts = {
        'header': '\n'.join(f'{k}: {v}' for k, v in (resp_headers or {}).items()),
        'html': html or '',
        'cookie': cookies or '',
        'meta': meta_content,
        'script_src': '\n'.join(script_srcs),
    }

    detected = []
    seen = set()

    for fp in FINGERPRINTS:
        best = None  # 该规则命中的最优结果（最高置信度 + 版本）
        match_count = 0  # 该规则命中了几个 pattern
        has_precise = False  # 是否有精确匹配（header/cookie/script_src/meta）

        for pat in fp['patterns']:
            matched, match_type = _match_pattern(
                pat, headers_lower, html_lower, cookies_lower,
                script_srcs, meta_content, status_code,
            )
            if not matched:
                continue
            match_count += 1
            if match_type in ('header', 'cookie', 'script_src', 'meta'):
                has_precise = True
            confidence = PATTERN_CONFIDENCE.get(match_type, 50)
            # 提取版本（如有 version 正则）
            version = ''
            version_re = pat.get('version', '')
            if version_re:
                version = _extract_version(version_re, raw_texts.get(match_type, ''))
                # 当前 pattern 文本提取失败 → 在所有文本上兜底尝试
                if not version:
                    for txt in raw_texts.values():
                        version = _extract_version(version_re, txt)
                        if version:
                            break
            cand = {'confidence': confidence, 'version': version, 'type': match_type}
            if best is None or _better(cand, best):
                best = cand

        # 精度过滤：只有 html 匹配（无 header/cookie/script_src/meta 精确匹配）的规则
        # → 降置信度到 50（被后面的 ≥50 过滤 + Top30 排序淘汰大部分）
        if best is not None and not has_precise:
            best['confidence'] = min(best['confidence'], 50)

        if best is not None:
            key = fp['name']
            if key not in seen:
                seen.add(key)
                detected.append({
                    'name': fp['name'],
                    'category': fp['category'],
                    'version': best['version'],
                    'confidence': best['confidence'],
                })

    # implies 传递闭包扩展：根据已命中技术的 implies 字段推断关联技术。
    # 例: 命中 WordPress → 推断 PHP。推断出的技术 confidence 标 50，version 为空。
    _apply_implies(detected, seen)

    # 结果过滤：宁少不误报
    # 排序：有版本号优先 > 置信度高
    detected.sort(key=lambda x: (
        1 if x.get('version') else 0,
        -(x.get('confidence', 0) or 0),
    ), reverse=True)
    # 必须有版本号（精确提取到了，不会误报）或 置信度 >= 90（header 强匹配）
    # 80% 的 meta/script_src 和 60% 的 html 匹配都过滤掉（误报率高）
    detected = [d for d in detected
                if d.get('version') or (d.get('confidence', 0) or 0) >= 90][:15]

    # 近义名称合并：Nginx/Nginx version、Apache/Apache HTTP Server 等归一化
    detected = _merge_synonyms(detected)

    return detected


def _normalize_name(name: str) -> str:
    """产品名归一化，用于近义合并。
    去掉 version/detect/server 等后缀，统一大小写。
    """
    n = name.strip().lower()
    # 去掉常见后缀
    for suffix in (' version', '- version', ' detect', '- detect',
                   ' detection', ' http server', ' web server',
                   ' detection panel', ' panel'):
        if n.endswith(suffix):
            n = n[:-len(suffix)]
    # 统一连字符
    n = n.replace('_', ' ').replace('-', ' ')
    # 合并多空格
    n = ' '.join(n.split())
    return n


def _merge_synonyms(detected: list[dict]) -> list[dict]:
    """合并近义名称的检测结果。
    规则：归一化后同名的，保留置信度最高（或带版本号）的一条。
    """
    # 显式近义映射（手工维护，处理特殊情况）
    SYNONYMS = {
        'php fpm': 'php',
        'apache httpd': 'apache',
        'nginx web server': 'nginx',
        'mariadb server': 'mariadb',
    }
    groups = {}  # normalized → [list of items]
    order = []
    for item in detected:
        norm = _normalize_name(item['name'])
        norm = SYNONYMS.get(norm, norm)
        if norm not in groups:
            groups[norm] = []
            order.append(norm)
        groups[norm].append(item)

    result = []
    for norm in order:
        items = groups[norm]
        if len(items) == 1:
            result.append(items[0])
            continue
        # 多条：优先选有版本的，其次置信度高的
        items.sort(key=lambda x: (
            1 if x.get('version') else 0,
            -(x.get('confidence', 0) or 0),
        ), reverse=True)
        result.append(items[0])
    return result


def _apply_implies(detected: list[dict], seen: set[str]) -> None:
    """对已检测到的技术做 implies 传递闭包扩展（原地追加）。

    遍历已命中技术的 implies 列表，将未直接命中的关联技术补全到结果里。
    传递闭包：A implies B, B implies C → 也会补出 C（直到无新增）。
    已直接命中的技术不覆盖（保留其原始置信度与版本）。
    """
    if not detected:
        return
    # 工作队列：从当前已命中技术出发，逐层扩展
    queue = list(detected)
    i = 0
    while i < len(queue):
        name = queue[i]['name']
        i += 1
        implies_list, _category = _IMPLIES_INDEX.get(name, ([], ''))
        for implied_name in implies_list:
            if not implied_name or implied_name in seen:
                continue
            seen.add(implied_name)
            # 推断出的技术：category 取其自身规则定义的 category（若有），否则标 'Implied'
            implied_category = _IMPLIES_INDEX.get(implied_name, ([], 'Implied'))[1] or 'Implied'
            entry = {
                'name': implied_name,
                'category': implied_category,
                'version': '',
                'confidence': IMPLY_CONFIDENCE,
            }
            detected.append(entry)
            queue.append(entry)  # 继续传递（B implies C）


def _better(a: dict, b: dict) -> bool:
    """比较两个命中结果，a 是否优于 b。
    优先级：有版本 > 无版本；版本号更完整（段数多）优先；最后高置信度。
    例：8.5.51(3段) 优于 1.1(2段)。
    """
    av, bv = a.get('version', ''), b.get('version', '')
    if bool(av) != bool(bv):
        return bool(av)
    if av and bv:
        # 比较版本段数（更完整的版本号通常更准确）
        a_segs = len(av.split('.'))
        b_segs = len(bv.split('.'))
        if a_segs != b_segs:
            return a_segs > b_segs
    return a['confidence'] > b['confidence']


def _safe_search(pattern: str, text: str) -> bool:
    """安全的正则搜索，编译失败或超时返回 False。

    nuclei/Go 的 RE2 语法与 Python re 略有差异（如未闭合分组），
    需要容错避免整个识别流程崩溃。
    """
    if not text:
        return False
    try:
        return bool(re.search(pattern, text, re.IGNORECASE))
    except (re.error, Exception):
        return False


def _match_pattern(pat, headers, html, cookies, script_srcs, meta, status_code) -> tuple[bool, str]:
    """匹配单个 pattern。返回 (是否命中, 命中的 pattern type)。

    成功时第二个返回值是该 pattern 的 type（用于置信度计算与版本提取定位）。
    """
    ptype = pat['type']
    pattern = pat['pattern']
    is_regex = pattern.startswith('re:')
    search_str = pattern[3:] if is_regex else pattern.lower()

    if ptype == 'header':
        for k, v in headers.items():
            combined = f'{k}: {v}'
            if is_regex:
                if _safe_search(search_str, combined):
                    return True, ptype
            elif search_str in combined:
                return True, ptype
        return False, ptype

    if ptype == 'html':
        if is_regex:
            return _safe_search(search_str, html), ptype
        return search_str in html, ptype

    if ptype == 'cookie':
        if is_regex:
            return _safe_search(search_str, cookies), ptype
        return search_str in cookies, ptype

    if ptype == 'meta':
        if is_regex:
            return _safe_search(search_str, meta), ptype
        return search_str in meta, ptype

    if ptype == 'script_src':
        for src in script_srcs:
            if is_regex:
                if _safe_search(search_str, src):
                    return True, ptype
            elif search_str in src:
                return True, ptype
        return False, ptype

    if ptype == 'status_code':
        # 支持 "200" / "200,301,302" / "2xx"（通配）
        codes = str(pattern).strip()
        if not codes or not status_code:
            return False, ptype
        for code in codes.split(','):
            code = code.strip().lower()
            if 'x' in code:
                # 通配：2xx / 3xx / 4xx / 5xx
                prefix = code[0]
                if str(status_code)[0] == prefix:
                    return True, ptype
            elif str(status_code) == code:
                return True, ptype
        return False, ptype

    return False, ptype


def _extract_version(version_re: str, text: str) -> str:
    """从 text 中用正则提取版本号。返回版本字符串或空串。

    支持两种前缀：
      re:XXX   — 正则，第 1 个捕获组为版本号（无捕获组则用整个匹配）
      kval:Header-Name — 从指定 HTTP header 字段的值提取版本
                         text 应为 "Key: Value\\nKey2: Value2" 格式
    """
    if not text:
        return ''
    # kval: 从指定 header 字段提取整个值作为版本
    if version_re.startswith('kval:'):
        field = version_re[5:].strip().lower()
        for line in text.splitlines():
            if ':' not in line:
                continue
            k, v = line.split(':', 1)
            if k.strip().lower() == field:
                # 取值里的版本部分（如 nginx/1.18.0 → 1.18.0）
                v = v.strip()
                vm = re.search(r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)', v)
                if vm:
                    return vm.group(1)
                # 没有数字版本号 → 返回空（避免把 "Apache" 当版本）
                return ''
        return ''
    # re: 正则提取
    pattern = version_re[3:] if version_re.startswith('re:') else version_re
    try:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            # 优先用捕获组，无捕获组则用整个匹配
            version = m.group(1) if m.groups() else m.group(0)
            return version.strip()[:32]  # 截断防异常长串
    except re.error:
        pass
    return ''
