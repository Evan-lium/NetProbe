"""指纹技术栈 → CVE 关联模块。

指纹识别出技术栈+版本后，查询漏洞数据库关联已知 CVE，
作为 category=cve_fingerprint 的漏洞追加到 host['vulnerabilities']。

数据源（按优先级尝试）:
  1. OSV API (api.osv.dev) — Google 维护，国内可访问，无 key 无限速
  2. NVD API — 备用（国内可能 SSL 不稳定）

特性:
  - 本地缓存（data/cve_cache.json，TTL 7天）避免重复查询
  - 只对有 version 的技术查询
  - 严格过滤：只保留有 CVE ID 的真实安全漏洞
  - 每个技术栈最多返回 5 条 CVE
"""
import json
import os
import re
import time
from datetime import datetime, timedelta

_CACHE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'data', 'cve_cache.json'
)
_CACHE_TTL_DAYS = 7

# 内部缓存
_cache: dict = {}
_cache_loaded = False

# 产品名映射：指纹名 → OSV/NVD 查询名
_PRODUCT_MAP = {
    'wordpress': 'wordpress',
    'php': 'php',
    'nginx': 'nginx',
    'apache': 'apache_httpd',
    'apache http server': 'apache_httpd',
    'tomcat': 'tomcat',
    'drupal': 'drupal',
    'joomla': 'joomla',
    'mysql': 'mysql',
    'redis': 'redis',
    'postgresql': 'postgresql',
    'node.js': 'node',
    'nodejs': 'node',
    'django': 'django',
    'flask': 'flask',
    'rails': 'rails',
    'ruby on rails': 'rails',
    'jenkins': 'jenkins',
    'gitlab': 'gitlab',
    'struts': 'struts',
    'struts2': 'struts2',
    'spring': 'spring_framework',
    'spring boot': 'spring_boot',
    'openssl': 'openssl',
    'iis': 'iis',
    'openresty': 'openresty',
}


def _load_cache():
    global _cache, _cache_loaded
    if _cache_loaded:
        return
    try:
        if os.path.exists(_CACHE_PATH):
            with open(_CACHE_PATH, encoding='utf-8') as f:
                _cache = json.load(f)
    except (json.JSONDecodeError, OSError):
        _cache = {}
    _cache_loaded = True


def _save_cache():
    try:
        os.makedirs(os.path.dirname(_CACHE_PATH), exist_ok=True)
        with open(_CACHE_PATH, 'w', encoding='utf-8') as f:
            json.dump(_cache, f, ensure_ascii=False)
    except OSError:
        pass


def _get_cached(key: str) -> list | None:
    _load_cache()
    entry = _cache.get(key)
    if not entry:
        return None
    cached_at = datetime.fromisoformat(entry['cached_at'])
    if datetime.utcnow() - cached_at > timedelta(days=_CACHE_TTL_DAYS):
        return None
    return entry.get('data', [])


def _set_cached(key: str, data: list):
    _cache[key] = {'cached_at': datetime.utcnow().isoformat(), 'data': data}
    _save_cache()


def _extract_cve_id(vuln: dict) -> str:
    """从 OSV 漏洞对象提取 CVE ID。"""
    # 直接 ID 就是 CVE
    vid = vuln.get('id', '')
    if vid.startswith('CVE-'):
        return vid
    # 从 aliases 找
    for alias in vuln.get('aliases', []):
        if alias.startswith('CVE-'):
            return alias
    # 从 references 找
    for ref in vuln.get('references', []):
        url = ref.get('url', '')
        m = re.search(r'(CVE-\d{4}-\d+)', url)
        if m:
            return m.group(1)
    return ''


def _extract_cvss(vuln: dict) -> tuple:
    """提取 CVSS 分数和严重性。返回 (score, severity)。"""
    # OSV severity 数组
    for s in vuln.get('severity', []):
        score_str = s.get('score', '')
        # CVSS vector string: "CVSS:3.1/AV:N/..."
        if score_str.startswith('CVSS:'):
            score = _parse_cvss_vector(score_str)
            if score > 0:
                return score, _cvss_to_severity(score)
        # 纯数字
        try:
            score = float(score_str)
            if score > 0:
                return score, _cvss_to_severity(score)
        except ValueError:
            pass
    # database_specific
    ds = vuln.get('database_specific', {})
    sev = ds.get('severity', '')
    if sev:
        sev_lower = sev.lower()
        score_map = {'critical': 9.0, 'high': 7.5, 'medium': 5.0, 'low': 2.5, 'moderate': 5.0}
        return score_map.get(sev_lower, 5.0), sev_lower
    return 0.0, 'medium'


def _parse_cvss_vector(vector: str) -> float:
    """从 CVSS v3 向量字符串估算分数。"""
    # 简化估算：基于攻击向量和网络复杂度
    score = 5.0  # 基础分
    if 'AV:N' in vector:
        score = 7.5
    elif 'AV:A' in vector:
        score = 5.0
    if 'C:H' in vector or 'I:H' in vector:
        score = max(score, 8.0)
    if 'PR:N' in vector:
        score += 0.5
    return min(score, 10.0)


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return 'critical'
    if score >= 7.0:
        return 'high'
    if score >= 4.0:
        return 'medium'
    return 'low'


def _is_security_related(vuln: dict) -> bool:
    """判断漏洞是否是安全相关的（过滤掉普通 bug 修复/版本更新）。"""
    # 有 CVE ID 的一定是安全相关
    if _extract_cve_id(vuln):
        return True
    # 检查 database_specific.categories
    ds = vuln.get('database_specific', {})
    cats = ds.get('categories', [])
    if cats:
        return True
    # summary 里包含安全关键词
    summary = (vuln.get('summary') or '').lower()
    for kw in ('vulnerability', 'security', 'exploit', 'xss', 'rce', 'sql injection',
               'remote code', 'privilege escalation', 'denial of service', 'bypass',
               'overflow', 'injection', 'csrf', 'traversal'):
        if kw in summary:
            return True
    return False


def _query_osv(product: str, version: str) -> list[dict]:
    """查 OSV API。"""
    import requests
    try:
        resp = requests.post(
            'https://api.osv.dev/v1/query',
            json={'version': version, 'package': {'name': product}},
            timeout=20,
            headers={'User-Agent': 'NetProbe/3.0'},
        )
        if resp.status_code != 200:
            return []
        vulns = resp.json().get('vulns', [])
    except Exception:
        return []

    results = []
    seen_cves = set()
    for vuln in vulns:
        # 过滤非安全相关
        if not _is_security_related(vuln):
            continue
        cve_id = _extract_cve_id(vuln)
        if not cve_id:
            continue  # 无 CVE ID 的跳过（保持数据质量）
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        score, severity = _extract_cvss(vuln)
        summary = (vuln.get('summary') or vuln.get('details', ''))[:200]

        results.append({
            'cve_id': cve_id,
            'description': summary,
            'cvss_score': score,
            'severity': severity,
        })

    # 按 CVSS 降序，取前 5
    results.sort(key=lambda x: -(x.get('cvss_score') or 0))
    return results[:5]


def _query_nvd_fallback(product: str, version: str) -> list[dict]:
    """NVD 备用查询。"""
    from .tools.nvd import query_nvd
    try:
        cves = query_nvd(f'{product} {version}')
        return [{
            'cve_id': c.get('cve_id', ''),
            'description': c.get('description', ''),
            'cvss_score': c.get('cvss_score', 0),
            'severity': c.get('severity', 'medium'),
        } for c in cves[:5] if c.get('cve_id')]
    except Exception:
        return []


def match_tech_to_cves(tech_list: list[dict]) -> list[dict]:
    """遍历指纹技术栈，对有 version 的查询关联 CVE。

    返回: 可直接追加到 host['vulnerabilities'] 的漏洞列表。
    """
    # 过滤出有效候选
    candidates = []
    for tech in tech_list:
        name = (tech.get('name') or '').strip().lower()
        version = (tech.get('version') or '').strip()
        if not name or not version or len(version) < 2 or version.isalpha():
            continue
        # 映射产品名
        mapped = _PRODUCT_MAP.get(name, name)
        candidates.append((name, version, mapped))

    if not candidates:
        return []

    results = []
    seen_cves = set()

    for orig_name, version, mapped_name in candidates:
        query_key = f'{mapped_name}:{version}'

        # 查缓存
        cached = _get_cached(query_key)
        if cached is not None:
            cves = cached
        else:
            # 先查 OSV，失败用 NVD
            cves = _query_osv(mapped_name, version)
            if not cves:
                cves = _query_nvd_fallback(mapped_name, version)
            _set_cached(query_key, cves)

        if not cves:
            continue

        for cve in cves:
            cve_id = cve.get('cve_id', '')
            if not cve_id or cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

            results.append({
                'name': f'{orig_name} {version}: {cve_id}',
                'severity': cve.get('severity', 'medium'),
                'cve': cve_id,
                'cvss_score': str(cve.get('cvss_score', 0)),
                'cwe': '',
                'category': 'cve_fingerprint',
                'template_id': '',
                'url': '',
                'matched_at': f'{orig_name} {version}',
                'description': cve.get('description', ''),
            })

    return results
