"""NVD（National Vulnerability Database）CVE 查询。

通过 NVD API 按产品名/版本查询已知漏洞。
无 key 限速约 5 req/30s，带 NVD_API_KEY 可达 50 req/30s。
"""

import json
import os
import time

import requests

NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
REQUEST_TIMEOUT = 15
# 简易限速: 两次请求间隔至少 6 秒（无 key 时 NVD 限 5 req/30s）
_last_request_time = 0.0
_MIN_INTERVAL = 6.0


def query_nvd(keyword: str, timeout: int = REQUEST_TIMEOUT) -> list[dict]:
    """按关键词（产品名或 CPE）查询 NVD 的 CVE 列表。

    参数:
        keyword: 产品名+版本（如 'openresty 1.29'）或 CPE 字符串
    返回: [{'cve_id', 'description', 'cvss_score', 'severity'}, ...]，失败返回空列表。
    """
    global _last_request_time

    # 限速
    elapsed = time.time() - _last_request_time
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)

    _last_request_time = time.time()

    headers = {'User-Agent': 'NetProbe/3.0'}
    api_key = os.environ.get('NVD_API_KEY', '')
    if api_key:
        headers['apiKey'] = api_key

    try:
        # keywordSearch 适合产品名+版本；若传入 cpe: 则用 cpeName
        if keyword.startswith('cpe:'):
            params = {'cpeName': keyword, 'resultsPerPage': 5}
        else:
            params = {'keywordSearch': keyword, 'resultsPerPage': 5}

        resp = requests.get(NVD_API, params=params, headers=headers, timeout=timeout)
        if resp.status_code != 200:
            return []

        data = resp.json()
        vulnerabilities = data.get('vulnerabilities', [])

        results = []
        for vuln in vulnerabilities:
            cve = vuln.get('cve', {})
            cve_id = cve.get('id', '')

            # 描述（取 en 值）
            description = ''
            for desc in cve.get('descriptions', []):
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')[:200]
                    break

            # CVSS 分数（优先 CVSS v3，回退 v2）
            cvss_score = 0.0
            severity = ''
            metrics = cve.get('metrics', {})
            for cvss_key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                if cvss_key in metrics and metrics[cvss_key]:
                    data_obj = metrics[cvss_key][0].get('cvssData', {})
                    cvss_score = data_obj.get('baseScore', 0.0)
                    severity = data_obj.get('baseSeverity', '')
                    break

            results.append({
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity,
            })

        return results

    except (requests.RequestException, json.JSONDecodeError, ValueError):
        return []
