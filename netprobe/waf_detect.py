"""WAF（Web Application Firewall）检测。

通过 HTTP 响应头、Cookie、响应体特征识别目标是否部署了 WAF，
识别 WAF 厂商/产品类型，标记防护层避免误报。

检测策略（纯内存分析，无额外网络请求，复用已采集的 headers/body）:
  1. 特征响应头（X-WAF / Server / Via / X-Powered-By 等）
  2. 特征 Cookie 名
  3. 拦截页特征（在 web_info 的 status/title 中识别）

识别结果追加到 host['_waf_detected']，用于风险评分和前端展示。
"""
from .cdn import detect_cdn


# WAF HTTP 头特征 → WAF 名称映射
WAF_HEADERS = {
    'x-waf-event-info': 'AWS WAF',
    'x-aws-waf-token': 'AWS WAF',
    'x-amzn-waf-action': 'AWS WAF',
    'x-cdn': 'Aliyun WAF',
    'x-yd-waf-info': 'Aliyun WAF',
    'x-yd-info': 'Aliyun WAF',
    'server': '_SERVER_CHECK',  # 特殊处理，见 WAF_SERVER_HINTS
    'via': '_VIA_CHECK',
    'x-sucuri-id': 'Sucuri WAF',
    'x-sucuri-cache': 'Sucuri WAF',
    'x-cdn-origin': 'Akamai',
    'x-akamai-transformed': 'Akamai',
    'set-cookie': '_COOKIE_CHECK',
    'x-ruxitjs': 'Dynatrace WAF',
    'x-denied': 'ACE XML Gateway',
    'x-firewall': 'Tencent Cloud WAF',
    'x-tencent-waf': 'Tencent Cloud WAF',
}

# Server 头关键词 → WAF 名称
WAF_SERVER_HINTS = {
    'cloudflare': 'Cloudflare WAF',
    'sucuri': 'Sucuri WAF',
    'imperva': 'Imperva Incapsula WAF',
    'incapsula': 'Imperva Incapsula WAF',
    'akamai': 'Akamai WAF',
    'f5 big-ip': 'F5 BIG-IP ASM',
    'bigip': 'F5 BIG-IP ASM',
    'mod_security': 'ModSecurity',
    'modsecurity': 'ModSecurity',
    '360wzb': '360 网站卫士',
    '360waf': '360 WAF',
    '360webmaster': '360 网站卫士',
    'wangsansan': '360 WAF',
    'yundun': '阿里云盾',
    'aliyun-waf': 'Aliyun WAF',
    'tencent-waf': 'Tencent Cloud WAF',
    'baiduyun': '百度云加速',
    'baidu': '百度云加速',
    'qianxin': '奇安信 WAF',
    'anquanbao': '安全宝 WAF',
    'nsfocus': '绿盟 WAF',
    'topsec': '天融信 WAF',
    'chinacache': 'ChinaCache',
    'wangsu': '网宿 WAF',
    'chinanetcenter': '网宿 WAF',
}

# Cookie 名关键词 → WAF 名称
WAF_COOKIE_HINTS = {
    'incap_ses': 'Imperva Incapsula WAF',
    'visid_incap': 'Imperva Incapsula WAF',
    'nlbi': 'Imperva Incapsula WAF',
    'sucuri_cloudproxy_uuid': 'Sucuri WAF',
    '__cfduid': 'Cloudflare WAF',
    'cf_clearance': 'Cloudflare WAF',
    '__cfruid': 'Cloudflare WAF',
    'phpsession': None,  # 忽略
    'jsessionid': None,
}

# 拦截页标题特征
WAF_BLOCK_TITLES = {
    'attention required! | cloudflare': 'Cloudflare WAF',
    'access denied': None,  # 太通用
    'blocked': None,
    '安全拦截': 'Aliyun WAF',
    'warning': None,
}


def detect_waf_for_hosts(hosts: list[dict]) -> int:
    """对所有主机的 web_info 做 WAF 检测。

    结果存入 host['_waf_detected']（WAF 名称列表）。
    返回检测到 WAF 的主机数。
    """
    detected_count = 0

    for host in hosts:
        waf_names = set()
        for w in host.get('web_info', []):
            headers = w.get('headers') or {}
            if not isinstance(headers, dict):
                continue

            # 1. 特征响应头检测
            for hkey, hval in headers.items():
                key_lower = hkey.lower()
                val_lower = str(hval).lower()

                # 直接匹配
                if key_lower in WAF_HEADERS:
                    mapping = WAF_HEADERS[key_lower]
                    if mapping == '_SERVER_CHECK':
                        for srv_kw, waf_name in WAF_SERVER_HINTS.items():
                            if srv_kw in val_lower:
                                waf_names.add(waf_name)
                    elif mapping == '_VIA_CHECK':
                        for srv_kw, waf_name in WAF_SERVER_HINTS.items():
                            if srv_kw in val_lower:
                                waf_names.add(waf_name)
                    elif mapping == '_COOKIE_CHECK':
                        for cookie_kw, waf_name in WAF_COOKIE_HINTS.items():
                            if cookie_kw in val_lower:
                                if waf_name:
                                    waf_names.add(waf_name)
                    elif mapping:
                        waf_names.add(mapping)

            # 2. Server 头独立检查（最常见的检测方式）
            server = headers.get('Server', '') or headers.get('server', '')
            if server:
                server_lower = server.lower()
                for srv_kw, waf_name in WAF_SERVER_HINTS.items():
                    if srv_kw in server_lower:
                        waf_names.add(waf_name)

            # 3. 拦截页标题检测
            title = (w.get('title') or '').lower().strip()
            if title:
                for block_title, waf_name in WAF_BLOCK_TITLES.items():
                    if block_title in title and waf_name:
                        waf_names.add(waf_name)
                # 403/406 + 特征 cookie = WAF 拦截信号
                status = w.get('status', 0)
                if status in (403, 406, 412, 429):
                    for hkey, hval in headers.items():
                        if hkey.lower() == 'set-cookie':
                            for cookie_kw, waf_name in WAF_COOKIE_HINTS.items():
                                if cookie_kw in str(hval).lower() and waf_name:
                                    waf_names.add(waf_name)

        if waf_names:
            host['_waf_detected'] = sorted(waf_names)
            detected_count += 1

    return detected_count


def get_waf_summary(host: dict) -> list[str]:
    """获取主机的 WAF 检测结果摘要。"""
    return host.get('_waf_detected', [])
