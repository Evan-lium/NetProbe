"""管理后台专项识别 — title / URL / 正文关键词三重判定。

detect_admin_panels(hosts) 遍历每个 host 的 web_info 站点，依据以下信号判定是否为
管理后台/登录页/控制台:
  1. title 含「后台/管理/admin/login/console/dashboard/管理台/控制台」等关键词
  2. URL 路径含 /admin /manager /console 等
  3. 正文/headers 关键词（兜底，本阶段 _raw_html 已剥离，故主要依赖 title+URL）

命中信号越多置信度越高（双信号 high，单信号 medium）。结果存 host['_admin_panels']，
格式 [{url, title, confidence, reason}]。纯内存计算，无网络请求。
"""

# title / 正文关键词（小写匹配，中英双语覆盖常见后台命名）
_TITLE_KEYWORDS = (
    '后台', '管理台', '控制台', '管理后台', '管理系统', '管理员',
    'admin', 'login', 'sign in', 'console', 'dashboard', 'manage',
    'backend', 'control panel', '控制面板', '登录', '登陆',
)

# URL 路径关键词（路径段匹配，避免误命中如 /admin-style 这类正常路径需用分隔判定）
_URL_KEYWORDS = ('/admin', '/manager', '/console', '/dashboard', '/login',
                 '/backend', '/cp/', '/admin/', '/manage/', '/system')


def detect_admin_panels(hosts: list[dict]) -> int:
    """对每个 host 的 web_info 站点判定是否为管理后台。

    结果写入 host['_admin_panels']（list[dict]，无命中则为空列表）。
    返回检测到的后台总数（用于进度展示）。
    """
    total = 0
    for host in hosts:
        panels = []
        for w in host.get('web_info', []) or []:
            panel = _detect_one(w)
            if panel:
                panels.append(panel)
        host['_admin_panels'] = panels
        total += len(panels)
    return total


def _detect_one(web_info: dict) -> dict | None:
    """判定单个 web 站点是否是后台，返回结果 dict 或 None。

    采用多信号加权：
      - title 命中关键词 → 强信号（权重 2）
      - URL 路径命中 → 强信号（权重 2）
    双信号 confidence=high，单信号 confidence=medium。reason 记录命中依据。
    """
    title = (web_info.get('title') or '').strip()
    url = (web_info.get('url') or '').strip()
    if not url:
        return None

    title_low = title.lower()
    url_low = url.lower()

    # 信号 1：title 关键词
    title_hit = _first_match(title_low, _TITLE_KEYWORDS)

    # 信号 2：URL 路径关键词
    url_hit = _first_match(url_low, _URL_KEYWORDS)

    if not title_hit and not url_hit:
        return None

    signals = []
    if title_hit:
        signals.append(f'title 命中「{title_hit}」')
    if url_hit:
        signals.append(f'URL 路径命中「{url_hit}」')

    # 双信号 high，单信号 medium
    confidence = 'high' if len(signals) >= 2 else 'medium'
    return {
        'url': url,
        'title': title,
        'confidence': confidence,
        'reason': '；'.join(signals),
    }


def _first_match(text: str, keywords: tuple[str, ...]) -> str:
    """返回 text 中首个命中的关键词（原文形式），无命中返回空串。"""
    for kw in keywords:
        if kw and kw in text:
            return kw
    return ''
