"""未授权接口枚举 — 检测常见管理/调试接口的未授权访问。

检测目标:
  - API 文档: Swagger/OpenAPI UI, API Blueprint, GraphQL Playground
  - Spring Boot: actuator/health/env/mappings/beans
  - 调试接口: phpinfo(), .env, debug console
  - 数据库管理: Druid, H2 Console, phpMyAdmin, Adminer
  - 服务发现: Eureka, Consul, Zookeeper
  - 监控: Prometheus, Grafana, Kibana, Druid Monitor
  - 容器: Docker API, Kubernetes API
  - 其他: .git/config, server-status, WP-Cron

命中追加到 host['vulnerabilities']（category=unauth_access）。
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

REQUEST_TIMEOUT = 6
_MAX_WORKERS = 10


# 未授权接口规则: path → (描述, 严重性, 响应特征关键词)
UNAUTH_PATHS = [
    # ── API 文档（信息泄露）──
    {'path': '/swagger-ui.html', 'desc': 'Swagger UI 未授权访问', 'severity': 'medium', 'keyword': 'swagger'},
    {'path': '/swagger-ui/index.html', 'desc': 'Swagger UI v3 未授权访问', 'severity': 'medium', 'keyword': 'swagger'},
    {'path': '/swagger-resources', 'desc': 'Swagger 资源配置泄露', 'severity': 'medium', 'keyword': 'swagger'},
    {'path': '/v2/api-docs', 'desc': 'Swagger API 文档泄露 (v2)', 'severity': 'medium', 'keyword': 'swagger'},
    {'path': '/v3/api-docs', 'desc': 'Swagger API 文档泄露 (v3)', 'severity': 'medium', 'keyword': 'openapi'},
    {'path': '/openapi.json', 'desc': 'OpenAPI 规范文档泄露', 'severity': 'medium', 'keyword': 'openapi'},
    {'path': '/graphql', 'desc': 'GraphQL 端点暴露', 'severity': 'high', 'keyword': 'graphql'},
    {'path': '/graphiql', 'desc': 'GraphiQL 调试控制台暴露', 'severity': 'high', 'keyword': 'graphiql'},

    # ── Spring Boot Actuator ──
    {'path': '/actuator', 'desc': 'Spring Boot Actuator 未授权访问', 'severity': 'high', 'keyword': 'actuator'},
    {'path': '/actuator/env', 'desc': 'Spring Boot 环境变量泄露 (含密码)', 'severity': 'critical', 'keyword': 'property'},
    {'path': '/actuator/heapdump', 'desc': 'Spring Boot 堆转储泄露', 'severity': 'critical', 'keyword': ''},
    {'path': '/actuator/mappings', 'desc': 'Spring Boot 路由映射泄露', 'severity': 'medium', 'keyword': 'handler'},
    {'path': '/actuator/configprops', 'desc': 'Spring Boot 配置属性泄露', 'severity': 'high', 'keyword': 'prefix'},
    {'path': '/actuator/beans', 'desc': 'Spring Boot Bean 列表泄露', 'severity': 'medium', 'keyword': 'bean'},
    {'path': '/env', 'desc': '环境变量接口泄露', 'severity': 'critical', 'keyword': 'property'},
    {'path': '/jolokia', 'desc': 'Jolokia JMX 接口暴露', 'severity': 'high', 'keyword': 'jolokia'},

    # ── 调试/配置 ──
    {'path': '/.env', 'desc': '.env 配置文件泄露', 'severity': 'critical', 'keyword': ''},
    {'path': '/phpinfo.php', 'desc': 'phpinfo() 信息泄露', 'severity': 'high', 'keyword': 'phpinfo'},
    {'path': '/info.php', 'desc': 'PHP 信息页面泄露', 'severity': 'high', 'keyword': 'php'},
    {'path': '/debug', 'desc': '调试接口暴露', 'severity': 'high', 'keyword': 'debug'},
    {'path': '/_debug', 'desc': '调试接口暴露 (_debug)', 'severity': 'high', 'keyword': 'debug'},
    {'path': '/console', 'desc': 'Web 控制台暴露', 'severity': 'high', 'keyword': 'console'},
    {'path': '/trace', 'desc': '请求追踪日志泄露', 'severity': 'high', 'keyword': 'trace'},

    # ── 数据库管理面板 ──
    {'path': '/druid/index.html', 'desc': 'Druid 监控面板未授权访问', 'severity': 'high', 'keyword': 'druid'},
    {'path': '/druid/login.html', 'desc': 'Druid 登录页暴露', 'severity': 'medium', 'keyword': 'druid'},
    {'path': '/h2-console', 'desc': 'H2 数据库控制台暴露', 'severity': 'critical', 'keyword': 'h2'},
    {'path': '/phpmyadmin', 'desc': 'phpMyAdmin 暴露', 'severity': 'medium', 'keyword': 'phpmyadmin'},
    {'path': '/adminer.php', 'desc': 'Adminer 数据库管理暴露', 'severity': 'medium', 'keyword': 'adminer'},

    # ── 服务发现/注册中心 ──
    {'path': '/eureka', 'desc': 'Eureka 注册中心未授权访问', 'severity': 'high', 'keyword': 'eureka'},
    {'path': '/eureka/apps', 'desc': 'Eureka 服务列表泄露', 'severity': 'high', 'keyword': 'application'},
    {'path': '/v1/catalog/datacenters', 'desc': 'Consul 数据中心列表泄露', 'severity': 'high', 'keyword': 'datacenter'},
    {'path': '/v1/agent/services', 'desc': 'Consul 服务列表泄露', 'severity': 'high', 'keyword': 'service'},

    # ── 监控系统 ──
    {'path': '/prometheus', 'desc': 'Prometheus 指标接口暴露', 'severity': 'medium', 'keyword': 'prometheus'},
    {'path': '/metrics', 'desc': '应用指标接口暴露', 'severity': 'medium', 'keyword': ''},
    {'path': '/server-status', 'desc': 'Apache server-status 暴露', 'severity': 'medium', 'keyword': 'server-status'},

    # ── 版本控制/代码泄露 ──
    {'path': '/.git/config', 'desc': '.git 仓库配置泄露', 'severity': 'critical', 'keyword': 'git'},
    {'path': '/.svn/entries', 'desc': '.svn 仓库泄露', 'severity': 'high', 'keyword': 'svn'},
    {'path': '/.DS_Store', 'desc': '.DS_Store 文件泄露', 'severity': 'low', 'keyword': ''},

    # ── 其他常见泄露 ──
    {'path': '/backup', 'desc': '备份目录暴露', 'severity': 'high', 'keyword': 'backup'},
    {'path': '/robots.txt', 'desc': 'robots.txt 泄露路径', 'severity': 'info', 'keyword': 'disallow'},
    {'path': '/crossdomain.xml', 'desc': 'crossdomain.xml 暴露', 'severity': 'info', 'keyword': 'crossdomain'},
]


def scan_unauth_for_hosts(hosts: list[dict]) -> int:
    """对所有主机的 Web 站点做未授权接口枚举。

    命中追加到 host['vulnerabilities']（category=unauth_access）。
    返回命中总数。
    """
    total_findings = 0
    for host in hosts:
        web_info = host.get('web_info', [])
        for w in web_info:
            url = w.get('url', '')
            if not url:
                continue
            findings = _probe_url(url)
            for f in findings:
                host.setdefault('vulnerabilities', []).append(f)
            total_findings += len(findings)

    return total_findings


def _probe_url(base_url: str) -> list[dict]:
    """对单个站点探测所有未授权路径。返回命中列表。"""
    results = []
    base = base_url.rstrip('/')

    def _check_one(item):
        path = item['path']
        url = base + path
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT,
                                allow_redirects=False, verify=False)
        except Exception:
            return None

        keyword = item.get('keyword', '')

        # 200 且匹配关键词 = 确认暴露
        if resp.status_code == 200:
            content = resp.text[:4096].lower()
            # 有关键词要求的验证内容；无关键词的 200 直接命中
            if not keyword or keyword.lower() in content:
                return {
                    'name': item['desc'],
                    'severity': item['severity'],
                    'category': 'unauth_access',
                    'url': url,
                    'matched_at': path,
                }

        # 403 + high/critical = 存在但被限（降级为 info）
        if resp.status_code == 403 and item['severity'] in ('critical', 'high'):
            return {
                'name': f'{item["desc"]} (403 被限制)',
                'severity': 'info',
                'category': 'unauth_access',
                'url': url,
                'matched_at': path,
            }

        return None

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = [pool.submit(_check_one, item) for item in UNAUTH_PATHS]
        for fut in as_completed(futures):
            try:
                result = fut.result()
            except Exception:
                result = None
            if result:
                results.append(result)

    return results
