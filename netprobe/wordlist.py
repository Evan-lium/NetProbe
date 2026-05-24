import os
import tempfile

COMMON_SUBDOMAINS = [
    # 基础服务
    'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail',
    'email', 'mx', 'mx1', 'mx2', 'relay',
    # Web 服务
    'api', 'api-gateway', 'app', 'web', 'portal', 'site',
    'blog', 'forum', 'wiki', 'docs', 'static', 'cdn',
    'assets', 'media', 'img', 'images', 'video', 'download',
    # 管理后台
    'admin', 'manager', 'manage', 'panel', 'cpanel', 'cp',
    'backend', 'console', 'dashboard', 'monitor', 'grafana',
    # 开发/测试环境
    'dev', 'test', 'staging', 'stage', 'uat', 'qa',
    'sandbox', 'demo', 'preview', 'beta', 'alpha',
    # 运维基础设施
    'ns1', 'ns2', 'ns3', 'dns', 'dns1', 'dns2',
    'vpn', 'proxy', 'gateway', 'router', 'firewall',
    'db', 'database', 'mysql', 'postgres', 'redis', 'mongo',
    'elastic', 'es', 'kafka', 'rabbitmq', 'mq',
    # CI/CD
    'git', 'gitlab', 'github', 'svn', 'jenkins', 'ci', 'cd',
    'build', 'deploy', 'registry', 'nexus', 'artifactory',
    # 监控/日志
    'log', 'logs', 'logger', 'logging',
    'monitor', 'monitoring', 'prometheus', 'grafana', 'zabbix',
    'alert', 'alerts', 'alertmanager', 'kibana', 'splunk',
    # 安全
    'auth', 'sso', 'oauth', 'login', 'signin', 'sign-in',
    'saml', 'cas', 'ldap', 'ad',
    # 内部服务
    'internal', 'intranet', 'vpn', 'office', 'oa',
    'hr', 'crm', 'erp', 'bi', 'report', 'reports',
    # 云/K8s
    'cloud', 'k8s', 'kubernetes', 'docker', 'container',
    'helm', 'rancher', 'traefik', 'nginx', 'ingress',
    # 移动端
    'm', 'mobile', 'app', 'ios', 'android', 'wap',
    # 其他常见
    'shop', 'store', 'pay', 'payment', 'order', 'cart',
    'search', 's', 'go', 'link', 'redirect', 'short',
    'status', 'health', 'ping', 'trace', 'debug',
    'backup', 'bak', 'old', 'new', 'next', 'v2', 'v3',
    'tv', 'live', 'stream', 'radio', 'news', 'press',
    'support', 'help', 'faq', 'feedback', 'contact',
    'careers', 'job', 'jobs', 'recruit', 'hire',
    'en', 'zh', 'cn', 'us', 'eu', 'asia',
    'www2', 'www3', 'web1', 'web2', 'web3',
    'server', 'server1', 'server2', 'node1', 'node2',
    'prod', 'production', 'pre', 'pre-prod',
    'test1', 'test2', 'testenv', 'testing',
    'dev1', 'dev2', 'devenv', 'development',
    'kb', 'knowledge', 'learn', 'training', 'edu',
]


def get_default_wordlist_path() -> str:
    """将内置字典写入临时文件，返回文件路径。调用方负责清理。"""
    fd, path = tempfile.mkstemp(suffix='.txt', prefix='subdomains_')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            for sub in COMMON_SUBDOMAINS:
                f.write(sub + '\n')
    except Exception:
        os.close(fd)
        raise
    return path


def load_external_wordlist(path: str) -> str:
    """校验外部字典文件是否可用，返回路径。"""
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"字典文件不存在: {path}")
    if os.path.getsize(path) == 0:
        raise ValueError(f"字典文件为空: {path}")
    return path
