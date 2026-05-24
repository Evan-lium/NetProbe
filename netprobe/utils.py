import re
import ipaddress


def is_ip_address(target: str) -> bool:
    try:
        ipaddress.ip_address(target.strip())
        return True
    except ValueError:
        return False


def validate_input(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("目标不能为空")
    if is_ip_address(target):
        return target
    # 域名格式校验: 允许字母、数字、连字符、点
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', target):
        raise ValueError(f"无效的目标: {target}")
    return target


# 常见多段 TLD，用于正确提取根域名
MULTI_PART_TLDS = {
    'co.uk', 'co.jp', 'co.kr', 'co.nz', 'co.in', 'co.za',
    'com.cn', 'com.au', 'com.br', 'com.tw', 'com.hk', 'com.sg',
    'net.cn', 'org.cn', 'org.uk', 'org.au',
    'ac.uk', 'ac.jp', 'ac.kr',
    'gov.cn', 'gov.uk', 'gov.au',
    'edu.cn', 'edu.au',
}


def extract_root_domain(hostname: str) -> str:
    hostname = hostname.rstrip('.').lower()
    parts = hostname.split('.')
    if len(parts) <= 2:
        return hostname
    # 检查末尾是否为多段 TLD
    last_three = '.'.join(parts[-3:])
    last_two = '.'.join(parts[-2:])
    if last_three in MULTI_PART_TLDS and len(parts) >= 4:
        return '.'.join(parts[-4:])
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])
