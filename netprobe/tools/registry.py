"""工具注册表 — 自动检测已安装的扫描工具，统一调度。"""

import os
import shutil
import sys
from pathlib import Path


def _get_extra_paths() -> list[str]:
    """根据当前平台生成额外的工具搜索路径。"""
    paths = []
    home = Path.home()
    is_win = sys.platform == 'win32'
    is_mac = sys.platform == 'darwin'

    # Go 工具目录
    gopath = os.environ.get('GOPATH', '')
    if gopath:
        paths.append(str(Path(gopath) / 'bin'))
    paths.append(str(home / 'go' / 'bin'))

    if is_win:
        # Nmap 安装目录
        for drive in ('C', 'D', 'E'):
            for pf in (f'{drive}:\\Program Files\\Nmap',
                       f'{drive}:\\Program Files (x86)\\Nmap'):
                paths.append(pf)
        # scoop
        paths.append(str(home / 'scoop' / 'shims'))
    elif is_mac:
        paths.append('/usr/local/bin')
        paths.append('/opt/homebrew/bin')
        paths.append('/opt/homebrew/sbin')
        paths.append(str(home / 'homebrew' / 'bin'))
        # MacPorts
        paths.append('/opt/local/bin')
        paths.append('/opt/local/sbin')
    else:
        # Linux
        paths.append('/usr/bin')
        paths.append('/usr/local/bin')
        paths.append('/usr/sbin')
        paths.append('/usr/local/sbin')
        paths.append('/snap/bin')
        paths.append(str(home / '.local' / 'bin'))

    return paths


_EXTRA_PATHS = _get_extra_paths()


def _find_executable(name: str) -> str | None:
    """查找可执行文件，优先从已知路径查找，再查系统 PATH。"""
    ext = '.exe' if sys.platform == 'win32' else ''
    # 优先从已知路径查找（避免找到系统 PATH 中同名的错误程序，如 hermes 的 httpx）
    for base in _EXTRA_PATHS:
        candidate = Path(base) / f'{name}{ext}'
        if candidate.is_file():
            return str(candidate)
    # 再查系统 PATH
    return shutil.which(name)


def check_tool(name: str) -> bool:
    """检查工具是否可用。"""
    return _find_executable(name) is not None


def get_tool_path(name: str) -> str:
    """返回工具可执行文件的完整路径，找不到则返回原始名称。"""
    return _find_executable(name) or name


# 工具能力常量
CAP_SUBDOMAIN = 'subdomain'
CAP_PORTSCAN = 'portscan'
CAP_WEBPROBE = 'webprobe'
CAP_DNS = 'dns'
CAP_PASSIVE = 'passive'

# 注册的工具信息: name -> {cmd, caps, label}
TOOL_INFO = {
    'subfinder':  {'cmd': 'subfinder',  'caps': [CAP_SUBDOMAIN], 'label': 'Subfinder'},
    'nmap':       {'cmd': 'nmap',       'caps': [CAP_SUBDOMAIN, CAP_PORTSCAN], 'label': 'Nmap'},
    'masscan':    {'cmd': 'masscan',    'caps': [CAP_PORTSCAN],  'label': 'Masscan'},
    'rustscan':   {'cmd': 'rustscan',   'caps': [CAP_PORTSCAN],  'label': 'RustScan'},
    'httpx':      {'cmd': 'httpx',      'caps': [CAP_WEBPROBE],  'label': 'Httpx'},
    'dnsx':       {'cmd': 'dnsx',       'caps': [CAP_DNS],       'label': 'DNSx'},
    'nuclei':     {'cmd': 'nuclei',     'caps': [CAP_WEBPROBE],  'label': 'Nuclei'},
}


def get_available_tools() -> dict[str, dict]:
    """返回所有可用工具及其能力。"""
    result = {}
    for name, info in TOOL_INFO.items():
        available = check_tool(info['cmd'])
        result[name] = {
            'name': name,
            'label': info['label'],
            'available': available,
            'caps': info['caps'],
        }
    return result


def get_tools_with_cap(cap: str) -> list[str]:
    """返回具有指定能力且已安装的工具名列表。"""
    return [
        name for name, info in TOOL_INFO.items()
        if cap in info['caps'] and check_tool(info['cmd'])
    ]


def best_tool_for(cap: str) -> str | None:
    """返回指定能力的最佳可用工具（优先级序）。"""
    priority = {
        CAP_SUBDOMAIN: ['subfinder', 'nmap'],
        CAP_PORTSCAN: ['masscan', 'rustscan', 'nmap'],
        CAP_WEBPROBE: ['httpx'],
        CAP_DNS: ['dnsx'],
    }
    for name in priority.get(cap, []):
        if check_tool(TOOL_INFO[name]['cmd']):
            return name
    return None
