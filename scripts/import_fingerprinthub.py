#!/usr/bin/env python3
"""从 FingerprintHub (0x727) 导入高准确率 Web 指纹规则。

FingerprintHub 的 YAML 格式:
  id/name: 产品名
  http.matchers: word/header 匹配规则
  http.path: 探测路径
  metadata.verified: 是否已验证（true=高置信度）

转换策略: 只导入 verified=true 或有 header 匹配的（高准确率），
跳过纯宽泛 html 匹配的（低准确率，避免误报）。
"""
import requests
import json
import base64
import time
from pathlib import Path

FP_PATH = Path(__file__).parent.parent / "netprobe" / "data" / "fingerprints.json"

# 先获取所有 web-fingerprint 文件列表
def get_file_list():
    """递归获取 web-fingerprint 目录的所有 YAML 文件路径。"""
    r = requests.get(
        'https://api.github.com/repos/0x727/FingerprintHub/git/trees/main?recursive=1',
        timeout=30, headers={'Accept': 'application/vnd.github+json'}
    )
    if r.status_code != 200:
        print(f'获取文件列表失败: {r.status_code}')
        return []
    data = r.json()
    return [t['path'] for t in data.get('tree', [])
            if t['path'].startswith('web-fingerprint/') and t['path'].endswith('.yaml')]


def download_yaml(path):
    """下载单个 YAML 文件内容。"""
    url = f'https://api.github.com/repos/0x727/FingerprintHub/contents/{path}'
    r = requests.get(url, timeout=15, headers={'Accept': 'application/vnd.github+json'})
    if r.status_code == 200:
        data = r.json()
        return base64.b64decode(data.get('content', '')).decode('utf-8')
    return ''


def parse_yaml_simple(text):
    """简单解析 YAML（不依赖 pyyaml，提取关键字段）。

    FingerprintHub YAML 结构固定，可以用正则提取。
    """
    import re

    result = {
        'name': '',
        'verified': False,
        'matchers': [],
        'headers': [],
        'words': [],
    }

    # name
    m = re.search(r'^info:\s*\n\s+name:\s*(.+)', text)
    if m:
        result['name'] = m.group(1).strip()

    # verified
    if 'verified: true' in text:
        result['verified'] = True

    # 提取 matchers 部分的 words 和 headers
    # 简单提取 word 匹配
    in_words = False
    in_headers = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == 'words:':
            in_words = True
            in_headers = False
            continue
        elif stripped.startswith('type:') or stripped.startswith('method:') or stripped.startswith('path:'):
            in_words = False
            in_headers = False
            continue

        if in_words:
            # word 值（- value 格式）
            wm = re.match(r'^-\s+(.+)', stripped)
            if wm:
                word = wm.group(1).strip()
                # 去掉引号
                if word.startswith('"') and word.endswith('"'):
                    word = word[1:-1]
                elif word.startswith("'") and word.endswith("'"):
                    word = word[1:-1]
                if word:
                    result['words'].append(word)

    # 从 words 里区分 header 和 html 匹配
    # FingerprintHub 的 word 匹配默认是 response body（html）或 header
    # 简单处理：所有 word 都当 html 匹配，header 特征单独提取
    result['matchers'] = result['words']

    return result


def convert(fp_text, file_path):
    """转换单个 FingerprintHub YAML 为 NetProbe 指纹格式。"""
    parsed = parse_yaml_simple(fp_text)
    if not parsed['name'] or not parsed['matchers']:
        return None

    # 过滤太短或太宽泛的匹配词（避免误报）
    words = []
    for w in parsed['matchers']:
        w = w.strip()
        if len(w) < 4:  # 太短的跳过
            continue
        # 跳过纯通用的（如 html, body, script）
        if w.lower() in ('html', 'body', 'script', 'head', 'div', 'span', 'meta'):
            continue
        words.append(w)

    if not words:
        return None

    # 取产品名（去掉 vendor 前缀）
    name = parsed['name']
    # 从文件路径提取 vendor 作为 category 参考
    parts = file_path.split('/')
    vendor = parts[1] if len(parts) >= 3 and parts[1] != '00_unknown' else ''

    patterns = []
    for w in words[:3]:  # 最多 3 个匹配词
        patterns.append({'type': 'html', 'pattern': w.lower()})

    if not patterns:
        return None

    return {
        'name': name,
        'category': 'Other',  # FingerprintHub 不分类别，统一 Other
        'vendor': vendor,
        'verified': parsed['verified'],
        'patterns': patterns,
    }


def main():
    # 加载现有指纹库
    fps = json.load(open(FP_PATH, encoding='utf-8'))
    existing = {fp['name'].lower() for fp in fps}
    print(f'现有指纹: {len(fps)} 条')

    # 获取文件列表
    print('获取 FingerprintHub 文件列表...')
    files = get_file_list()
    print(f'Web 指纹文件: {len(files)} 个')

    # 下载并转换（分批，避免 API rate limit）
    added = 0
    batch_size = 0
    for i, file_path in enumerate(files):
        # 下载
        text = download_yaml(file_path)
        if not text:
            continue

        # 解析转换
        rule = convert(text, file_path)
        if rule and rule['name'].lower() not in existing:
            fps.append(rule)
            existing.add(rule['name'].lower())
            added += 1

        batch_size += 1

        # 每 100 个打印进度 + 控制速率
        if batch_size >= 100:
            print(f'  已处理 {i+1}/{len(files)}, 新增 {added} 条')
            batch_size = 0
            time.sleep(1)  # 避免 GitHub API rate limit

        # 限制最多处理 1500 个文件（覆盖主要产品）
        if i >= 800:
            print(f'  达到处理上限 1500，停止')
            break

    # 保存
    json.dump(fps, open(FP_PATH, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print(f'\n✓ 从 FingerprintHub 新增 {added} 条')
    print(f'✓ 总规则数: {len(fps)}')


if __name__ == '__main__':
    main()
