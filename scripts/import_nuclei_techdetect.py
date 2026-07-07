#!/usr/bin/env python3
"""从 nuclei-templates 的 tech-detect 模板导入高准确率指纹规则。

数据源: projectdiscovery/nuclei-templates/http/technologies/*.yaml
       通过 jsdelivr CDN 拉取，绕开 GitHub API 限流。

模板格式关键字段:
  info.name             产品名
  info.metadata.vendor  厂商
  info.metadata.product 产品名
  info.metadata.category 分类（cms/framework/webserver 等）
  info.tags             标签（含分类线索）
  http.matchers         匹配规则（word/regex/dsl/status, part: header/body/all）
  http.matchers-condition 多特征是 and 还是 or
  http.extractors       版本提取（regex/kval）

转换策略:
  - word/regex part=header → header pattern
  - word/regex part=body/all → html pattern
  - dsl contains(tolower(header)...) → header pattern
  - dsl contains(tolower(body)...)   → html pattern
  - extractor regex 含 group → 加 version 字段
  - 多 matcher 按 matchers-condition 决定合并方式
  - 只保留至少 1 个有意义的 header/body 特征（跳过纯 status 匹配）
"""
import json
import re
import time
import sys
from pathlib import Path

import requests

FP_PATH = Path(__file__).parent.parent / "netprobe" / "data" / "fingerprints.json"

# nuclei metadata.category → NetProbe category
CATEGORY_MAP = {
    "cms": "CMS",
    "framework": "Framework",
    "webserver": "Server",
    "server": "Server",
    "database": "Database",
    "panel": "Web服务器面板",
    "cdn": "CDN",
    "waf": "WAF",
    "oa": "OA",
    "forum": "Forum",
    "ecommerce": "Ecommerce",
    "analytics": "Analytics",
    "build": "Build",
    "monitoring": "监控",
}

# 名称/标签 → 分类（补充 nuclei 模板未标 category 的情况）
NAME_CATEGORY_HINTS = {
    "nginx": "Server", "apache": "Server", "iis": "Server", "litespeed": "Server",
    "openresty": "Server", "tengine": "Server", "caddy": "Server", "lighttpd": "Server",
    "tomcat": "Server", "jetty": "Server", "undertow": "Server",
    "php": "Runtime", "python": "Runtime", "node": "Runtime", "ruby": "Runtime",
    "mysql": "Database", "redis": "Database", "mongodb": "Database", "postgresql": "Database",
    "phpmyadmin": "Database面板", "adminer": "Database面板",
    "wordpress": "CMS", "drupal": "CMS", "joomla": "CMS", "ghost": "CMS",
    "cloudflare": "CDN", "akamai": "CDN", "fastly": "CDN",
    "kibana": "监控", "grafana": "监控", "prometheus": "监控", "zabbix": "监控",
    "discourse": "Forum", "phpbb": "Forum",
}

# 宽泛/无意义的 pattern（几乎匹配所有网页，会导致严重误报）
# 这些 pattern 在 nuclei 里靠 matchers-condition:and 组合才有意义，
# 但我们的引擎是 OR 匹配，必须过滤掉
VAGUE_PATTERNS = {
    # 通用 HTML 标签（每个网页都有）
    "<html", "<body", "<head", "<div", "<span", "<meta", "<title",
    "<script", "<link", "<img", "<p>", "<br", "<h1", "<h2",
    # 通用 header 值（每个 HTTP 响应都有）
    "text/html", "text/plain", "application/json", "application/javascript",
    "content-type", "charset", "utf-8", "gzip", "keep-alive",
    "connection:", "server:", "date:", "cache-control",
    # 通用正则碎片
    "re:<", "re:>",
}


def _is_vague(pattern: str) -> bool:
    """判断 pattern 是否过于宽泛（会匹配大部分网页）。"""
    pat = pattern.lower().strip()
    if pat.startswith("re:"):
        pat = pat[3:].strip()
    if not pat:
        return True
    # 太短（<4 字符且非正则）基本是噪声
    if len(pat) < 4 and not pat.startswith("\\") and not pat.startswith("["):
        return True
    # 命中宽泛集合
    for v in VAGUE_PATTERNS:
        if pat == v or pat.startswith(v + ":") or pat == v + ">":
            return True
    # 纯通用 header 名（如 "content-type" 单独出现）
    if pat in ("content-type", "server", "set-cookie", "x-powered-by", "location"):
        return True
    return False

# CDN 加速域名
CDN_BASE = "https://cdn.jsdelivr.net/gh/projectdiscovery/nuclei-templates@main"
API_TREE = ("https://api.github.com/repos/projectdiscovery/nuclei-templates"
            "/git/trees/main?recursive=1")


def get_file_list() -> list[str]:
    """获取 http/technologies 下所有 yaml 文件相对路径。"""
    r = requests.get(API_TREE, timeout=30,
                     headers={"Accept": "application/vnd.github+json"})
    if r.status_code != 200:
        print(f"获取文件列表失败: {r.status_code}")
        return []
    data = r.json()
    files = [t["path"] for t in data.get("tree", [])
             if t["path"].startswith("http/technologies/")
             and t["path"].endswith(".yaml")
             and t["type"] == "blob"]
    # 排除 eol/ 和 default- 这类页面识别（不是产品指纹）
    files = [f for f in files
             if "/eol/" not in f
             and not f.split("/")[-1].startswith("default-")]
    return files


def download_yaml(rel_path: str) -> str:
    """通过 jsdelivr 下载 yaml 内容。"""
    url = f"{CDN_BASE}/{rel_path}"
    r = requests.get(url, timeout=20)
    if r.status_code == 200:
        return r.text
    return ""


# ---------- YAML 解析（轻量级，针对 nuclei 固定结构） ----------

def extract_block(text: str, key: str, indent_base: int = 0) -> list[str]:
    """提取一个 yaml 块的行（按缩进）。"""
    lines = text.splitlines()
    out = []
    in_block = False
    base_indent = -1
    for line in lines:
        if line.rstrip().endswith(f"{key}:") and not line.startswith(" " * (indent_base + 1)):
            in_block = True
            base_indent = len(line) - len(line.lstrip())
            continue
        if in_block:
            if line.strip() == "":
                continue
            cur_indent = len(line) - len(line.lstrip())
            if cur_indent <= base_indent and line.strip():
                break
            out.append(line)
    return out


def parse_info(text: str) -> dict:
    """解析 info 段。"""
    info = {}
    m = re.search(r"^info:\s*\n((?:[ \t]+.*\n?)+)", text, re.MULTILINE)
    if not m:
        return info
    block = m.group(1)

    nm = re.search(r"name:\s*(.+)", block)
    if nm:
        info["name"] = nm.group(1).strip().strip("'\"")

    # metadata.vendor / product / category
    vm = re.search(r"vendor:\s*(\S+)", block)
    if vm:
        info["vendor"] = vm.group(1).strip().strip("'\"")
    pm = re.search(r"product:\s*(\S+)", block)
    if pm:
        info["product"] = pm.group(1).strip().strip("'\"")
    cm = re.search(r"category:\s*(\S+)", block)
    if cm:
        info["category"] = cm.group(1).strip().strip("'\"")

    # verified
    if "verified: true" in block:
        info["verified"] = True

    # tags
    tm = re.search(r"tags:\s*(.+)", block)
    if tm:
        info["tags"] = [t.strip() for t in tm.group(1).split(",")]

    return info


def _extract_section(text: str, section: str) -> str:
    """提取 yaml 中某个 http 请求块下的子段（matchers / extractors 等）文本。

    nuclei 的 http 段是列表，每个请求块以 `  - method: GET` 开头（缩进 2+4=6），
    其下 matchers/extractors 缩进为 4。我们定位缩进 4 的 `matchers:` / `extractors:`
    并截取到下一个同级 key 为止。
    """
    lines = text.splitlines()
    start_i = None
    key_indent = None
    for i, line in enumerate(lines):
        # 缩进 4 的 `matchers:` 或 `extractors:`
        m = re.match(r"^(    )(\w+):\s*$", line)
        if m and m.group(2) == section:
            start_i = i + 1
            key_indent = 4
            break
    if start_i is None:
        return ""

    out = []
    for j in range(start_i, len(lines)):
        ln = lines[j]
        if ln.strip() == "":
            out.append(ln)
            continue
        cur_indent = len(ln) - len(ln.lstrip())
        # 遇到同级或更浅的 key（非列表项）→ 结束
        if cur_indent <= key_indent and ln.lstrip() and not ln.lstrip().startswith("- "):
            break
        out.append(ln)
    return "\n".join(out)


def parse_matchers_condition(text: str) -> str:
    """提取 matchers-condition。"""
    m = re.search(r"matchers-condition:\s*(\w+)", text)
    return m.group(1) if m else "or"


def _parse_list_blocks(section_text: str) -> list[tuple[str, str]]:
    """从一段 section 文本里解析出每个 `- type: xxx` 列表项的 body。

    返回 [(type, body_text), ...]。
    """
    if not section_text:
        return []
    lines = section_text.splitlines()
    items = []
    cur_type = None
    cur_body = []
    list_indent = None
    for line in lines:
        m = re.match(r"^(\s+)- type:\s*(\w+)\s*$", line)
        if m:
            indent = len(m.group(1))
            if list_indent is None:
                list_indent = indent
            if indent == list_indent:
                # 新列表项
                if cur_type is not None:
                    items.append((cur_type, "\n".join(cur_body)))
                cur_type = m.group(2)
                cur_body = []
                continue
        if cur_type is not None:
            cur_body.append(line)
    if cur_type is not None:
        items.append((cur_type, "\n".join(cur_body)))
    return items


def parse_matchers(text: str) -> list[dict]:
    """解析所有 matchers，返回 [{type, part, words:[], regex:[], dsl:[], condition}]。"""
    section = _extract_section(text, "matchers")
    matchers = []
    for mtype, body in _parse_list_blocks(section):
        matcher = {"type": mtype, "words": [], "regex": [], "dsl": []}
        pm = re.search(r"part:\s*(\w+)", body)
        if pm:
            matcher["part"] = pm.group(1)
        cm = re.search(r"condition:\s*(\w+)", body)
        if cm:
            matcher["condition"] = cm.group(1)
        # words
        for wm in re.finditer(r"^\s+-\s+(.+)$", body, re.MULTILINE):
            w = wm.group(1).strip().strip("'\"")
            if w:
                matcher["words"].append(w)
        # regex
        for rm in re.finditer(r"^\s+-\s+(.+)$", body, re.MULTILINE):
            rx = rm.group(1).strip().strip("'\"")
            if rx:
                matcher["regex"].append(rx)
        # dsl
        for dm in re.finditer(r"^\s+-\s+(.+)$", body, re.MULTILINE):
            d = dm.group(1).strip().strip("'\"")
            if d:
                matcher["dsl"].append(d)
        matchers.append(matcher)
    return matchers


def parse_extractors(text: str) -> list[dict]:
    """解析 extractors，提取 version 正则。"""
    section = _extract_section(text, "extractors")
    extractors = []
    for etype, body in _parse_list_blocks(section):
        ext = {"etype": etype}
        nm = re.search(r"name:\s*(\w+)", body)
        if nm:
            ext["name"] = nm.group(1)
        if re.search(r"^\s+regex:", body, re.MULTILINE):
            for rm in re.finditer(r"^\s+-\s+(.+)$", body, re.MULTILINE):
                rx = rm.group(1).strip().strip("'\"")
                if rx:
                    ext["regex"] = rx
                    break
        pm = re.search(r"part:\s*(\w+)", body)
        if pm:
            ext["part"] = pm.group(1)
        if re.search(r"^\s+kval:", body, re.MULTILINE):
            for k in re.finditer(r"^\s+-\s+(.+)$", body, re.MULTILINE):
                ext["kval"] = k.group(1).strip().strip("'\"")
                break
        if re.search(r"internal:\s*true", body):
            ext["internal"] = True
        extractors.append(ext)
    return extractors


# ---------- 转换 ----------

def _clean_pattern(p: str) -> str:
    """清理 pattern 字符串。"""
    p = p.strip().strip("'\"")
    # nuclei 的 regex 用单引号包裹，去掉
    return p


def _dsl_to_pattern(dsl: str) -> tuple[str, str] | None:
    """把 dsl 表达式转为 (type, pattern)。
    例: 'contains(tolower(header), "nginx")' → ('header', 'nginx')
    """
    # contains(tolower(header), "xxx")
    m = re.search(r'contains\s*\(\s*tolower\s*\(\s*(\w+)\s*\)\s*,\s*["\'](.+?)["\']', dsl)
    if m:
        part = m.group(1)
        val = m.group(2)
        if part in ("header", "all_header"):
            return ("header", val.lower())
        if part in ("body", "all", "raw"):
            return ("html", val.lower())
    # contains(header, "xxx") / contains(body, "xxx")
    m = re.search(r'contains\s*\(\s*(\w+)\s*,\s*["\'](.+?)["\']', dsl)
    if m:
        part = m.group(1)
        val = m.group(2)
        if part in ("header", "all_header"):
            return ("header", val.lower())
        if part in ("body", "all", "raw"):
            return ("html", val.lower())
    return None


def convert(text: str) -> dict | None:
    """转换单个 yaml 为 NetProbe 指纹格式。"""
    info = parse_info(text)
    if not info.get("name"):
        return None

    matchers = parse_matchers(text)
    condition = parse_matchers_condition(text)
    extractors = parse_extractors(text)

    patterns = []
    header_set = set()
    html_set = set()

    for matcher in matchers:
        mtype = matcher["type"]
        part = matcher.get("part", "body")

        if mtype == "status":
            continue  # 状态码不作为指纹

        if mtype == "word":
            for w in matcher["words"]:
                w = _clean_pattern(w)
                if not w or len(w) < 3:
                    continue
                if part in ("header", "all_header"):
                    if w.lower() not in header_set:
                        header_set.add(w.lower())
                        patterns.append({"type": "header", "pattern": w.lower()})
                else:
                    if w.lower() not in html_set:
                        html_set.add(w.lower())
                        patterns.append({"type": "html", "pattern": w.lower()})

        elif mtype == "regex":
            for rx in matcher["regex"]:
                rx = _clean_pattern(rx)
                if not rx:
                    continue
                # 标记为正则
                tagged = f"re:{rx}"
                if part in ("header", "all_header"):
                    patterns.append({"type": "header", "pattern": tagged})
                else:
                    patterns.append({"type": "html", "pattern": tagged})

        elif mtype == "dsl":
            for d in matcher["dsl"]:
                d = _clean_pattern(d)
                res = _dsl_to_pattern(d)
                if res:
                    ptype, val = res
                    if ptype == "header" and val not in header_set:
                        header_set.add(val)
                        patterns.append({"type": "header", "pattern": val})
                    elif ptype == "html" and val not in html_set:
                        html_set.add(val)
                        patterns.append({"type": "html", "pattern": val})

    # 过滤宽泛 pattern（text/html、<html> 等会匹配几乎所有网页）
    patterns = [p for p in patterns if not _is_vague(p["pattern"])]

    # 没有任何有意义特征 → 跳过
    if not patterns:
        return None

    # pattern 去重（按 type+pattern）
    seen = set()
    deduped = []
    for p in patterns:
        k = (p["type"], p["pattern"])
        if k not in seen:
            seen.add(k)
            deduped.append(p)
    patterns = deduped[:6]

    # 版本提取：优先 name 含 version 且 regex 有捕获组
    version_regex = None
    version_kval = None
    # 第一轮：找 name 明确标注 version 的
    for ext in extractors:
        ename = ext.get("name", "").lower()
        rx = ext.get("regex")
        if "version" in ename and rx and "(" in rx and ")" in rx:
            version_regex = rx
            break
    # 第二轮：兜底，任意 regex 含数字捕获组
    if not version_regex:
        for ext in extractors:
            rx = ext.get("regex", "")
            if rx and "(" in rx and re.search(r"\\d|\[0-9\]", rx):
                version_regex = rx
                break
    # kval 类型：从 header 提取（如 Server、X-Powered-By）
    if not version_regex:
        for ext in extractors:
            kv = ext.get("kval")
            if kv and ext.get("part") in ("header", "all_header", None):
                version_kval = kv
                break

    if version_regex:
        # 给所有 pattern 加 version 正则（引擎会在命中的 pattern 文本上提取，
        # 失败时兜底到所有文本，所以绑到每个 pattern 都安全）
        for p in patterns:
            if "version" not in p:
                p["version"] = f"re:{version_regex}"
    elif version_kval:
        # kval：从 header 字段提取，只绑到 header pattern
        for p in patterns:
            if p["type"] == "header" and "version" not in p:
                p["version"] = f"kval:{version_kval}"

    # 产品名：优先用 info.name，清理
    name = info["name"]
    # 去掉常见后缀
    name = re.sub(r"\s+(Detect(?:ion)?|Panel|Detection)$", "", name, flags=re.IGNORECASE)
    name = name.strip()

    # 分类
    category = "Other"
    cat_raw = info.get("category", "")
    if cat_raw and cat_raw.lower() in CATEGORY_MAP:
        category = CATEGORY_MAP[cat_raw.lower()]
    else:
        # 从 tags 推断
        tags = info.get("tags", [])
        for tag in tags:
            if tag.lower() in CATEGORY_MAP:
                category = CATEGORY_MAP[tag.lower()]
                break
    # 兜底：从名称推断（Nginx/Apache/Tomcat 等常见产品）
    if category == "Other":
        name_lower = name.lower()
        for hint, cat in NAME_CATEGORY_HINTS.items():
            if hint in name_lower:
                category = cat
                break

    rule = {
        "name": name,
        "category": category,
        "patterns": patterns,
        "source": "nuclei-techdetect",
    }
    if info.get("vendor"):
        rule["vendor"] = info["vendor"]
    if info.get("verified"):
        rule["verified"] = True

    return rule


# ---------- 去重合并 ----------

def _fingerprint_key(rule: dict) -> str:
    """生成去重 key：name 小写 + 第一个 pattern 的归一化。"""
    name = rule["name"].lower()
    # 取最显著的一个 pattern
    pats = rule.get("patterns", [])
    sig = ""
    for p in pats:
        if p["type"] == "header":
            sig = p["pattern"]
            break
    if not sig and pats:
        sig = pats[0]["pattern"]
    return f"{name}::{sig[:40]}"


def merge(existing: list[dict], new_rules: list[dict]) -> tuple[list[dict], dict]:
    """合并去重。
    策略：
      - 完全相同 name+signature → 跳过
      - name 相同但 signature 不同 → 合并 patterns（增强现有规则）
      - 全新 name → 追加
    """
    existing_keys = {_fingerprint_key(r) for r in existing}
    name_index = {}
    for i, r in enumerate(existing):
        nl = r["name"].lower()
        name_index.setdefault(nl, []).append(i)

    stats = {"added": 0, "merged": 0, "skipped": 0}
    for rule in new_rules:
        key = _fingerprint_key(rule)
        if key in existing_keys:
            stats["skipped"] += 1
            continue

        nl = rule["name"].lower()
        if nl in name_index:
            # 同名规则 → 合并 patterns（去重）
            for idx in name_index[nl]:
                target = existing[idx]
                existing_pats = {(p["type"], p["pattern"]) for p in target.get("patterns", [])}
                added_any = False
                for p in rule["patterns"]:
                    pk = (p["type"], p["pattern"])
                    if pk not in existing_pats:
                        target.setdefault("patterns", []).append(p)
                        existing_pats.add(pk)
                        added_any = True
                # 补 version
                for p in rule["patterns"]:
                    if "version" in p:
                        for tp in target.get("patterns", []):
                            if "version" not in tp and tp["type"] == p["type"]:
                                tp["version"] = p["version"]
                                break
                if added_any:
                    stats["merged"] += 1
                else:
                    stats["skipped"] += 1
                existing_keys.add(key)
                break
            else:
                # name_index 有 key 但所有 idx 都被 skip（理论上不会）
                existing.append(rule)
                existing_keys.add(key)
                stats["added"] += 1
        else:
            existing.append(rule)
            existing_keys.add(key)
            name_index.setdefault(nl, []).append(len(existing) - 1)
            stats["added"] += 1

    return existing, stats


def main():
    import argparse
    parser = argparse.ArgumentParser(description="导入 nuclei tech-detect 指纹")
    parser.add_argument("--dry-run", action="store_true", help="只统计不写入")
    parser.add_argument("--limit", type=int, default=0, help="限制处理文件数（0=全部）")
    args = parser.parse_args()

    print(f"指纹库路径: {FP_PATH}")
    existing = json.load(open(FP_PATH, encoding="utf-8"))
    print(f"现有规则: {len(existing)} 条")

    print("\n获取 nuclei-templates 文件列表...")
    files = get_file_list()
    print(f"technologies 模板: {len(files)} 个")
    if args.limit:
        files = files[:args.limit]
        print(f"  (限制处理 {len(files)} 个)")

    print("\n下载并转换模板（并发）...")
    from concurrent.futures import ThreadPoolExecutor, as_completed

    new_rules = []
    failed = 0

    def _download_and_convert(rel):
        text = download_yaml(rel)
        if not text:
            return None
        return convert(text)

    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(_download_and_convert, rel): rel for rel in files}
        done = 0
        for fut in as_completed(futures):
            done += 1
            try:
                rule = fut.result()
            except Exception:
                rule = None
            if rule is None:
                failed += 1
            else:
                new_rules.append(rule)
            if done % 100 == 0:
                print(f"  进度 {done}/{len(files)}, 已转换 {len(new_rules)} 条, 失败 {failed}")

    print(f"\n转换完成: {len(new_rules)} 条新规则 (失败 {failed})")

    print("\n合并去重...")
    merged, stats = merge(existing, new_rules)
    print(f"  新增: {stats['added']}")
    print(f"  增强现有: {stats['merged']}")
    print(f"  跳过重复: {stats['skipped']}")

    if args.dry_run:
        print(f"\n[dry-run] 合并后总计 {len(merged)} 条（未写入）")
    else:
        with open(FP_PATH, "w", encoding="utf-8") as f:
            json.dump(merged, f, ensure_ascii=False, indent=2)
        print(f"\n✓ 写入完成: {len(merged)} 条 → {FP_PATH}")

    # 分类统计
    import collections
    cat = collections.Counter(r.get("category", "Other") for r in merged)
    print("\n合并后分类分布 Top 10:")
    for k, v in cat.most_common(10):
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
