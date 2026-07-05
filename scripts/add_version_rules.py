#!/usr/bin/env python3
"""给现有高频指纹规则补充 version 提取字段。"""
import json
from pathlib import Path

FP_PATH = Path(__file__).parent.parent / "netprobe" / "data" / "fingerprints.json"
fps = json.load(open(FP_PATH, encoding="utf-8"))

# 按名称查找并补充 version 提取规则
VERSION_MAP = {
    # Web 服务器
    "Nginx": {"header": "Server", "version": "re:nginx/([0-9.]+)"},
    "Apache": {"header": "Server: Apache", "version": "re:Apache(?:-AdvancedExtranet)?/([0-9.]+)"},
    "Tomcat": {"header": "Server: Apache-Coyote", "version": "re:Coyote/([0-9.]+)"},
    "IIS": {"header": "Server: Microsoft-IIS", "version": "re:Microsoft-IIS/([0-9.]+)"},
    # CMS
    "WordPress": {"meta": "WordPress", "version": "re:WordPress\\s+([0-9.]+)"},
    "Drupal": {"header": "X-Generator: Drupal", "version": "re:Drupal\\s+([0-9.]+)"},
    "Joomla": {"header": "X-Content-Powered-By", "version": "re:Joomla!?\\s*([0-9.]+)"},
    # 框架
    "PHP": {"header": "X-Powered-By: PHP", "version": "re:PHP/?([0-9.]+)"},
    "ThinkPHP": {"header": "X-Powered-By: ThinkPHP", "version": "re:ThinkPHP/?([0-9.]+)"},
    "Express": {"header": "X-Powered-By: Express", "version": "re:Express/?([0-9.]+)"},
    # JS 库
    "jQuery": {"script_src": "jquery", "version": "re:jquery[.-]([0-9.]+)"},
    # 运维工具
    "Jenkins": {"header": "X-Jenkins", "version": "re:X-Jenkins:\\s*([0-9.]+)"},
    "Grafana": {"html": "re:window.grafanaConfig.*?version.*?:.*?\"([0-9.]+)", "version": "re:version.*?([0-9.]+)"},
    # React/Angular 版本（从 script src 或 meta 提取）
    "React": {"script_src": "react", "version": "re:react[.@/-]([0-9]+\\.[0-9]+)"},
    "Angular": {"html": "ng-version", "version": "re:ng-version=\"([0-9.]+)\""},
    "Vue.js": {"script_src": "vue", "version": "re:vue[.@/-]([0-9]+\\.[0-9]+)"},
}

updated = 0
for fp in fps:
    name = fp["name"]
    rule = None
    for key, val in VERSION_MAP.items():
        if name.lower() == key.lower():
            rule = val
            break
    if not rule:
        continue

    # 找到匹配的 pattern 并加 version
    version_re = rule["version"]
    for pat in fp["patterns"]:
        if "version" in pat:
            break  # 已有 version，跳过
        # 检查这个 pattern 的 type+text 是否匹配
        ptype = pat["type"]
        ptext = pat["pattern"]
        for vtype, vval in rule.items():
            if vtype == "version":
                continue
            # 如果 pattern 匹配这个特征，给它加 version
            if (ptype in vval.lower() or vval.lower() in ptext.lower()
                or (ptype == "header" and "header" in vval.lower())
                or (ptype == "script_src" and "script_src" in vval.lower())
                or (ptype == "html" and "html" in vval.lower())
                or (ptype == "meta" and "meta" in vval.lower())):
                pat["version"] = version_re
                updated += 1
                break

json.dump(fps, open(FP_PATH, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
with_ver = sum(1 for fp in fps for p in fp["patterns"] if "version" in p)
print(f"更新 {updated} 个 pattern，总计 {with_ver} 条带 version 提取")
