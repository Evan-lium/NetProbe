<div align="center">

# 🔭 NetProbe

**开源一体化资产探测与攻击面管理（ASM）平台**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Vue](https://img.shields.io/badge/Vue-3-42b883?logo=vue.js&logoColor=white)](https://vuejs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)]()
[![Platform](https://img.shields.io/badge/Platform-Win%20%7C%20macOS%20%7C%20Linux-lightgrey)]()

一条管道打通「子域名发现 → 端口扫描 → Web 探测 → 指纹识别 → 漏洞扫描 → 安全检测 → 风险评分 → 变更检测 → 资产关联 → 多渠道告警」全流程

</div>

---

## 📸 界面预览

<table>
  <tr>
    <td width="50%" align="center"><b>仪表盘 · 扫描总览</b></td>
    <td width="50%" align="center"><b>资产清单 · FOFA 风格</b></td>
  </tr>
  <tr>
    <td><img src="readme_resource/scan_1.png" alt="Dashboard"/></td>
    <td><img src="readme_resource/scan_2.png" alt="Assets"/></td>
  </tr>
</table>

---

## ✨ 核心亮点

| 维度 | 能力 |
|------|------|
| 🔍 **一站式管道** | 10 个扫描阶段、6 套预设引擎、20+ 检测模块，单次任务全覆盖 |
| 🧬 **9800+ 指纹** | Wappalyzer + FingerprintHub + nuclei tech-detect 三库融合 |
| 🔴 **CVE 自动关联** | 指纹版本 → OSV/NVD → CVE + CVSS，闭环到风险评分 |
| 🛡 **深度安全检测** | SSL/TLS / 邮件安全 / 未授权接口 / WAF / CORS / 弱口令 / 安全头 |
| 🔌 **插件系统** | 13 个内置插件 + 社区扩展（`data/plugins/` 放 `.py` 即自动注册）|
| 📊 **风险评分** | 6 维加权（敏感路径 / 高危端口 / CVE / SSL / 漏洞 / 威胁情报）|
| 🔄 **变更检测** | 多维度 Diff + 资产生命周期时间线（全行业独占）|
| 👥 **RBAC 权限** | 4 角色 × 9 权限，菜单与操作动态过滤 |
| 📄 **专业报告** | PDF/HTML 渗透报告（封面 + 执行摘要 + 风险矩阵 + 漏洞详情 + 修复建议）|
| 🔔 **6 渠道告警** | Webhook / 钉钉 / 企业微信 / 飞书 / Telegram / 邮件 |

---

## 🏗 架构

```
┌─────────────────────────────────────────────────────┐
│                   Vue 3 + Element Plus               │
│  Dashboard │ Tasks │ Assets │ ASM │ Plugins │ Stats  │
└──────────────────────┬──────────────────────────────┘
                       │ REST API + SSE
┌──────────────────────┴──────────────────────────────┐
│                  FastAPI + PostgreSQL                 │
│   Auth(JWT+RBAC) │ Scan Engine │ Alert │ Report      │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────┐
│              NetProbe 扫描引擎 (Python)               │
│                                                       │
│  子域名    端口扫描    Web探测    指纹识别    漏洞扫描  │
│  subfinder  nmap      httpx     9800+规则   nuclei   │
│  crt.sh     masscan   playwright  version   CVE关联   │
│  FOFA       rustscan              提取      OSV/NVD  │
│                                                       │
│  ──────── 插件系统 (13 内置 + 社区扩展) ──────────    │
│  SSL深度│CORS│安全头│未授权接口│弱口令│WAF│邮件安全    │
│  管理后台│robots│目录爆破│接管检测│CDN真实IP│CVE关联   │
│                                                       │
│  风险评分 → 变更Diff → 资产关联 → 告警通知             │
└───────────────────────────────────────────────────────┘
```

---

## 🚀 快速开始

### Docker 部署（推荐）

```bash
git clone https://github.com/Evan-lium/NetProbe.git
cd NetProbe
docker compose up -d
```

访问 `http://localhost:8000`，默认账号 `admin / admin`

> 容器预装 nmap / masscan / subfinder / nuclei / Playwright，开箱即用。
> PostgreSQL 自动启动并持久化，无需额外配置。

### 手动部署

```bash
# 后端
pip install -r server/requirements.txt
uvicorn server.main:app --host 0.0.0.0 --port 8000 --reload

# 前端（另开终端）
cd frontend && npm install && npm run dev
# 访问 http://localhost:5173
```

> 不设 `DATABASE_URL` 环境变量时自动使用 SQLite（零配置）。
> 连 PostgreSQL：`export DATABASE_URL=postgresql://user:pass@localhost:5432/netprobe`

### 外部工具（按需安装）

| 工具 | 用途 | 安装 |
|------|------|------|
| **nmap** | 端口扫描（必选）| [nmap.org](https://nmap.org/download.html) |
| **subfinder** | 被动子域名 | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **nuclei** | 漏洞扫描 | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **masscan** | 高速端口（可选）| `apt install masscan` / `brew install masscan` |
| **rustscan** | 快速端口（可选）| [GitHub Releases](https://github.com/RustScan/RustScan/releases) |

---

## 📋 功能清单

### 扫描管道

| 阶段 | 能力 | 数据源 |
|------|------|--------|
| 子域名发现 | 被动 + 主动枚举 | subfinder / crt.sh / FOFA / Hunter / DNS 爆破 |
| 端口扫描 | 三引擎自动调度 | nmap / masscan / rustscan |
| Web 探测 | HTTP 指纹 + 截图 | httpx / Python requests / Playwright |
| 指纹识别 | 9800+ 规则三库融合 | Wappalyzer + FingerprintHub + nuclei tech-detect |
| 漏洞扫描 | 模板化检测 | nuclei v3 |
| CVE 关联 | 版本→CVE 自动匹配 | OSV API + NVD API |
| 安全检测 | 13 个插件模块 | 见下方插件列表 |

### 安全检测插件（13 个）

| 插件 | 检测内容 | 分类 |
|------|---------|------|
| 🔒 SSL/TLS 深度 | 弱协议 / 弱加密 / 证书过期 / 自签名 / 域名不匹配 | 漏洞 |
| 🔓 未授权接口 | Swagger / actuator / phpinfo / .env / Druid 等 40+ 路径 | 漏洞 |
| 🌐 CORS 检测 | 宽松跨域 / 通配符 Origin / 凭证+通配 | 漏洞 |
| 🛡 安全响应头 | HSTS / X-Frame-Options / CSP / X-Content-Type-Options | 漏洞 |
| 🔑 弱口令爆破 | SSH / MySQL / Redis / FTP / PostgreSQL | 漏洞 |
| 🧱 WAF 识别 | Cloudflare / 阿里云 / 腾讯云 / 360 / Imperva 等 20+ | 信息 |
| 📧 邮件安全 | SPF / DKIM / DMARC / MTA-STS | 漏洞 |
| ⚙ 管理后台 | title / URL / 正文三重判定 | 侦察 |
| 🗺 robots/sitemap | 路径提取 + 隐藏接口发现 | 侦察 |
| ⚠ 子域名接管 | CNAME 悬挂 / dangling DNS | 漏洞 |
| 📂 目录爆破 | 字典枚举（114 词表）| 侦察 |
| 📍 CDN 真实 IP | 证书 SAN + 历史 DNS + favicon hash | 侦察 |
| 🔴 CVE 关联 | 指纹版本 → OSV/NVD | 漏洞 |

### 资产管理

- **FOFA 风格资产清单** — 跨扫描去重聚合，站点标题 / 技术栈 / 端口 / 漏洞数一目了然
- **资产标签 / 分组** — 自定义标签（重要 / 影子 / 废弃 / 核心 / 测试）
- **资产关联图谱** — ECharts 力导向图（IP / 证书 / Banner / 指纹 / ASN）
- **变更 Diff** — 左右分栏对比，端口 / Web / 技术栈 / 敏感路径变化高亮
- **资产生命周期** — 跨扫描时间线，新增 / 消失 / 变化趋势

### 攻击面管理（ASM）

- **ASM 总览** — 监控目标 + 漏洞生命周期 + 扫描趋势 + 告警 + 标签统计
- **漏洞生命周期** — 7 状态流转（待处理 → 已确认 → 修复中 → 已修复 → 已验证 → 已关闭 + 误报）
- **巡航模式** — 定时扫描 + 自动 Diff 告警

### 团队协作

- **RBAC** — 管理员 / 扫描员 / 审计员 / 只读，4 角色 × 9 权限
- **专业报告** — PDF/HTML（封面 + 执行摘要 + 风险矩阵 + 漏洞详情 + 修复建议 + 资产清单）
- **多渠道告警** — Webhook / 钉钉 / 企业微信 / 飞书 / Telegram / 邮件

---

## 🖥 命令行（CLI）

```bash
# 扫描
python main.py scan example.com
python main.py scan example.com -f json -o report.json

# CI/CD 模式（高危退出码非零）
python main.py ci example.com --severity-threshold 70

# 更新指纹库
python main.py update-fingerprints
```

---

## 🔧 配置

### 环境变量

```yaml
environment:
  DATABASE_URL: postgresql://netprobe:netprobe123@postgres:5432/netprobe
  FOFA_EMAIL: ""        # FOFA 邮箱
  FOFA_KEY: ""          # FOFA API Key
  HUNTER_KEY: ""        # 奇安信鹰图
  NVD_API_KEY: ""       # NVD 漏洞库
  SHODAN_API_KEY: ""    # Shodan
  GITHUB_TOKEN: ""      # GitHub 代码泄露监控
  NETPROBE_SECRET_KEY: ""  # JWT 密钥（生产环境务必修改）
```

### 插件开发

将 `.py` 放入 `data/plugins/` 即自动注册：

```python
from netprobe.plugins.base import Plugin

class MyPlugin(Plugin):
    name = 'my_plugin'
    display_name = '我的检测插件'
    description = '自定义安全检测'
    category = 'vuln'    # vuln / recon / info
    stage = 'vuln'       # vuln / web / sensitive / takeover
    icon = '🔬'
    is_builtin = False

    def run(self, hosts, options, emit=None):
        # 检测逻辑，结果追加到 host['vulnerabilities']
        return findings_count
```

---

## 📊 数据规模

| 指标 | 数量 |
|------|------|
| Web 指纹规则 | 9,876 条（三库融合 + 版本提取 485 条）|
| 敏感路径规则 | 566 条 |
| 安全检测插件 | 13 个内置 + 社区扩展 |
| 预设扫描引擎 | 6 套 |
| API 端点 | 19 个路由模块 |
| 前端页面 | 18 个 |
| Python 模块 | 99 个 |
| 数据库表 | 16 张 |

---

## 🛠 技术栈

| 类别 | 技术 |
|------|------|
| 后端 | FastAPI + SQLAlchemy + Pydantic v2 + APScheduler |
| 数据库 | PostgreSQL / SQLite（双后端，环境变量切换）|
| 认证 | JWT + bcrypt + RBAC 4 角色 |
| 前端 | Vue 3 + TypeScript + Element Plus + ECharts + vue-i18n |
| 构建 | Vite + Docker 多阶段构建 |
| 扫描引擎 | nmap / masscan / rustscan / subfinder / nuclei / Playwright |

---

## 📜 法律与免责声明

本工具仅供**合法的安全研究和授权测试**使用。使用前请确保：

1. 已获得目标系统的**明确授权**
2. 遵守当地**法律法规**
3. 仅用于自有资产审计、授权渗透测试、安全教学与研究

使用者因不当使用而产生的一切法律责任，由使用者**自行承担**。

---

## 🙏 致谢

- [Nmap](https://nmap.org/) · [subfinder](https://github.com/projectdiscovery/subfinder) · [nuclei](https://github.com/projectdiscovery/nuclei) · [masscan](https://github.com/robertdavidgraham/masscan)
- [Wappalyzer](https://github.com/wappalyzer/wappalyzer) · [FingerprintHub](https://github.com/0x727/FingerprintHub) · [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
- [crt.sh](https://crt.sh/) · [FOFA](https://fofa.info/) · [Hunter](https://hunter.qianxin.com/)
- [FastAPI](https://fastapi.tiangolo.com/) · [Vue.js](https://vuejs.org/) · [Element Plus](https://element-plus.org/) · [ECharts](https://echarts.apache.org/)

---

## 📄 开源协议

[Apache License 2.0](LICENSE)

```
Copyright 2024-2026 Evan-lium
Licensed under the Apache License, Version 2.0
```
