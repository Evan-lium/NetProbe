# NetProbe v3.0 架构设计文档

> 版本: 3.0 | 日期: 2026-07-02 | 状态: 已实施（Phase 1-4 落地，v2.2 剩余：定时扫描、Diff 对比）

---

## 1. 概述

### 1.1 背景

NetProbe v2.x 是 Flask 单体应用，所有前端代码内联在一个 995 行的 `index.html` 中（CSS + JS + HTML），扫描结果仅存储在 Python 内存 dict 中，服务重启数据即丢失。随着功能持续增长（历史记录、资产管理、设置、告警），单体架构已无法支撑。

### 1.2 目标

| 目标 | 说明 |
|------|------|
| 一站式管道 | 子域名 → 端口 → Web → 指纹 → 敏感路径 → JS 分析 → 报告，单工具全链路 |
| 前后端分离 | Vue 前端 + Python FastAPI REST API，独立开发部署 |
| 持久化资产库 | SQLite 存储所有扫描结果，跨扫描资产聚合，历史可追溯 |
| 变更检测 | 同目标多次扫描自动 diff，新增/消失/变化高亮 |
| 智能风险评分 | 综合指纹版本 × CVE × 敏感路径 × 威胁情报的上下文评分 |
| 可扩展架构 | Blueprint 分层、Service 层解耦，为后续插件系统打基础 |

### 1.3 竞品定位

```
                        资产发现能力
                     完整 ←────────→ 单一
                      │
                 ARL (已停更)        OneForAll (子域名)
                 SpiderFoot (OSINT)  httpx (探测)
                  ★ NetProbe ★       nuclei (漏洞)
                      │              Ehole (指纹)
                      │
                 有 Web UI ←───→ 无 Web UI
                 + 持久化          纯 CLI
                 + 变更检测
                 + 风险评分
```

**NetProbe 在开源工具中的定位：**

| 象限 | 代表工具 | NetProbe 差异 |
|------|----------|--------------|
| 纯子域名枚举 | OneForAll, Amass, subfinder | NetProbe 覆盖全链路，不只枚举子域名 |
| 纯探测/指纹 | httpx, Ehole, Finger, ObserverWard | NetProbe 内置探测+指纹，无需串联 |
| 纯漏洞扫描 | nuclei, Nuclei-Templates | NetProbe 先做资产发现，再做漏洞关联 |
| 桌面端工具 | Goby | NetProbe 是 Web 应用，有 API，可自动化 |
| 企业平台 | 长亭云图、鹰图、FOFA、微步 | NetProbe 开源免费，小团队可用 |
| 已停更 | ARL | NetProbe 活跃开发，现代技术栈 |

**核心差异化：开源领域唯一同时做到以下 5 点的工具：**
1. 一站式扫描管道（不需串联多个工具）
2. 持久化资产库 + 跨扫描聚合
3. 多次扫描自动变更检测
4. 综合风险评分（指纹+CVE+威胁情报）
5. 中英文情报源融合

### 1.4 技术栈全景

```
┌──────────────────────────────────────────────────────────────┐
│                        用户浏览器                             │
│                  Vue 3 + TypeScript 5                        │
│              Element Plus + Vue Router 4 + Pinia             │
└──────────────────────┬───────────────────────────────────────┘
                       │ Axios (REST) / EventSource (SSE)
                       ▼
┌──────────────────────────────────────────────────────────────┐
│                    FastAPI (REST API)                        │
│                 SQLAlchemy 2 / Pydantic 2                    │
├──────────────────────────────────────────────────────────────┤
│  routers/ (APIRouter 路由层)                                 │
│    scan / result / history / assets / settings / tools        │
├──────────────────────────────────────────────────────────────┤
│  services/ (业务逻辑层)                                      │
│    scan_service / history_service / asset_service             │
├──────────┬───────────────────────────────────────────────────┤
│  models/ │              netprobe/ (扫描引擎)                  │
│  (ORM)   │  engine / scanner / web_probe / fingerprint / ...  │
├──────────┴───────────────────────────────────────────────────┤
│                     SQLite (持久化)                           │
│              Playwright (PDF 导出)                            │
└──────────────────────────────────────────────────────────────┘
```

| 分类 | 技术 | 版本 | 用途 | 选型理由 |
|------|------|------|------|----------|
| **前端** | | | | |
| 框架 | Vue 3 | 3.5+ | SPA 单页应用 | 国内安全工具标配（ARL/Goby 均用 Vue），学习成本最低 |
| 语言 | TypeScript | 5.x | 类型安全 | 编译期捕获错误、IDE 提示友好、重构可靠 |
| 构建 | Vite | 6.x | 开发热更新、生产打包 | Vue 官方推荐、启动秒级、HMR 极快 |
| UI 库 | Element Plus | 2.x | 企业级组件 | 国内 Vue 生态第一 UI 库，表格/表单/导航完善，自动导入 |
| 状态管理 | Pinia | 2.x | 全局状态 | Vue 官方推荐，轻量，TypeScript 友好 |
| 路由 | Vue Router | 4.x | 前端路由 | 声明式路由、嵌套路由、URL 参数 |
| HTTP | Axios | 1.x | API 请求 | 拦截器、取消请求、JSON 自动转换 |
| 国际化 | vue-i18n | 11.x | 中英文切换 | 内置 zh-CN / en 两套 locale，按浏览器语言默认 |
| **后端** | | | | |
| 框架 | FastAPI | 0.115+ | REST API | 自动 OpenAPI 文档、原生 SSE、Pydantic 校验 |
| 服务器 | Uvicorn | 0.30+ | ASGI 服务器 | FastAPI 标准运行时，支持 async |
| ORM | SQLAlchemy | 2.x | 数据库操作 | 自动建表、关系映射、sync 模式适配 SQLite |
| 跨域 | CORSMiddleware | 内置 | 开发环境跨域 | FastAPI 内置，无需额外依赖 |
| **数据** | | | | |
| 数据库 | SQLite | 3.45+ | 持久化存储 | 零配置、单文件、适合单机安全工具 |
| **导出** | | | | |
| PDF | Playwright | 1.4x+ | HTML → PDF | Chromium 渲染、中文零配置、已集成 |
| **引擎** | | | | |
| 扫描 | netprobe 包 | 2.0 | 全部扫描逻辑 | 已完成、保持不变 |
| 端口扫描 | python-nmap | 0.7+ | Nmap 封装 | 行业标准端口扫描器 |
| DNS | dnspython | 2.8+ | DNS 解析 | 全功能 DNS 工具库 |
| HTTP | requests | 2.28+ | Web 探测 | 最流行的 Python HTTP 库 |

### 1.5 架构对比（v2 vs v3）

| 维度 | v2.x（当前） | v3.0（目标） |
|------|-------------|-------------|
| 前端 | 内联 HTML + CSS + JS（995 行单文件） | Vue 3 + TypeScript + Element Plus（模块化） |
| 后端 | Flask 单文件（176 行） | FastAPI + APIRouter + Service 分层 |
| 数据存储 | Python 内存 dict（重启丢失） | SQLite 数据库（7 张表，持久化） |
| 导航 | 无（单页） | 多页面（侧边栏/顶部可切换） |
| 构建 | 无构建步骤 | Vite（热更新 + 生产优化） |
| 部署 | `python app.py` | `uvicorn server.main:app`（开发）或 `npm run build` + FastAPI 静态挂载（生产） |

---

## 2. 项目结构

```
NetProbe/
│
├── server/                            # ── FastAPI 后端 ──
│   ├── __init__.py                    # create_app() 工厂函数
│   ├── main.py                        # uvicorn 启动入口
│   ├── config.py                      # Pydantic Settings 配置
│   ├── db.py                          # SQLAlchemy engine + SessionLocal
│   │
│   ├── models/                        # SQLAlchemy ORM 模型
│   │   ├── __init__.py                # Base + init_db() + import all
│   │   ├── scan.py                    # Scan 模型
│   │   ├── host.py                    # Host, Port, Banner 模型
│   │   └── web.py                     # WebInfo, SensitivePath, JSFinding 模型
│   │
│   ├── schemas/                       # Pydantic 请求/响应模型
│   │   ├── __init__.py
│   │   ├── scan.py                    # ScanRequest, ScanResponse, ScanResult
│   │   ├── history.py                 # HistoryItem, HistoryList
│   │   └── asset.py                   # AssetSummary
│   │
│   ├── routers/                       # APIRouter 路由层
│   │   ├── __init__.py                # include_all_routers(app)
│   │   ├── scan.py                    # POST /api/scan, GET /api/stream/:id
│   │   ├── result.py                  # GET /api/result/:id, GET /api/download/:id/:fmt
│   │   ├── tasks.py                   # GET /api/tasks, GET/POST-cancel /api/tasks/:id, DELETE
│   │   ├── history.py                 # GET /api/history, GET/DELETE /api/history/:id
│   │   ├── assets.py                  # GET /api/assets
│   │   ├── settings.py                # GET/PUT /api/settings
│   │   └── tools.py                   # GET /api/tools
│   │
│   └── services/                      # 业务逻辑层（路由与引擎之间的桥梁）
│       ├── __init__.py
│       ├── scan_service.py            # 扫描任务管理（线程、SSE、双写）
│       ├── history_service.py         # 历史查询（分页、搜索、统计）
│       └── asset_service.py           # 资产聚合查询（跨 scan 汇总）
│
├── frontend/                          # ── Vue 3 前端（Vite 项目）──
│   ├── package.json
│   ├── vite.config.ts                 # Element Plus auto-import + API proxy
│   ├── tsconfig.json
│   ├── index.html                     # Vite 入口 HTML
│   │
│   ├── public/
│   │   └── favicon.svg
│   │
│   └── src/
│       ├── main.ts                    # Vue 挂载入口（createApp + router + pinia）
│       ├── App.vue                    # 根组件：<router-view> + 布局壳
│       │
│       ├── router/
│       │   └── index.ts               # 路由定义（6 个页面）
│       │
│       ├── stores/                    # Pinia 状态管理
│       │   ├── scan.ts                # 扫描状态（taskId, status, events, hosts）
│       │   └── app.ts                 # 全局状态（布局模式、工具状态）
│       │
│       ├── layouts/                   # 布局组件
│       │   ├── SidebarLayout.vue      # 左侧固定侧边栏布局（默认）
│       │   └── TopNavLayout.vue       # 顶部水平导航栏布局
│       │
│       ├── views/                     # 页面组件（每个对应一个路由）
│       │   ├── Dashboard.vue          # /          扫描首页
│       │   ├── ScanResult.vue         # /scan/:id  实时扫描结果（SSE）
│       │   ├── History.vue            # /history   历史记录列表
│       │   ├── ScanDetail.vue         # /history/:id  历史扫描详情
│       │   ├── Assets.vue             # /assets    资产清单
│       │   └── Settings.vue           # /settings  系统设置
│       │
│       ├── components/                # 可复用业务组件
│       │   ├── ScanForm.vue           # 扫描表单（目标、选项、引擎选择器）
│       │   ├── ProgressLog.vue        # SSE 实时进度日志（暗色终端风格）
│       │   ├── HostCard.vue           # 主机结果卡片（可展开）
│       │   ├── PortTable.vue          # 端口列表
│       │   ├── WebInfoTable.vue       # Web 站点列表（SSL 标签、技术栈 Tag）
│       │   ├── SensitiveTable.vue     # 敏感路径列表（风险等级着色）
│       │   ├── JSAnalysisTable.vue    # JS 分析列表
│       │   ├── BannerTable.vue        # Banner 列表
│       │   └── StatsGrid.vue          # 统计概览（4 格数字卡片）
│       │
│       ├── api/                       # API 调用封装
│       │   ├── index.ts               # axios 实例 + 拦截器
│       │   └── scan.ts                # 所有 API 方法
│       │
│       ├── types/                     # TypeScript 类型
│       │   └── index.ts               # Scan, Host, Port, WebInfo 等接口定义
│       │
│       └── styles/
│           └── global.css             # Element Plus 主题覆盖 + 全局样式
│
├── netprobe/                          # ── 扫描引擎包（保持不变）──
│   ├── __init__.py
│   ├── engine.py                      # 扫描编排
│   ├── scanner.py                     # Nmap 集成
│   ├── web_probe.py                   # HTTP 探测
│   ├── dns_utils.py                   # DNS 解析
│   ├── fingerprint.py                 # Web 指纹识别
│   ├── banner_grab.py                 # Banner 抓取
│   ├── sensitive_probe.py             # 敏感路径探测
│   ├── js_analyzer.py                 # JS 分析
│   ├── formatter.py                   # 输出格式化（含 Playwright PDF）
│   ├── utils.py                       # 工具函数
│   ├── wordlist.py                    # 子域名字典
│   ├── tools/                         # 外部工具封装
│   │   ├── registry.py
│   │   ├── subfinder.py
│   │   ├── crtsh.py
│   │   ├── fofa.py
│   │   ├── hunter.py
│   │   └── ...
│   └── data/
│       ├── fingerprints.json
│       └── sensitive_paths.json
│
├── main.py                            # CLI 入口（保持不变）
├── instance/                          # SQLite 数据库（运行时生成）
│   └── netprobe.db
└── docs/
    ├── ARCHITECTURE.md                # 本文件
    └── ROADMAP.md
```

---

## 3. 数据库设计

### 3.1 ER 关系

```
scans ──1:N──> hosts ──1:N──> ports
                      ├──1:N──> banners
                      ├──1:N──> web_info
                      ├──1:N──> sensitive_paths
                      └──1:N──> js_findings

settings (独立 key-value 表)
```

### 3.2 表定义

#### scans — 扫描任务

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| scan_id | TEXT | PK | uuid hex（12 位） |
| name | TEXT | DEFAULT '' | 任务名称（用户可自定义，默认自动生成） |
| target_raw | TEXT | NOT NULL | 用户原始输入 |
| base_domain | TEXT | DEFAULT '' | 显示标签（如 `baidu.com+qq.com+1more`） |
| status | TEXT | DEFAULT 'running' | running / done / error |
| options_json | TEXT | DEFAULT '{}' | 扫描选项 JSON |
| host_count | INTEGER | DEFAULT 0 | |
| port_count | INTEGER | DEFAULT 0 | |
| web_count | INTEGER | DEFAULT 0 | |
| sensitive_count | INTEGER | DEFAULT 0 | |
| error_msg | TEXT | DEFAULT '' | 错误信息 |
| started_at | DATETIME | NOT NULL | |
| finished_at | DATETIME | | |
| duration_secs | INTEGER | | 耗时秒数 |

#### hosts — 主机

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| host_id | INTEGER | PK AUTO | |
| scan_id | TEXT | FK → scans | ON DELETE CASCADE |
| target | TEXT | DEFAULT '' | 所属扫描目标 |
| hostname | TEXT | DEFAULT '' | |
| ip | TEXT | DEFAULT '' | |
| os_info | TEXT | DEFAULT '' | |
| sort_order | INTEGER | DEFAULT 0 | 显示排序 |

#### ports — 端口

| 字段 | 类型 | 约束 |
|------|------|------|
| port_id | INTEGER | PK AUTO |
| host_id | INTEGER | FK → hosts, CASCADE |
| port | INTEGER | NOT NULL |
| proto | TEXT | DEFAULT 'tcp' |
| state | TEXT | DEFAULT 'open' |
| service | TEXT | DEFAULT '' |
| product | TEXT | DEFAULT '' |
| version | TEXT | DEFAULT '' |

#### banners — 服务 Banner

| 字段 | 类型 | 约束 |
|------|------|------|
| banner_id | INTEGER | PK AUTO |
| host_id | INTEGER | FK → hosts, CASCADE |
| port | INTEGER | NOT NULL |
| service | TEXT | DEFAULT '' |
| banner | TEXT | DEFAULT '' |

#### web_info — Web 站点

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| web_id | INTEGER | PK AUTO | |
| host_id | INTEGER | FK → hosts, CASCADE | |
| port | INTEGER | NOT NULL | |
| url | TEXT | NOT NULL | |
| status_code | INTEGER | | |
| title | TEXT | DEFAULT '' | |
| redirect | TEXT | DEFAULT '' | |
| headers_json | TEXT | DEFAULT '{}' | `{server, powered_by, framework, cms}` |
| tech_json | TEXT | DEFAULT '[]' | `[{name, category}, ...]` |
| ssl_json | TEXT | DEFAULT 'null' | `{subject, issuer, protocol, expired}` |

#### sensitive_paths — 敏感路径

| 字段 | 类型 | 约束 |
|------|------|------|
| id | INTEGER | PK AUTO |
| host_id | INTEGER | FK → hosts, CASCADE |
| path | TEXT | NOT NULL |
| description | TEXT | DEFAULT '' |
| severity | TEXT | DEFAULT 'info' |
| status_code | INTEGER | |

#### js_findings — JS 分析

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| id | INTEGER | PK AUTO | |
| host_id | INTEGER | FK → hosts, CASCADE | |
| js_url | TEXT | NOT NULL | |
| api_endpoints_json | TEXT | DEFAULT '[]' | `["/api/v1/...", ...]` |
| secrets_json | TEXT | DEFAULT '[]' | `[{type, match, severity}, ...]` |

#### settings — 系统设置

| 字段 | 类型 | 约束 |
|------|------|------|
| key | TEXT | PK |
| value | TEXT | NOT NULL |

### 3.3 索引

```sql
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_started ON scans(started_at DESC);
CREATE INDEX idx_hosts_scan ON hosts(scan_id);
CREATE INDEX idx_hosts_ip ON hosts(ip);
CREATE INDEX idx_hosts_hostname ON hosts(hostname);
CREATE INDEX idx_ports_host ON ports(host_id);
CREATE INDEX idx_web_info_host ON web_info(host_id);
CREATE INDEX idx_banners_host ON banners(host_id);
CREATE INDEX idx_sensitive_host ON sensitive_paths(host_id);
CREATE INDEX idx_js_findings_host ON js_findings(host_id);
```

### 3.4 JSON 列设计说明

`tech_json`、`ssl_json`、`headers_json`、`api_endpoints_json`、`secrets_json` 使用 JSON 文本存储嵌套数据。

**为什么不用关联表**：这些数据仅用于展示渲染，不需要按子字段单独查询。用 JSON 列避免 5 张额外的 JOIN 表，保持查询简洁。如果未来需要按技术栈搜索资产，可以在 `hosts` 表加一个 `tech_names` 平铺列。

---

## 4. REST API 设计

### 4.1 通用约定

- 前缀: `/api`
- 数据格式: JSON (`Content-Type: application/json`)
- 错误响应: `{"error": "描述信息"}` + HTTP 状态码
- 分页参数: `?page=1&per_page=20`
- 时间格式: ISO 8601 (`2026-05-25T21:30:00`)

### 4.2 扫描 API

#### POST /api/scan — 启动扫描

**请求:**
```json
{
  "target": "example.com",
  "name": "任务名称（可选，默认自动生成）",
  "no_dns_brute": false,
  "no_web": false,
  "no_validate": false,
  "timeout": 300,
  "subdomain_tool": "auto",
  "portscan_tool": "auto",
  "web_tool": "auto",
  "dns_tool": "auto",
  "port_preset": "common",
  "custom_ports": ""
}
```

> `port_preset` 取值：`common`（常用端口）/ `top1000` / `all` / `custom`（自定义，此时填 `custom_ports`，如 `"80,443,8080"`）。

**响应:**
```json
{
  "task_id": "a1b2c3d4e5f6",
  "status": "running"
}
```

#### GET /api/stream/\<scan_id\> — SSE 实时进度

**Content-Type:** `text/event-stream`

**事件格式:**
```
data: {"event": "progress", "text": "[+] 发现子域名: www.example.com"}

data: {"event": "done", "hosts": [...], "base_domain": "example.com"}

data: {"event": "error", "text": "扫描异常: timeout"}

data: {"event": "heartbeat"}
```

#### GET /api/result/\<scan_id\> — 获取扫描结果

**响应:**
```json
{
  "scan_id": "a1b2c3d4e5f6",
  "status": "done",
  "base_domain": "example.com",
  "hosts": [
    {
      "host_id": 1,
      "hostname": "www.example.com",
      "ip": "93.184.216.34",
      "os_info": "",
      "ports": [...],
      "banners": [...],
      "web_info": [...],
      "sensitive": [...],
      "js_findings": [...]
    }
  ]
}
```

#### GET /api/download/\<scan_id\>/\<fmt\> — 下载报告

- `fmt`: txt / csv / json / pdf
- 返回文件附件

### 4.3 任务 API

> 任务 API 是前端 `/tasks` 页面的数据来源，合并展示「内存中活跃任务」与「数据库中已完成任务」，并提供运行中任务的取消能力。

#### GET /api/tasks — 任务列表

合并返回内存中活跃任务（含运行进度）与 DB 中最近 50 条已完成任务，运行中任务排在前。

**响应:** `{"items": [...], "total": N}`，每项含 `id/scan_id/name/target/status/host_count/port_count/web_count/started_at/finished_at/duration_secs/progress/options/error_msg`。

#### GET /api/tasks/\<task_id\> — 任务详情

先查内存（运行中，带实时 progress），未命中则回退 DB。

#### POST /api/tasks/\<task_id\>/cancel — 取消任务

仅对运行中任务生效。置 `cancel_event` 信号 → 终止所有跟踪的子进程（nmap/masscan/rustscan）→ 推送 `cancelled` SSE 事件 → 更新 DB 状态为 `cancelled`。

#### DELETE /api/tasks/\<task_id\> — 删除任务

若仍在运行先取消，再从内存移除并级联删除 DB 中该 scan 及其全部关联数据。

### 4.4 历史 API

> 历史 API（`/api/history`）仍保留可用，但前端默认入口已迁移到 `/api/tasks`。两者底层共用同一批 scan 记录。

#### GET /api/history — 扫描列表

**参数:** `?page=1&per_page=20&q=example&status=done`

**响应:**
```json
{
  "items": [
    {
      "scan_id": "a1b2c3d4e5f6",
      "target_raw": "example.com",
      "base_domain": "example.com",
      "status": "done",
      "host_count": 5,
      "port_count": 12,
      "web_count": 8,
      "sensitive_count": 3,
      "started_at": "2026-05-25T21:30:00",
      "finished_at": "2026-05-25T21:32:15",
      "duration_secs": 135
    }
  ],
  "total": 42,
  "page": 1,
  "per_page": 20
}
```

#### GET /api/history/\<scan_id\> — 扫描详情

同 `/api/result/<scan_id>` 响应格式，但从数据库读取。

#### DELETE /api/history/\<scan_id\> — 删除扫描

级联删除所有关联 hosts、ports、web_info 等数据。

**响应:** `{"ok": true}`

### 4.5 资产 API

#### GET /api/assets — 跨扫描资产汇总

**参数:** `?q=example&sort=last_seen`

**响应:**
```json
{
  "items": [
    {
      "ip": "93.184.216.34",
      "hostname": "www.example.com",
      "first_seen": "2026-05-20T10:00:00",
      "last_seen": "2026-05-25T21:30:00",
      "scan_count": 3,
      "port_count": 4,
      "web_count": 2
    }
  ],
  "total": 15
}
```

**SQL 逻辑:**
```sql
SELECT h.ip, h.hostname,
       MIN(s.started_at) AS first_seen,
       MAX(s.started_at) AS last_seen,
       COUNT(DISTINCT h.scan_id) AS scan_count
FROM hosts h JOIN scans s ON h.scan_id = s.scan_id
WHERE s.status = 'done'
GROUP BY h.ip, h.hostname
```

#### GET /api/assets/\<ip\> — 单 IP 详情

返回该 IP 在所有扫描中的端口、Web、技术栈聚合信息。

### 4.6 设置 API

#### GET /api/tools — 工具可用性

**响应:**
```json
{
  "nmap": true,
  "subfinder": false,
  "masscan": false,
  "rustscan": false,
  "httpx": false,
  "dnsx": false,
  "nuclei": false
}
```

#### GET /api/settings — 获取设置

**响应:**
```json
{
  "fofa_email": "",
  "fofa_key": "",
  "hunter_key": "",
  "default_timeout": 300
}
```

#### PUT /api/settings — 更新设置

**请求:** 同 GET 响应格式。只更新传入的字段。

---

## 5. 前端页面设计

### 5.1 路由表

| 路径 | 组件 | 说明 |
|------|------|------|
| `/` | Dashboard | 扫描首页（表单 + 最近扫描） |
| `/scan/:id` | ScanResult | 实时扫描结果（SSE 驱动） |
| `/tasks` | Tasks | 任务列表（活跃运行中 + 历史已完成，含取消/删除/内嵌表单） |
| `/tasks/:id` | ScanDetail | 任务详情（数据库加载） |
| `/assets` | Assets | 资产清单 |
| `/settings` | Settings | 系统设置 |

> 旧版 `/history` 与 `/history/:id` 已重定向到 `/tasks` 与 `/tasks/:id`。History 组件保留但默认路由不再挂载。

### 5.2 页面详细设计

#### Dashboard（/）

```
┌─────────────────────────────────────────┐
│  扫描目标                                │
│  ┌─────────────────────────────────────┐│
│  │ example.com                         ││
│  │                                     ││
│  └─────────────────────────────────────┘│
│  ☑ 子域名枚举  ☑ Web 探测  ☐ DNS 验证  │
│  子域名引擎: [auto ▾]  端口引擎: [auto ▾]│
│                          [🚀 开始扫描]   │
├─────────────────────────────────────────┤
│  最近扫描                                │
│  ┌─────────────────────────────────────┐│
│  │ example.com  done  5主机  12端口     ││
│  │ test.com     done  3主机  8端口      ││
│  │ ...                                 ││
│  └─────────────────────────────────────┘│
└─────────────────────────────────────────┘
```

- ScanForm 组件（复用）
- 最近 5 条扫描记录（API: `GET /api/history?per_page=5`）
- 点击"开始扫描"后跳转到 `/scan/:id`

#### ScanResult（/scan/:id）

```
┌─────────────────────────────────────────┐
│ 主机: 5  端口: 12  Web: 8  敏感: 3      │
│ [TXT] [CSV] [JSON] [PDF]               │
├─────────────────────────────────────────┤
│ ┌─ 实时进度 ───────────────────────────┐│
│ │ [+] 发现子域名: www.example.com      ││
│ │ [+] 端口扫描: 80/tcp open            ││
│ │ [*] Web 探测: https://... 200 OK     ││
│ └─────────────────────────────────────-┘│
│                                          │
│ ▼ [1] www.example.com (93.184.216.34)   │
│   端口: 80, 443, 22                     │
│   Web: https://... "Example" [200]      │
│   Banner: SSH-2.0-OpenSSH_8.9          │
│                                          │
│ ▶ [2] api.example.com (10.0.0.1)       │
└─────────────────────────────────────────┘
```

- SSE 连接实时更新（useSSE hook）
- 进度日志（ProgressLog 组件，暗色终端风格）
- 主机列表（HostCard 组件，可展开）
- 统计卡片（StatsGrid 组件）
- 下载按钮栏

#### History（/history）

```
┌─────────────────────────────────────────┐
│ [🔍 搜索目标...]  状态: [全部▾]  日期范围 │
├─────────────────────────────────────────┤
│ 时间       │ 目标          │状态│主机│操作 │
│ 05-25 21:30│ example.com   │ ✓ │ 5  │👁 🗑 │
│ 05-25 20:15│ test.com      │ ✓ │ 3  │👁 🗑 │
│ 05-24 18:00│ demo.cn       │ ✗ │ 0  │👁 🗑 │
│                                          │
│              < 1 2 3 >                   │
└─────────────────────────────────────────┘
```

- Element Plus Table + 搜索 + 筛选 + 分页
- 操作：查看详情（跳转 /history/:id）、删除（确认弹窗）、下载

#### ScanDetail（/history/:id）

布局同 ScanResult，但数据通过 `GET /api/history/:id` 从数据库加载，无 SSE。

#### Assets（/assets）

```
┌─────────────────────────────────────────┐
│ [🔍 搜索...]  排序: [最近发现 ▾]        │
├─────────────────────────────────────────┤
│ IP             │ 主机名      │端口│扫描次数│
│ 93.184.216.34  │ www.example │ 4  │ 3     │
│ 10.0.0.1       │ api.example │ 2  │ 1     │
│                                          │
│ ▼ 93.184.216.34 详细信息                │
│   端口: 80/tcp http, 443/tcp https      │
│   Web: https://www.example.com [200]    │
│   技术: nginx, PHP, MySQL               │
│   首次发现: 05-20  最后: 05-25          │
└─────────────────────────────────────────┘
```

- 聚合查询所有扫描中的唯一 (ip, hostname) 对
- 可展开查看端口/Web/技术栈详情

#### Settings（/settings）

```
┌─────────────────────────────────────────┐
│  工具状态                                │
│  ✅ nmap     ❌ subfinder  ❌ masscan   │
│  ❌ rustscan ❌ httpx      ❌ dnsx      │
│  ❌ nuclei                               │
├─────────────────────────────────────────┤
│  API 密钥                                │
│  FOFA Email: [______________]           │
│  FOFA Key:   [______________]           │
│  Hunter Key: [______________]           │
│                          [💾 保存]      │
├─────────────────────────────────────────┤
│  界面设置                                │
│  导航布局:  ○ 侧边栏  ● 顶部导航栏      │
└─────────────────────────────────────────┘
```

---

## 6. 导航系统

### 6.1 布局切换机制

**默认：左侧固定侧边栏**，可在设置页切换为顶部导航栏。

实现方式：
1. Pinia store `app.ts` 读取 `localStorage.getItem('netprobe_layout')`
2. 默认值 `'sidebar'`，可选 `'topnav'`
3. `App.vue` 根据 store 值动态切换组件 `<SidebarLayout>` 或 `<TopNavLayout>`
4. 设置页切换时写 `localStorage` 并通过 `$forceUpdate` 刷新

### 6.2 侧边栏布局

使用 Element Plus `el-container` + `el-aside` + `el-menu`：

```
┌──────────┬──────────────────────────────┐
│ NetProbe │                              │
│ v2.2     │      页面内容区               │
│──────────│                              │
│ ⚡ Scan  │                              │
│ 📋 Hist  │                              │
│ 🖥 Asset │                              │
│ ⚙ Set    │                              │
│──────────│                              │
│ 3/7 工具 │                              │
└──────────┴──────────────────────────────┘
```

- `el-aside` 宽度: 220px，`el-menu` 垂直模式
- 图标用 `@element-plus/icons-vue`
- 当前路由高亮：`useRoute().path` 匹配 `el-menu` 的 `default-active`
- 移动端: `el-drawer` 实现侧边栏折叠

### 6.3 顶部导航布局

使用 Element Plus `el-header` + `el-menu` 水平模式：

```
┌──────────────────────────────────────────┐
│ NetProbe │ Scan │ History │ Assets │ Set │
├──────────────────────────────────────────┤
│                                          │
│              页面内容区（全宽）            │
│                                          │
└──────────────────────────────────────────┘
```

- Menu `mode="horizontal"`
- 同样的导航项和图标
- 内容区无左侧 margin，全宽展示

### 6.4 导航项

| key | 图标 | 标签 | 路径 |
|-----|------|------|------|
| dashboard | `Odometer` | Dashboard | `/` |
| history | `Clock` | Scan History | `/history` |
| assets | `Grid` | Asset Inventory | `/assets` |
| settings | `Setting` | Settings | `/settings` |

---

## 7. TypeScript 类型定义

```typescript
// ── 扫描 ──

interface Scan {
  scan_id: string;
  target_raw: string;
  base_domain: string;
  status: 'running' | 'done' | 'error';
  host_count: number;
  port_count: number;
  web_count: number;
  sensitive_count: number;
  error_msg: string;
  started_at: string;
  finished_at: string | null;
  duration_secs: number | null;
}

interface ScanOptions {
  no_dns_brute: boolean;
  no_web: boolean;
  no_validate: boolean;
  timeout: number;
  subdomain_tool: string;
  portscan_tool: string;
  web_tool: string;
  dns_tool: string;
}

// ── 主机 ──

interface Host {
  host_id: number;
  hostname: string;
  ip: string;
  os_info: string;
  ports: Port[];
  banners: Banner[];
  web_info: WebInfo[];
  sensitive: SensitivePath[];
  js_findings: JSFinding[];
}

interface Port {
  port: number;
  proto: string;
  state: string;
  service: string;
  product: string;
  version: string;
}

interface Banner {
  port: number;
  service: string;
  banner: string;
}

// ── Web ──

interface WebInfo {
  port: number;
  url: string;
  status_code: number;
  title: string;
  redirect: string;
  headers: Record<string, string>;
  tech: TechItem[];
  ssl: SSLInfo | null;
}

interface TechItem {
  name: string;
  category: string;
}

interface SSLInfo {
  subject: string;
  issuer: string;
  protocol: string;
  expired: boolean;
  not_after?: string;
  cipher?: string;
}

// ── 敏感路径 ──

interface SensitivePath {
  path: string;
  description: string;
  severity: 'high' | 'medium' | 'low' | 'info';
  status_code: number;
}

// ── JS 分析 ──

interface JSFinding {
  js_url: string;
  api_endpoints: string[];
  secrets: Secret[];
}

interface Secret {
  type: string;
  match: string;
  severity: string;
}

// ── 资产汇总 ──

interface AssetSummary {
  ip: string;
  hostname: string;
  first_seen: string;
  last_seen: string;
  scan_count: number;
  port_count: number;
  web_count: number;
}

// ── API 响应 ──

interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
}

// ── SSE 事件 ──

type SSEEvent =
  | { event: 'progress'; text: string }
  | { event: 'done'; hosts: Host[]; base_domain: string }
  | { event: 'error'; text: string }
  | { event: 'heartbeat' };

// ── 设置 ──

interface AppSettings {
  fofa_email: string;
  fofa_key: string;
  hunter_key: string;
  default_timeout: number;
}

type LayoutMode = 'sidebar' | 'topnav';
```

---

## 8. 前后端通信

### 8.1 开发环境

```
浏览器 ──> Vite Dev Server (5173) ──proxy /api──> Uvicorn (8000)
                   │
                   └── 热更新 Vue/TS
```

Vite `vite.config.ts` 代理配置：
```typescript
export default defineConfig({
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
});
```

FastAPI 启用 CORS（开发环境）：
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### 8.2 生产环境

```
浏览器 ──> Uvicorn (8000)
              ├── /api/*        → REST API
              └── /*            → Vue 静态文件 (SPA fallback)
```

- `npm run build` 输出到 `frontend/dist/`
- FastAPI 用 `StaticFiles(directory="frontend/dist", html=True)` 挂载静态文件
- `html=True` 启用 SPA fallback（所有未匹配路径返回 `index.html`）
- 或使用 Nginx 反向代理

### 8.3 SSE 连接

- 前端: `EventSource` API（浏览器原生，自动重连）
- 后端: `StreamingResponse(event_generator(), media_type="text/event-stream")`，60 秒心跳
- 后端 SSE 使用同步 `queue.Queue`（StreamingResponse 支持同步生成器，无需 asyncio 改造）
- 扫描完成后 SSE 关闭，前端切换为普通 API 获取最终数据

---

## 9. 实施步骤

### Phase 1: 后端骨架（预计 1-2 天）

| 步骤 | 任务 | 产出 |
|------|------|------|
| 1.1 | 创建 `server/` 目录 + `__init__.py` 工厂 | FastAPI app 可启动 |
| 1.2 | 实现 `db.py` + SQLAlchemy 模型 | 7 张表 + 自动建库 |
| 1.3 | 实现 Pydantic schemas | 请求/响应类型定义 |
| 1.4 | 实现 scan router + service | POST /api/scan, GET /api/stream/:id |
| 1.5 | 实现 result router | GET /api/result/:id, GET /api/download/:id/:fmt |
| 1.6 | 实现 history router + service | 分页列表、详情、删除 |
| 1.7 | 实现 assets router + service | 跨扫描资产聚合 |
| 1.8 | 实现 settings + tools router | 设置 CRUD + 工具检测 |
| 1.9 | 验证：curl 测试所有 API | 全部端点可响应 |

### Phase 2: 前端骨架（预计 1 天）

| 步骤 | 任务 | 产出 |
|------|------|------|
| 2.1 | `npm create vite@latest frontend -- --template vue-ts` | frontend/ 目录 |
| 2.2 | 安装依赖 | element-plus, vue-router, pinia, axios |
| 2.3 | 配置 Vite (Element Plus auto-import + proxy) | vite.config.ts |
| 2.4 | 实现 TypeScript 类型 | types/index.ts |
| 2.5 | 实现 API service 层 | api/index.ts, api/scan.ts |
| 2.6 | 实现 Pinia stores | stores/scan.ts, stores/app.ts |
| 2.7 | 实现布局切换 | layouts/SidebarLayout.vue, TopNavLayout.vue |
| 2.8 | 实现 App.vue + 路由 | router/index.ts |
| 2.9 | 验证：空白页面可见侧边栏，路由可切换 | 布局可用 |

### Phase 3: 页面开发（预计 2-3 天）

| 步骤 | 任务 | 产出 |
|------|------|------|
| 3.1 | Dashboard 页面 | ScanForm + 最近扫描列表 |
| 3.2 | ProgressLog 组件 | SSE 实时进度（暗色终端风格） |
| 3.3 | ScanResult 页面 | SSE 连接 + 实时结果展示 |
| 3.4 | HostCard + 子表格组件 | PortTable, WebInfoTable, BannerTable 等 |
| 3.5 | History 页面 | 搜索 + 筛选 + 分页表格 |
| 3.6 | ScanDetail 页面 | 数据库加载的扫描详情 |
| 3.7 | Assets 页面 | 跨扫描资产汇总表 |
| 3.8 | Settings 页面 | 工具状态 + API Key + 布局切换 |
| 3.9 | 验证：所有页面功能可用 | 完整可操作的 Web UI |

### Phase 4: 集成与收尾（预计 0.5 天）

| 步骤 | 任务 |
|------|------|
| 4.1 | 端到端扫描流程测试（Vue → FastAPI → netprobe → DB → 展示） |
| 4.2 | PDF 导出测试 |
| 4.3 | 生产构建：`npm run build` + FastAPI 静态文件挂载 |
| 4.4 | 清理旧文件（app.py, templates/） |
| 4.5 | 更新 requirements.txt |
| 4.6 | Git 提交推送 |

**总计预计：5-7 天**

> **实施状态（2026-07-02 核对）**：Phase 1-4 已全部落地。后端 7 张表已建（`data/netprobe.db` 内有真实扫描数据验证），前端 `npm run build` 通过，端到端扫描链路（Vue → FastAPI → netprobe → SQLite → 展示）已跑通。额外完成超出原设计的：任务取消机制、子进程跟踪、中英文 i18n。v2.2 尚余两项（定时扫描 cron、结果 Diff 对比）待实现。

---

## 10. 后端请求流

### 10.1 三层架构调用链

```
┌─────────────────────────────────────────────────────────────┐
│                    api/ (路由层)                              │
│  接收 HTTP 请求 → 参数校验 → 调用 Service → 构造 JSON 响应     │
│  职责：路由匹配、请求解析、响应格式化、HTTP 状态码              │
│  不包含业务逻辑，不直接操作数据库                              │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                 services/ (业务逻辑层)                       │
│  scan_service:   扫描任务编排、线程管理、SSE 推送、结果双写    │
│  history_service: 历史查询、分页搜索、统计聚合                │
│  asset_service:  跨扫描资产汇总、唯一 (ip,host) 去重          │
│  职责：业务编排、事务管理、跨 Model 操作                      │
│  不包含 HTTP 细节（Request/Response），不包含扫描引擎细节      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│          models/ (ORM) + netprobe/ (扫描引擎)                │
│  models:      SQLAlchemy 模型，数据 CRUD，关系映射            │
│  netprobe:    独立扫描引擎包，不依赖 FastAPI / DB             │
│  职责：数据存取、扫描执行                                     │
│  不包含 HTTP 或业务逻辑                                       │
└─────────────────────────────────────────────────────────────┘
```

### 10.2 扫描请求完整流程

```
浏览器                   FastAPI                    netprobe
  │                        │                           │
  │  POST /api/scan        │                           │
  │  {target, options}     │                           │
  │──────────────────────>│                           │
  │                        │                           │
  │                        │  scan_service.start()     │
  │                        │  ├─ 生成 scan_id          │
  │                        │  ├─ 写入 scans 表         │
  │                        │  │  (status=running)      │
  │                        │  └─ 启动后台线程           │
  │                        │     thread.start()        │
  │                        │         │                 │
  │  {scan_id, status}     │         │                 │
  │<──────────────────────│         │                 │
  │                        │         │                 │
  │  GET /api/stream/:id   │         │                 │
  │  (EventSource)         │         │                 │
  │──────────────────────>│         │                 │
  │                        │         │                 │
  │                        │  SSE 队列监听             │
  │                        │         │  engine.run()   │
  │                        │         │────────────────>│
  │                        │         │                 │
  │                        │         │  callback:      │
  │                        │         │  on_progress()  │
  │                        │         │<────────────────│
  │                        │         │                 │
  │                        │  SSE push progress        │
  │  data: {progress}      │         │                 │
  │<──────────────────────│         │                 │
  │                        │         │                 │
  │                        │         │  engine 返回     │
  │                        │         │  hosts 列表      │
  │                        │         │<────────────────│
  │                        │         │                 │
  │                        │  scan_service.on_done()   │
  │                        │  ├─ 写入 hosts/ports/web  │
  │                        │  │  banners/sensitive/js  │
  │                        │  ├─ 更新 scans 统计字段    │
  │                        │  │  (status=done)         │
  │                        │  └─ SSE push done          │
  │                        │         │                 │
  │  data: {done, hosts}   │         │                 │
  │<──────────────────────│         │                 │
  │                        │         │                 │
  │  EventSource.close()   │         │                 │
  │──────────────────────>│         │                 │
```

### 10.3 并发与任务管理

- 使用 `threading.Thread` 执行扫描（非 asyncio，因为 netprobe 引擎是同步的）
- 全局 `_tasks: dict[task_id, dict]` 维护每个任务的队列、状态、取消信号、跟踪的子进程
- **支持并发多任务**：每次 `POST /api/scan` 起独立线程，互不阻塞；活跃任务超过 `_TASK_MAX_AGE`（1 小时）自动清理
- **任务取消机制**：`POST /api/tasks/:id/cancel` 置 `cancel_event` →
  - 终止所有已跟踪的底层子进程（通过 `_process_callback` 注册的 nmap/masscan/rustscan 进程）
  - 引擎在每个阶段检查 `_is_cancelled()` 提前退出
  - 推送 `cancelled` SSE 事件，DB 状态置为 `cancelled`
- 任务结果双写：内存 `_tasks[task_id]["hosts"]`（供 SSE 实时推送）+ SQLite（持久化供历史/资产查询）

---

## 11. 安全设计

### 11.1 输入校验

| 入口 | 校验规则 |
|------|----------|
| POST /api/scan target | 非空、长度 ≤ 500、仅允许域名/IP/CIDR 字符 |
| PUT /api/settings | API Key 长度 ≤ 200、超时值 30–3600 |
| GET /api/history q | 长度 ≤ 200，SQL LIKE 通配符转义 |

### 11.2 API Key 存储

- 存储在 SQLite `settings` 表中（明文）
- **适用场景**：单机本地工具，无多用户场景
- 未来 v3.0+ 多用户版本需改为加密存储（AES-256 或系统 keyring）
- `.gitignore` 排除 `instance/netprobe.db`

### 11.3 CORS 策略

```python
# 开发环境
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"])

# 生产环境（前后端同源，不需要 CORS）
# CORS 不启用
```

### 11.4 XSS 防护

- Vue 模板默认转义 HTML，`{{ }}` 插值自动 escape
- 后端 API 只返回 JSON，不渲染 HTML
- PDF 导出的 HTML 通过 `html.escape()` 转义所有用户数据
- 不使用 `v-html`（除非 PDF 预览场景已严格消毒）

### 11.5 命令注入防护

- netprobe 引擎调用外部工具（nmap、subfinder 等）使用 `subprocess.run(list)` 而非 `shell=True`
- 目标域名在传入命令前做白名单字符校验

---

## 12. 错误处理

### 12.1 后端错误响应格式

```json
{
  "error": "描述信息（中文，面向用户）",
  "detail": "英文技术细节（可选，仅开发模式）"
}
```

### 12.2 HTTP 状态码约定

| 状态码 | 场景 |
|--------|------|
| 200 | 成功 |
| 400 | 参数校验失败（空目标、非法字符） |
| 404 | scan_id 不存在 |
| 409 | 已有扫描在运行（冲突） |
| 500 | 服务器内部错误（扫描引擎异常） |

### 12.3 前端错误处理

```typescript
// api/index.ts axios 拦截器
import { ElMessage } from 'element-plus'

api.interceptors.response.use(
  (res) => res,
  (error) => {
    const msg = error.response?.data?.detail || '网络请求失败'
    ElMessage.error(msg)  // Element Plus 全局提示
    return Promise.reject(error)
  },
)
```

### 12.4 扫描引擎错误

- 扫描线程内部 `try/except` 捕获所有异常
- 异常信息写入 `scans.error_msg` 字段
- 通过 SSE 推送 `error` 事件到前端
- 扫描状态置为 `error`

---

## 13. 开发环境搭建

### 13.1 环境要求

| 工具 | 最低版本 | 用途 |
|------|----------|------|
| Python | 3.10+ | 后端运行时（使用 `X \| Y` 类型联合语法） |
| Node.js | 18+ | 前端构建 |
| npm/pnpm | 8+ / 8+ | 前端包管理 |
| Nmap | 7.x | 端口扫描（可选，有 python-nmap 降级方案） |
| Git | 2.x | 版本控制 |

### 13.2 后端启动

```bash
# 1. 创建虚拟环境
cd NetProbe
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

# 2. 安装依赖
pip install -r server/requirements.txt
playwright install chromium

# 3. 启动后端 (自动建库 + 启动)
cd server
uvicorn main:app --reload --port 8000
# FastAPI 运行在 http://127.0.0.1:8000
# Swagger 文档: http://127.0.0.1:8000/docs
```

### 13.3 前端启动

```bash
# 1. 安装依赖
cd frontend
npm install

# 2. 启动开发服务器
npm run dev
# Vite 运行在 http://localhost:5173
# /api 请求自动代理到 FastAPI (8000)

# 3. 生产构建
npm run build
# 输出到 frontend/dist/
```

### 13.4 开发工作流

```
1. 启动后端 (终端 1):  cd server && uvicorn main:app --reload --port 8000
2. 启动前端 (终端 2):  cd frontend && npm run dev
3. 浏览器访问:         http://localhost:5173
4. API 文档:           http://localhost:8000/docs (FastAPI 自动生成 Swagger UI)
5. 修改前端代码:       Vite HMR 自动热更新
6. 修改后端代码:       uvicorn --reload 自动重启
```

---

## 14. 部署策略

### 14.1 一体化部署（推荐，单机使用）

```bash
# 构建 Vue 前端
cd frontend && npm run build

# 输出结构
frontend/
  dist/
    assets/
      index-[hash].js
      index-[hash].css
    index.html

# 启动 FastAPI（同时提供 API 和静态文件）
cd server
uvicorn main:app --host 0.0.0.0 --port 8000
# 访问 http://127.0.0.1:8000
```

FastAPI 静态文件挂载：
```python
from fastapi.staticfiles import StaticFiles

# 所有 API 路由注册之后
app.mount("/", StaticFiles(directory="../frontend/dist", html=True), name="static")
```

### 14.2 Nginx 反向代理（生产环境 / 多用户）

```nginx
server {
    listen 80;
    server_name netprobe.example.com;

    # 前端静态文件
    location / {
        root /opt/netprobe/frontend/dist;
        try_files $uri $uri/ /index.html;
    }

    # API 反向代理
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        # SSE 支持
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 600s;
    }
}
```

### 14.3 Docker 部署（v3.0+ 规划）

```dockerfile
# Dockerfile (简化示意)
FROM python:3.12-slim
WORKDIR /app
COPY server/ ./server/
COPY netprobe/ ./netprobe/
COPY frontend/dist/ ./frontend/dist/

RUN pip install -r server/requirements.txt && \
    playwright install chromium --with-deps

EXPOSE 8000
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## 15. 测试策略

### 15.1 后端测试

| 类型 | 工具 | 覆盖范围 |
|------|------|----------|
| 单元测试 | pytest | services/ 业务逻辑、models/ ORM |
| API 测试 | pytest + FastAPI TestClient | 所有 API 端点 |
| 端到端 | 手动 | 扫描流程 + PDF 导出 |

```python
# 示例：API 测试
def test_scan_api(client):
    resp = client.post('/api/scan', json={'target': 'example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'scan_id' in data
```

### 15.2 前端测试

| 类型 | 工具 | 覆盖范围 |
|------|------|----------|
| 组件测试 | Vitest + Vue Test Utils | 组件渲染、交互 |
| 类型检查 | TypeScript 编译 | 编译期类型安全 |

### 15.3 手动测试清单

- [ ] 启动扫描 → SSE 进度实时显示 → 结果正确渲染
- [ ] 扫描完成 → 数据库写入 → 历史页可查看
- [ ] PDF/CSV/JSON/TXT 下载正确
- [ ] 资产页跨扫描汇总准确
- [ ] 设置保存 / 布局切换持久化
- [ ] 移动端响应式布局正常
- [ ] 浏览器后退 / 前进 / 刷新不丢状态
- [ ] 侧边栏 / 顶部导航切换正常

---

## 16. 性能考量

### 16.1 前端优化

| 策略 | 实现方式 |
|------|----------|
| 路由懒加载 | Vue Router `component: () => import()`，按页面拆分 bundle |
| 虚拟滚动 | 大量端口/主机列表使用 `el-table` 虚拟滚动 |
| 防抖搜索 | 搜索输入 300ms 防抖 |
| 生产构建 | Vite Tree-shaking + 代码分割 + gzip |

### 16.2 后端优化

| 策略 | 实现方式 |
|------|----------|
| 数据库连接池 | SQLAlchemy 默认连接池（SQLite 单连接足够） |
| 查询优化 | 索引覆盖所有 WHERE/JOIN 列，分页用 `LIMIT/OFFSET` |
| JSON 列 | 避免过度 JOIN，嵌套数据用 JSON 存储 |
| SSE 心跳 | 60 秒心跳防止连接超时 |

### 16.3 容量估算

| 场景 | 数据量 | SQLite 表现 |
|------|--------|-------------|
| 单次扫描 50 主机 × 10 端口 | ~500 行 ports | 毫秒级 |
| 100 次扫描历史 | ~5 万行 hosts | 毫秒级 |
| 资产汇总查询 | 聚合 5 万行 | < 100ms |
| 数据库文件大小 | 100 次扫描 | ~5–10 MB |

SQLite 单机场景下不需要分库分表。超过 10 万条 hosts 可考虑迁移 PostgreSQL。

---

## 17. 依赖清单

### 后端 (server/requirements.txt)

```
fastapi>=0.115
uvicorn[standard]>=0.30
sqlalchemy>=2.0
python-nmap>=0.7.1
dnspython>=2.8.0
requests>=2.28
playwright>=1.40
```

### 前端 (frontend/package.json 核心依赖)

```json
{
  "dependencies": {
    "vue": "^3.5",
    "vue-router": "^4.x",
    "pinia": "^2.x",
    "element-plus": "^2.x",
    "@element-plus/icons-vue": "^2.x",
    "axios": "^1.x"
  },
  "devDependencies": {
    "typescript": "^5.x",
    "vite": "^6.x",
    "@vitejs/plugin-vue": "^5.x",
    "vue-tsc": "^2.x",
    "unplugin-auto-import": "^0.18",
    "unplugin-vue-components": "^0.27"
  }
}
```
