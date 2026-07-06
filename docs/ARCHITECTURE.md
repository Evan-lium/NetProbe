# NetProbe 架构概览

> 版本: 当前主线 | 这是一份**架构概览**，不是详细设计文档。字段定义、代码细节请直接看源码。

---

## 1. 架构概览

NetProbe 采用前后端分离 + 独立扫描引擎的三层架构：

```
┌──────────────────────────────────────────────────────────┐
│                    用户浏览器                              │
│          Vue 3 + TypeScript + Element Plus                │
│          Pinia · Vue Router · vue-i18n · ECharts          │
└────────────────────────┬─────────────────────────────────┘
                         │ Axios (REST) / EventSource (SSE)
                         │  Bearer JWT
                         ▼
┌──────────────────────────────────────────────────────────┐
│              FastAPI (REST API + JWT 中间件)               │
│   routers/  →  services/  →  models/ (SQLAlchemy ORM)     │
│                         │                                │
│                         └──→  netprobe/ (扫描引擎包)      │
├──────────────────────────────────────────────────────────┤
│   APScheduler (定时巡检)   ·   SQLite (持久化)            │
│   Playwright (Web 截图)    ·   外部工具 (nmap/nuclei/...)  │
└──────────────────────────────────────────────────────────┘
```

**核心设计原则：**

- **三层后端** — `routers/`（路由 + 参数校验）→ `services/`（业务编排）→ `models/`（ORM）+ `netprobe/`（扫描引擎）
- **引擎解耦** — `netprobe/` 是独立扫描包，不依赖 FastAPI / DB，CLI 与 Web 共用同一套扫描逻辑
- **结果双写** — 扫描结果同时写内存（供 SSE 实时推送）与 SQLite（持久化供历史/资产查询）
- **同步线程** — 扫描在 `threading.Thread` 中执行（netprobe 引擎是同步的），FastAPI 本身保持 async

---

## 2. 项目结构

```
NetProbe/
├── server/                     # ── FastAPI 后端 ──
│   ├── __init__.py             # create_app() 工厂 + JWT 中间件 + 启动钩子
│   ├── main.py                 # uvicorn 启动入口
│   ├── config.py               # 路径 / 密钥 / JWT 配置
│   ├── db.py                   # SQLAlchemy engine + SessionLocal
│   ├── models/                 # ORM 模型（15 张表）
│   ├── schemas/                # Pydantic 请求/响应模型
│   ├── routers/                # API 路由（16 个模块）
│   ├── services/               # 业务逻辑层（扫描调度/通知/认证/变更/ASM...）
│   └── requirements.txt
│
├── frontend/                   # ── Vue 3 前端（Vite）──
│   └── src/
│       ├── views/              # 页面（Dashboard/Tasks/ASM/Assets/Graph/...）
│       ├── components/         # 可复用组件
│       ├── stores/             # Pinia 状态
│       ├── router/             # 路由表
│       ├── api/                # axios 封装
│       └── i18n/               # 中英双语
│
├── netprobe/                   # ── 核心扫描引擎（CLI 与 server 共用）──
│   ├── engine.py               # 统一扫描流水线编排
│   ├── scanner.py              # Nmap 交互（dns-brute + 两步端口扫描）
│   ├── web_probe.py            # Web 探测（HTTP/HTTPS + SSL + 编码）
│   ├── fingerprint.py          # 技术栈指纹识别（8143 条）
│   ├── sensitive_probe.py      # 敏感路径探测
│   ├── takeover_detect.py      # 子域名接管检测
│   ├── security_headers.py     # HTTP 安全头检查
│   ├── cors_check.py           # CORS 配置检测
│   ├── brute_force.py          # 弱口令爆破
│   ├── github_leak.py          # GitHub 代码泄露监控
│   ├── origin_ip.py            # CDN 真实 IP 发现
│   ├── admin_detect.py         # 管理后台识别
│   ├── js_analyzer.py          # JS 分析（API + 密钥泄露）
│   ├── risk.py                 # 6 维风险评分
│   ├── tools/                  # 外部工具适配（nmap/masscan/subfinder/nuclei/...）
│   └── data/                   # 规则数据（指纹/敏感路径/接管/CDN）
│
├── data/                       # SQLite 数据库 + settings.json
├── output/                     # 扫描报告输出
├── main.py                     # CLI 入口（scan / ci / update-fingerprints）
├── Dockerfile                  # 多阶段构建
└── docker-compose.yml          # 一键部署
```

---

## 3. 数据流（扫描管道）

一次完整扫描经历以下阶段，每个阶段可由扫描引擎配置开关：

1. **目标解析** — 域名 → A 记录，IP → 反向 DNS，提取根域
2. **被动情报收集** — crt.sh / FOFA / Hunter / Shodan / Censys 多源聚合子域名
3. **子域名枚举** — subfinder + nmap dns-brute，泛解析预检过滤假阳性，DNS 验证存活
4. **端口扫描** — nmap / masscan / rustscan 三引擎按可靠性优先级自动调度、优雅降级
5. **Web 探测** — HTTP/HTTPS 探活、标题、重定向、SSL 证书、编码识别
6. **指纹识别** — 8143 条规则多维匹配（HTTP 头 + HTML + Cookie）
7. **敏感路径 + 接管 + JS 分析** — 泄露检测、CNAME 悬挂、API 端点与密钥提取
8. **漏洞扫描** — nuclei 模板检测 + 安全头/CORS/弱口令等专项安全检测
9. **风险评分** — 6 维加权计算 0–100 综合分，自动分级
10. **结果落库 + 告警** — 写入 SQLite，触发变更检测 Diff 与多渠道通知

> 全程通过 SSE（`text/event-stream`，60s 心跳）向前端推送进度，扫描完成后切换为普通 API 取最终数据。

---

## 4. 数据库

SQLite 单文件（`data/netprobe.db`），15 张表：

| 模块 | 表 | 说明 |
|------|----|------|
| **扫描** | `scans` | 扫描任务（状态/统计/耗时）|
| | `hosts` | 主机（域名/IP/OS）|
| | `ports` | 端口（协议/状态/服务/版本）|
| | `banners` | 服务 Banner |
| **Web** | `web_info` | Web 站点（标题/状态码/技术栈/SSL，JSON 列）|
| | `sensitive_paths` | 敏感路径（分级）|
| | `js_findings` | JS 分析（API 端点 + 密钥泄露）|
| | `whois_records` | WHOIS/RDAP 记录（域名到期监控）|
| | `vulnerabilities` | nuclei 漏洞结果 |
| **调度** | `schedules` | 定时扫描任务（cron）|
| **告警** | `alerts` | 告警规则 |
| | `alert_events` | 告警触发历史 |
| **配置** | `scan_engines` | 扫描引擎配置（6 预设 + 自定义）|
| | `asset_tags` | 资产标签 |
| **用户** | `users` | 用户（用户名/密码哈希/管理员标记）|

**约定：** 嵌套展示数据（技术栈、SSL、headers 等）用 JSON 列存储，避免过度 JOIN；按子字段查询需求出现时再加平铺列。表间通过 `scan_id` / `host_id` 外键关联，`ON DELETE CASCADE`。

---

## 5. API 概览

所有路由前缀 `/api`，需 Bearer JWT 认证（登录接口豁免）。

| 路由模块 | 主要端点 | 说明 |
|----------|---------|------|
| `auth` | `POST /auth/login`、`GET /auth/me`、用户 CRUD | 登录 / 当前用户 / 用户管理 |
| `scan` | `POST /scan`、`GET /stream/<id>` | 启动扫描 / SSE 进度 |
| `result` | `GET /result/<id>`、`GET /download/<id>/<fmt>` | 结果 / 报告下载 |
| `tasks` | `GET /tasks`、cancel / delete | 活跃 + 历史任务，支持取消 |
| `history` | `GET /history`、详情、删除 | 扫描历史 |
| `assets` | `GET /assets`、单 IP 详情 | 跨扫描资产汇总 |
| `asset_tags` | 标签 CRUD | 资产分组 |
| `schedules` | 定时任务 CRUD | APScheduler 调度 |
| `scan_engines` | 引擎 CRUD | 6 预设 + 自定义 |
| `alerts` | 告警规则 / 事件 | 告警配置与历史 |
| `asm` | `GET /asm/overview` | ASM 总览聚合 |
| `correlations` | 关联查询 | 资产关联 |
| `stats` | 统计聚合 | 端口/技术栈/漏洞分布 |
| `search` | 资产检索 | 跨表搜索 |
| `settings` | `GET/PUT /settings` | API Key / 通知 / 布局 |
| `tools` | `GET /tools` | 外部工具可用性检测 |

> 通用约定：JSON 格式、错误 `{detail: "..."}` + HTTP 状态码、分页 `?page=&per_page=`。

---

## 6. 认证流程

采用 **JWT 中间件 + bcrypt 密码哈希**：

```
登录                        请求受保护 API
  │                            │
  ▼                            ▼
POST /api/auth/login        GET /api/... (任意受保护路由)
{username, password}        Header: Authorization: Bearer <token>
  │                            │
  ▼                            ▼
auth_service.login          JWT 中间件（server/__init__.py）
  ├─ bcrypt 校验密码          ├─ 豁免 /api/auth/login、/docs、静态文件
  └─ 签发 JWT (7天)           ├─ 解析 Bearer token → get_current_user()
        │                    ├─ 失败 → 401 {detail: "token 无效或已过期"}
        ▼                    └─ 通过 → 放行到路由
  返回 {access_token, user}
```

- **首次启动**自动创建默认管理员 `admin / admin`（`init_admin()`），登录后请改密码
- **双角色**：`is_admin` 标记管理员，用户管理接口要求管理员权限（`_require_admin`）
- **token 有效期** 7 天，算法 HS256，密钥见 `config.py`
- 前端 axios 拦截器自动附带 token，401 时跳转登录页

---

## 7. 部署

详细步骤见 **[README.md](../README.md)**。

**Docker（推荐）：**

```bash
docker compose up -d      # 访问 http://localhost:8000（admin/admin）
```

**手动开发（前后端分离）：**

```bash
# 后端
uvicorn server.main:app --host 0.0.0.0 --port 8000 --reload

# 前端（另开终端，5173 代理 /api → 8000）
cd frontend && npm run dev
```

**生产构建：** `cd frontend && npm run build`，产物 `frontend/dist/` 由 FastAPI `StaticFiles(html=True)` 托管（SPA fallback），前后端同源无需 CORS。
