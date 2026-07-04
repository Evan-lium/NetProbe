# NetProbe 剩余开发任务计划

> 制定：2026-07-04 ｜ 基于 `DEVELOPMENT-PLAN.md` 各阶段实际完成情况核实
> 原则：按「可独立交付的批次」组织，每批完成后可验收、可单独发布，不必等全部做完

---

## 当前进度基线

| 原阶段 | 状态 | 剩余实质任务 |
|--------|:---:|------|
| Phase 0 工程修复 | ✅ | — |
| Phase 1 漏洞扫描 | ✅ | — |
| Phase 2 指纹扩充 | ⚠️ | Web 指纹 961/3500；Wappalyzer/EHole 导入未做 |
| Phase 3 引擎可配置 | ❌ | 整阶段空白（现仅 quick/deep 两档） |
| Phase 4 深度检测 | ⚠️ | API 发现/POC 验证/目录爆破未做；JS 分析有基础 |
| Phase 5 工程化 | ❌ | Docker/测试/CI 未做 |

---

## 交付批次总览

```
批次 1（立竿见影）  指纹库扩充 + 多渠道通知
    │   识别率从 961→3000+，告警渠道补齐，工作量小见效快
    ↓
批次 2（能跑起来）  Docker 部署 + 用户文档
    │   一键启动，别人能 clone 下来直接用
    ↓
批次 3（灵活控制）  扫描引擎可配置化
    │   阶段独立开关 + 自定义引擎，对齐 reNgine
    ↓
批次 4（深度增强）  API 发现 + JS 深度 + 目录爆破
    │   差异化能力，超越多数开源工具
    ↓
批次 5（工程交付）  测试 + CI + 性能优化
        生产级交付标准
```

---

## 批次 1：指纹库扩充 + 多渠道通知（立竿见影）

**价值**：识别率是最直观的体验提升；通知渠道是竞品对比里唯一的 ⚠️ 短板。
**工作量**：小 ｜ **依赖**：无

### 1.1 导入 Wappalyzer 指纹（Phase 2.1）
- 下载 Wappalyzer 官方 `technologies.json`（~3000 技术）
- 写转换器：Wappalyzer 的 `js/cookies/headers/meta/html/css` 分类 → NetProbe 的 `{name,category,patterns:[{type,pattern}]}`
- 目标：Web 指纹 961 → **3000+**
- 文件：`netprobe/data/fingerprints.json`（合并去重）+ 新建 `scripts/import_wappalyzer.py`

### 1.2 多渠道通知（补短板）
- 现状：`notify_service.py` 仅 Webhook
- 新增：邮件（SMTP）/ 钉钉 / 企业微信 / 飞书 / Telegram
- 统一接口：每个渠道一个 `send_xxx()` 函数，配置存 `settings.json`
- 文件：`server/services/notify_service.py` + 前端设置页加渠道配置 UI

### 1.3 指纹自动更新（可选，Phase 2.5）
- 命令 `netprobe update-fingerprints`：从 GitHub 拉 Wappalyzer 最新 release
- 文件：`netprobe/main.py` 加子命令

---

## 批次 2：Docker 部署 + 用户文档（能跑起来）

**价值**：没 Docker，别人 clone 下来要手动装 nmap/masscan/nuclei/Playwright，劝退。一键启动是开源项目的基本门槛。
**工作量**：中 ｜ **依赖**：无

### 2.1 Dockerfile（多阶段构建）
- 阶段 1（前端）：`node:20-alpine` → `npm ci && npm run build` → `frontend/dist/`
- 阶段 2（运行时）：`python:3.12-slim` + apt 装 nmap/masscan + Go 工具（subfinder/httpx/nuclei）+ Playwright chromium
- 文件：新建 `Dockerfile`

### 2.2 docker-compose.yml
- 单服务（前后端同源 8000 端口，SQLite 文件型，APScheduler 进程内）
- Volume：`./data:/app/data`（DB+settings+screenshots）、`./output:/app/output`
- 环境变量：`TZ=Asia/Shanghai` + 可选 API keys
- 文件：新建 `docker-compose.yml`

### 2.3 .dockerignore
- 排除 `frontend/node_modules`、`frontend/dist`、`__pycache__`、`.git`、`output/`、`data/netprobe.db`
- 文件：新建 `.dockerignore`

### 2.4 用户文档完善
- README 加 Docker 部署章节 + 手动部署章节 + 环境变量说明
- 文件：`README.md`

---

## 批次 3：扫描引擎可配置化（灵活控制）

**价值**：现仅 quick/deep 两档，用户无法"只扫端口"或"只跑子域名"。对齐 reNgine 的自定义引擎体验。
**工作量**：中 ｜ **依赖**：无

### 3.1 扫描引擎数据模型（Phase 3.1）
- 新建 `scan_engines` 表：`{id, name, config_json, is_preset, created_at}`
- config_json 结构：`{stages:{subdomain,port,web,fingerprint,sensitive,vuln,screenshot,js}, port_range, port_engine, nuclei_severity, nuclei_tags}`
- 预设引擎：快速（只子域名+端口）、标准（默认）、深度（全量+漏洞）、仅 Web、仅端口
- 文件：`server/models/scan_engine.py` + db 迁移

### 3.2 引擎配置 UI（Phase 3.2/3.3）
- Tasks 表单：扫描引擎选择器（预设下拉 + 自定义）
- 自定义引擎编辑器：阶段开关（el-switch 组）+ 端口配置 + nuclei 模板选择
- 文件：`frontend/src/views/Tasks.vue`

### 3.3 引擎解析与执行（Phase 3.3/3.4/3.5）
- scan_service 启动扫描时读引擎配置，传给 engine.py 的 options
- engine.py 每个阶段前检查 options.stages.xxx 是否启用，未启用则跳过
- 文件：`netprobe/engine.py`（加阶段开关）+ `server/services/scan_service.py`

### 3.4 引擎 CRUD API
- GET/POST/PUT/DELETE `/api/scan-engines`
- 文件：`server/routers/scan_engines.py`

---

## 批次 4：深度检测能力（差异化增强）

**价值**：API 发现、JS 密钥深度分析、目录爆破是商业工具的标配，开源竞品普遍缺失——做完是真正的护城河。
**工作量**：中-大 ｜ **依赖**：批次 3 的引擎框架（作为可选阶段）

### 4.1 API 端点发现（Phase 4.1）
- 现状：仅敏感路径表里有 `/graphql` 固定路径
- 新增：从 JS 提取 REST 端点（已有 6 类正则基础）+ spider 爬取页面链接 + GraphQL Schema 内省 + OpenAPI/Swagger 文档解析
- 入库：复用 `js_findings.api_endpoints_json`
- 文件：`netprobe/api_discovery.py`（新建）+ engine 集成

### 4.2 JS 深度分析增强（Phase 4.2）
- 现状：js_analyzer.py 有 6 类 API 正则 + 9 类密钥规则
- 增强：集成 linkfinder 正则（URL 端点提取更准）+ 扩充密钥规则（cloud keys/token/private key 等）+ JS sourcemap 解析
- 文件：`netprobe/js_analyzer.py`（扩充规则）

### 4.3 目录爆破（Phase 4.4）
- 现状：sensitive_probe 只查固定 566 条路径
- 新增：基于词表的目录爆破（复用现有并发框架），支持递归深度、扩展名、过滤
- 词表：内置常见目录词表（admin/api/config/backup 等）
- 文件：`netprobe/dir_brute.py`（新建）+ engine 作为可选阶段

### 4.4 POC 验证（Phase 4.3，可选）
- 对 NVD 匹配到的 CVE，定向调 nuclei 对应模板验证
- 现状：nuclei 是全量扫描，非 CVE 定向
- 文件：`netprobe/risk.py` + nuclei_tool.py 协作

---

## 批次 5：工程化收尾（生产交付）

**价值**：测试 + CI 让项目长期可维护，性能优化支撑大规模扫描。
**工作量**：中 ｜ **依赖**：前 4 批完成

### 5.1 单元测试（Phase 5.3）
- pytest 覆盖核心服务：fingerprint / risk / diff_service / correlation_service / banner_grab
- 目标覆盖率：核心模块 >70%
- 文件：新建 `tests/`

### 5.2 CI 流水线（Phase 5.4）
- GitHub Actions：lint（ruff）+ frontend build + pytest + Docker 镜像构建发布
- 文件：`.github/workflows/ci.yml`

### 5.3 性能优化（Phase 5.5）
- 大目标（100+ 子域名）扫描的并发/内存/超时优化
- SQLite 批量插入、SSE 背压、nuclei 并发控制
- 文件：`netprobe/engine.py` + `server/services/scan_service.py`

---

## 执行建议

| 优先级 | 批次 | 理由 |
|:---:|------|------|
| P0 | **批次 1** 指纹扩充 | 识别率是安全工具的命脉，961→3000+ 立刻见效 |
| P0 | **批次 2** Docker | 没它项目没法用，门槛最低 |
| P1 | **批次 3** 引擎配置 | 体验对齐 reNgine，灵活性 |
| P2 | **批次 4** 深度检测 | 差异化，但依赖批次 3 |
| P3 | **批次 5** 工程化 | 长期维护，最后做 |

**推荐路径**：批次 1 → 批次 2 → 批次 3 → 批次 4 → 批次 5
每批完成后可验收，随时可停，停下也有完整可用的版本。
