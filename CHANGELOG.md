# Changelog

本项目所有重要变更记录。版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

---

## [v3.8.1] — 2026-07-17

### 文档
- 重写 README（居中标题 + 7 badge + 架构图 + 13 插件清单 + 数据规模）
- 重写 ARCHITECTURE.md（插件系统/RBAC/PG/漏洞生命周期/性能优化/专业报告）
- 更新 6 张界面截图

### 修复
- 插件 API 401（`from ...netprobe` 相对导入超出顶层包）
- 迁移脚本 try/finally 缩进断裂
- 分页默认 20→10 条/页

---

## [v3.8.0] — 2026-07-16

### 新增 — 插件系统
- `netprobe/plugins/` 可热插拔检测模块架构
- `base.py` Plugin 抽象基类（name/display_name/category/stage）
- `registry.py` 注册中心 + 自动发现 + 启用状态持久化
- `builtin.py` 13 个内置插件（SSL/CORS/安全头/未授权/弱口令/WAF/邮件安全/管理后台/robots/目录爆破/接管/CDN真实IP/CVE关联）
- 社区插件：`data/plugins/*.py` 自动注册
- 前端插件管理页（启用/禁用/分类展示/开发指南）
- API: `GET /api/plugins`、`PATCH /api/plugins/{name}/toggle`

### 新增 — 漏洞生命周期
- 7 状态流转：open → confirmed → fixing → fixed → verified → closed + false_positive
- `vulnerabilities` 表加 status/note/updated_at 字段
- API: `PATCH /api/vulnerabilities/{id}/status`、`GET /api/vulnerabilities/stats`
- 前端漏洞行内联状态选择器

### 新增 — 专业报告
- PDF/HTML 渗透报告（封面 + 执行摘要 + 风险矩阵 + 漏洞详情 + 修复建议 + 资产清单）
- 11 种漏洞分类的针对性修复建议
- 任务详情页导出下拉按钮

---

## [v3.7.0] — 2026-07-15

### 新增 — 5 大安全检测模块
- **CVE 关联** (`cve_match.py`)：指纹版本 → OSV API + NVD → CVE + CVSS，7 天本地缓存
- **SSL/TLS 深度检测** (`ssl_check.py`)：弱协议/弱加密套件/证书过期/自签名/域名不匹配
- **邮件安全基线** (`mail_security.py`)：SPF/DKIM/DMARC/MTA-STS
- **未授权接口枚举** (`unauth_scan.py`)：Swagger/actuator/phpinfo/.env/Druid 等 40+ 路径
- **WAF 识别** (`waf_detect.py`)：Cloudflare/阿里云/腾讯云/360/Imperva 等 20+ 厂商

### 变更
- `risk.py` CVE 维度扩展：遍历 `web_info[].tech[]` 调用 cve_match
- 前端漏洞分组新增 4 个分类（cve_fingerprint/ssl_tls/mail_security/unauth_access）

---

## [v3.6.0] — 2026-07-14

### 新增 — PostgreSQL 迁移
- `DATABASE_URL` 环境变量切换数据库（保留 SQLite 双后端）
- `docker-compose.yml` 新增 `postgres:16-alpine` 服务
- `scripts/migrate_sqlite_to_pg.py` 数据迁移脚本（含 boolean 转换 + 序列同步）
- `.env.example` 环境变量示例

### 性能优化
- `asset_service.list_assets` 消除 N+1 查询（143 次→3 次）
- 后端预聚合 preview，前端不再逐个请求详情
- 进度日志内存缓冲批量写入（每 3 秒/20 条）
- SQLite WAL 模式 + 连接池 + busy_timeout

### 修复
- SSE 鉴权：EventSource 改用 `?token=` query 参数
- 资产漏洞数一致性（列表与详情去重逻辑对齐）

---

## [v3.5.0] — 2026-07-13

### 新增 — 指纹库扩充
- 指纹规则从 8143 扩充至 9876 条（含 favicon_hash 引擎支持）
- 新增 FingerprintHub 中文指纹库导入

### 变更
- 匹配引擎增强：安全正则搜索 / kval 版本提取 / 近义名称合并 / 版本完整度优先

---

## [v3.4.0] — 2026-07-12

### 新增 — 指纹库扩充
- 导入 nuclei tech-detect 模板（684 新增 + 84 增强）
- 指纹总数 8143 → 8827 条
- 带 version 提取的 pattern 从 26 增至 485 条

### 变更
- 匹配引擎：安全正则 `_safe_search`、近义名称合并、版本完整度优先

---

## [v3.3.0] — 2026-07-11

### 新增
- 资产标签 / 分组系统（7 预设标签 + 自定义）
- ASM 攻击面管理仪表盘（监控目标 + 扫描趋势 + 告警 + 标签统计）

---

## [v3.2.0] — 2026-07-10

### 新增 — 用户认证
- JWT 登录/退出/改密码（bcrypt 哈希，非 passlib）
- 用户管理 CRUD（管理员增删改用户）
- JWT 中间件保护所有 `/api` 路由

### UI 优化
- 表格列宽统一 min-width 自适应 + 表头不截断
- 操作按钮 `:has(.el-button)` 选择器修复遮挡

---

## [v3.1.0] — 2026-07-09

### 新增
- 指纹库扩充至 8143 条（Wappalyzer 4864 + FingerprintHub 2576 + 手工）
- 端口覆盖从 23 扩充至 192 个
- 扫描引擎可配置化（6 预设 + 自定义引擎，10 阶段独立开关）

### UI
- 全面重构为"明亮+品牌强调"风格（蓝色主题）
- 资产列表 FOFA 风格表格
- 分页 per-page 独立持久化

---

## [v3.0] — 2026-07-08

### 架构重构 — 前后端分离
- **后端**: FastAPI + SQLAlchemy + SQLite（16 张表）
- **前端**: Vue 3 + TypeScript + Element Plus + ECharts + vue-i18n
- **扫描引擎**: 重构为 `netprobe` 包，CLI 与 Web 共用

### 核心功能
- 扫描管道：子域名 → 端口 → Web → 指纹 → 敏感路径 → 漏洞 → 风险评分
- SSE 实时进度推送
- 扫描历史记录持久化
- 定时扫描（APScheduler + cron）
- 扫描结果 Diff 对比
- 跨资产关联引擎 + 关联图谱
- 6 维风险评分
- 资产关系图谱（ECharts）
- Web 截图（Playwright）
- 多渠道通知（Webhook/钉钉/企业微信/飞书/Telegram/邮件）
- 告警规则（新端口/新子域名/新漏洞/证书过期/技术栈变化）
- 子域名接管检测
- CI/CD 集成（`netprobe ci`）

---

## [v2.x] — 2026-06 ~ 07

### CLI 时代（纯 Python 命令行工具）
- 多引擎域名探测（subfinder + nmap dns-brute）
- 端口扫描（nmap 三步法 + masscan/rustscan 降级）
- Web 探测 + SSL 证书 + HTTP 指纹 + Banner 抓取
- JS 文件分析（API 端点 + 密钥泄露）
- 敏感路径探测
- PDF/HTML/CSV/JSON 报告导出
- OS 识别 + 编码检测

---

## [v1.0] — 2026-06

### 初始版本
- NetProbe 多引擎域名探测平台
