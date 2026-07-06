# NetProbe Roadmap

> 版本: 3.3 | 更新: 2026-07-06

---

## 竞品分析摘要

> 📊 **完整的竞品对比矩阵见 [COMPETITIVE_ANALYSIS.md](./COMPETITIVE_ANALYSIS.md)**（11 款竞品 16 维度横向对比）
>
> **核心结论**：NetProbe 得分 29/34 居开源竞品首位，在变更检测、风险评分、JS 分析、中英文情报融合四个维度具备全行业独占优势。

### 全行业 10 大缺口与 NetProbe 覆盖情况

| # | 痛点 | NetProbe 覆盖 |
|---|------|:---:|
| 1 | **工具碎片化** — 需串联 4-6 个工具（subfinder→nmap→httpx→nuclei），格式不统一 | ✅ 一站式管道 |
| 2 | **无持久化资产库** — Goby/Ehole/Finger 单次扫描即丢，无法回答"上次到现在什么变了" | ✅ SQLite 12 表 |
| 3 | **无变更检测** — 无开源工具能自动 diff 两次扫描结果 | ✅ 六维 diff（独占） |
| 4 | **指纹规则过时** — EHole/Finger/ObserverWard 依赖社区维护 | ⚠️ 961 条 + 版本提取（扩充中） |
| 5 | **无风险评分** — 所有工具输出扁平列表，无优先级 | ✅ 六维加权评分（独占） |
| 6 | **JS/SPA 分析浅** — 无工具从 JS bundle 提取 API 端点 | ✅ API+密钥提取（独占） |
| 7 | **中英文源割裂** — 国际工具缺中文源，国内工具缺国际源 | ✅ FOFA+Hunter+crt.sh+Shodan（独占） |
| 8 | **无 API 资产发现** — 无工具系统发现 REST/GraphQL 端点 | ❌ v3.0 待做 |
| 9 | **企业平台昂贵** — 长亭云图/鹰图/微步/FOFA 均收费 | ✅ 开源免费 |
| 10 | **无 CI/CD 集成** — 无开源工具提供管道集成 | ✅ `netprobe ci` |

> 10 大痛点中 NetProbe 已覆盖 8 项（含 4 项全行业独占），仅「指纹规模」「API 资产发现」待补。

---

## 核心差异化定位

> 详细的差异化优势与对标分析见 [COMPETITIVE_ANALYSIS.md](./COMPETITIVE_ANALYSIS.md) 第四章。
>
> NetProbe 围绕 5 个差异化能力构建护城河：①一站式管道 → ②持久化资产库 → ③变更检测 → ④智能风险评分 → ⑤中英文情报融合。其中**变更检测、风险评分、JS 分析、中英文情报融合**是全行业独占能力。

---

## 版本规划

### v2.1 — 资产指纹增强 ✅ 已完成

- [x] **Favicon 哈希指纹** — 计算站点 favicon 的 MMH3 哈希（FOFA `icon_hash` 同款），优先解析 HTML `<link rel="icon">` 自定义路径回退 `/favicon.ico`，用于跨资产关联
- [x] **指纹版本提取** — 指纹引擎 pattern 规则新增 `version` 字段（正则提取），从 HTTP 头/meta/HTML 提取组件具体版本号（如 `nginx/1.25.3`、`WordPress 6.4.1`、`PHP/8.2.1`）；多 pattern 命中取最优（有版本 > 无版本，高置信度优先）
- [x] **扩展协议 Banner 解析** — 补全 SSH/FTP/SMTP/POP3/IMAP/PostgreSQL 版本正则提取（如 `SSH-2.0-OpenSSH_8.9p1` → OpenSSH 8.9p1），banner 结果回填 ports 表（仅填 nmap 未识别的空值，不覆盖权威数据）
- [x] **CDN / WAF / 云平台检测** — 整合 cdn.py（HTTP 头特征 + IP 网段库）与指纹库 CDN/WAF 规则，检测结果注入 tech 统一展示，避免两套割裂
- [x] **指纹置信度评分** — 按 pattern 来源加权：header=90 / cookie=85 / meta=80 / script_src=75 / status_code=70 / html=60，前端标签 hover 显示置信度与来源类型
- [x] **指纹库扩充** — 为 14 条高频产品 pattern 补 version 提取规则（WordPress/Drupal/Joomla/Ghost/Apache/Nginx/Tomcat/IIS/OpenResty/PHP/ThinkPHP），向后兼容不破坏现有规则

### v2.2 — 任务控制与持久化（v3.0 架构重构）✅ 已完成

- [x] **前后端分离** — Vue 3 + TypeScript + Element Plus 前端，FastAPI REST API 后端（含 SSE 实时进度、任务取消、中英文 i18n）
- [x] **扫描历史记录** — SQLite 持久化，7 张表完整存储（scans/hosts/ports/banners/web_info/sensitive_paths/js_findings），支持查看、搜索
- [x] **定时扫描** — cron 表达式调度周期性扫描任务（APScheduler + schedules 表持久化，启动自动重建，并发数控制）
- [x] **结果对比 (Diff)** — 同一目标多次扫描结果 diff，高亮新增/消失的子域名、端口、服务、技术栈变化（后端计算 + 三色展示）

### v2.3 — 资产关联与线索追踪 ✅ 已完成

- [x] **跨资产关联引擎** — 自动关联：同 IP 多域名、同证书多域名、同技术栈、同服务指纹（6 类关联查询 + 前端关联图谱页，复用现有扫描数据）
- [x] **基于证书的资产发现** — 从 SSL 证书 SAN / Subject 中提取关联域名（crtsh 证书元数据增强采集 + 通配符线索 + 去 SAN 截断）
- [x] **种子扩展 (Pivot)** — 域名 → IP → ASN → 网段 → 更多域名，自动扩展攻击面（单层 pivot，ipwhois + 反向 DNS，限每网段 20 IP 防递归）
- [x] **反向搜索** — 给定 IP，反查所有关联域名、证书、端口、技术栈、Banner、WHOIS（GET /api/search/reverse?ip=）
- [x] **IOC / APT 线索追踪** — 根据 Favicon 哈希（FOFA icon_hash 同款 mmh3）、Banner 指纹、证书指纹追踪基础设施（by_favicon/by_banner 关联）
- [x] **WHOIS 查询与反查** — 域名注册信息（RDAP）、IP 的 ASN/网段（ipwhois），扫描时自动查询存 whois_records 表
- [x] **DNS 区域传送** — 尝试 AXFR 获取完整 DNS 记录（dns_utils 扩展 NS/MX/CNAME/TXT 多记录 + AXFR，99% 域名拒绝属正常）

### v2.4 — 智能风险评分 ✅ 已完成

- [x] **资产风险评分** — 综合敏感路径(30%) × 高危端口(25%) × CVE(20%) × SSL证书(15%) × 威胁情报(10%)，输出 0-100 分，分档高/中/低危，资产列表按风险分排序
- [x] **CVE 自动关联** — 补全 nmap 的 CPE 字段（此前被代码丢弃），调 NVD API 按 product+version/CPE 查询已知漏洞（带限速，可选 NVD_API_KEY）
- [x] **威胁情报增强** — 复用 Hunter API 的 risk_level 字段标记高危资产（>=2 计入风险评分）
- [x] **CDN 背后溯源** — HTTP 头特征检测（CF-Ray/X-Amz-Cf-Id 等）+ 本地 CDN IP 段库（Cloudflare/AWS/阿里云/腾讯云等）双重识别

### v2.5 — 可视化与报告 ✅ 已完成

- [x] **资产关系图谱** — 域名 ↔ IP ↔ 证书 ↔ 技术栈 ↔ Favicon 的关联关系可视化（ECharts 力导向图，correlation_service.build_graph + Graph.vue）
- [x] **交互式统计图表** — 风险等级分布饼图、端口数量分布柱状图、Top 资产条形图（ECharts + Stats.vue）
- [x] **Web 截图** — 深度模式开关，复用 Playwright 对 Web 站点全页截图，存 data/screenshots/（screenshot.py + engine 深度模式 + DB screenshot_path 列）
- [x] **HTML 报告** — 独立可分享的 HTML 格式报告，复用 PDF 模板（formatter.save_to_html + download 端点 + 前端下载项）
- [x] **资产生命周期仪表盘** — 同目标多次扫描的资产新增/消失/变化趋势（diff_service.compute_timeline + ECharts 折线图 + Timeline.vue）

### v2.6 — 告警与集成 ✅ 已完成

- [x] **多渠道通知** — Webhook 推送（notify_service + settings.notifications 配置，可扩展邮件/钉钉/Slack）
- [x] **告警规则** — 新端口/新子域名/高危路径/证书过期/技术栈变化 5 类规则（alert_service 定时扫描后自动检查，复用 compute_diff，命中触发通知 + 写历史）
- [x] **子域名接管检测** — CNAME 指向未注册 SaaS 的 dangling DNS 检测（takeover_fingerprints.json 10 种 SaaS 指纹 + takeover_detect + engine 接入）
- [x] **CI/CD 集成** — `netprobe ci` 子命令，发现高危资产（风险分超阈值/高危敏感路径）退出码非零（main.py 重构 subparsers，复用 scan_all_targets）
- [x] **REST API 完善** — alert/notify CRUD 端点（GET/POST/DELETE /api/alerts + 触发历史，照 schedules.py 模板）

### v2.7 — 资产清单重构与协议分层可视化 ✅ 已完成

- [x] **资产清单 FOFA 风格重构** — 从卡片网格改为全宽行卡片（单列），左侧 IP:端口标识 + 端口/协议标签，中间 Banner 区（标题/状态码/Server/技术栈），右侧风险徽章 + 左侧风险色条，核心信息一眼可见无需展开（Assets.vue，对标 FOFA 资产列表密度）
- [x] **后台并发预取详情** — 列表加载后限流并发（6 路）预取每个资产的轻量预览（首站点/端口/主端口/漏洞数），卡片直接展示富信息而无需逐个点击
- [x] **详情改为居中大弹窗** — 从右侧 620px 抽屉改为 92vw × 88vh 固定高度弹窗，内部 Tab 独立滚动，贯通 flex 高度链（每环 min-height:0）保证数据再多也不溢出
- [x] **协议分层可视化** — 资产详情新增「协议分层」Tab，按 OSI 七层（可切 TCP/IP 五层）归类开放端口的服务，每层展示服务标签 + 计数，点击服务弹出端口明细，底部攻击面分布小结（服务→层级映射表 + 端口兜底推断，纯前端计算零后端改动）

### v3.0 — 协作与高级功能

- [x] **多用户支持** — JWT 认证 + 管理员/普通用户两档权限 + 用户管理 CRUD
- [x] **攻击面管理 (ASM)** — ASM 总览仪表盘 + CT 证书监控 + DNS 变更监控 + 巡航模式
- [x] **JS/SPA 深度分析** — 从 JS bundle 提取 API 端点（8类正则）+ 密钥泄露检测（18类，含 AWS/Google/Slack/Stripe/Azure 等）+ linkfinder 端点提取
- [ ] **插件系统** — 模块化架构，支持社区贡献的扫描模块和情报源
- [x] **Docker 部署** — 多阶段 Dockerfile（前端构建 + Python 运行时）+ docker-compose 一键启动，含 nmap/masscan/nuclei/subfinder + Playwright
- [x] **API 资产发现** — 从 JS/页面链接提取 REST 端点 + OpenAPI/Swagger 文档解析 + GraphQL 内省 + 目录爆破（114 词表）
- [x] **多渠道通知** — Webhook/钉钉/企业微信/飞书/Telegram/邮件 6 渠道（补齐 v2.6 唯一短板）
- [x] **扫描引擎可配置化** — 6 预设引擎 + 自定义引擎，10 个扫描阶段独立开关，对齐 reNgine 灵活性
