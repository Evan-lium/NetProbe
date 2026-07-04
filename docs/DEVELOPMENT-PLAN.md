# NetProbe 开发计划

> 版本: 1.0 | 更新: 2026-07-04
> 基于：竞品调研（reNgine/ARL/nuclei）+ 代码真实完成度审查

---

## 一、现状基线（代码审查结论）

### ✅ 真正扎实的能力（8-10 分）

| 能力 | 现状 | 评分 |
|---|---|---|
| 子域名发现 | subfinder + crt.sh + nmap dns-brute + FOFA/Hunter（key 注入已打通）| 8/10 |
| 端口扫描 | nmap/rustscan/masscan 三引擎 fallback（masscan 有导入 bug）| 7/10 |
| Web 探测 | HTTP 指纹 + SSL 证书 + favicon + CDN + 重定向二次请求 | 8/10 |
| 持久化 + 变更检测 | SQLite 11 张表 + diff + 时间线仪表盘 | 9/10 |
| 风险评分 | 5 维度加权 0-100（敏感路径/高危端口/CVE/SSL/威胁情报）| 8/10 |
| 资产关联 | 6 维度（同IP/证书/技术栈/服务/Favicon/Banner）| 8/10 |
| 可视化 | ECharts 统计/图谱/时间线 + Playwright 截图 + HTML 报告 | 8/10 |
| 前端 UI | 13 页全功能 + 实时控制台 SSE + 浅色主题 | 9/10 |
| CI/CD | `netprobe ci` 子命令 + 退出码语义 | 7/10 |
| 告警通知 | 5 类规则 + Webhook 推送 + 触发历史 | 8/10 |

### 🔴 关键缺口（2-5 分，影响产品完整性）

| # | 缺口 | 现状 | 评分 | 影响 |
|---|---|---|---|---|
| **1** | **漏洞扫描** | nuclei 注册了能力声明但**从未调用**，零 POC 能力，仅 NVD CVE 元数据匹配 | **2/10** | 安全工具核心价值缺失 |
| **2** | **指纹库规模** | 42 条 Web 指纹 / 53 条敏感路径 / 10 条接管指纹 | **3/10** | 识别率低，演示级 |
| **3** | **POC 漏洞验证** | 无主动验证，只靠版本号猜 CVE | **1/10** | 误报率高 |
| **4** | **扫描引擎可配置** | 只有快速/标准/深度三档，无法精细选工具/参数 | **4/10** | 灵活性不足 |
| **5** | **工程缺陷** | masscan 导入 bug / app.py 死代码 / bson 缺失 / DER 证书解析失效 | **5/10** | 隐蔽功能失效 |

---

## 二、竞品差距分析

### 对标 reNgine 2.2（⭐7k+，最接近定位的开源竞品）

| 能力 | reNgine | NetProbe | 差距 |
|---|---|---|---|
| 漏洞扫描 | ✅ nuclei 深度集成 + GPT 报告 | ❌ 无 | 🔴 核心 |
| 指纹识别 | ✅ Wappalyzer(3000+) + EHole | ⚠️ 42 条 | 🔴 严重 |
| 扫描引擎配置 | ✅ 可视化自定义引擎 | ❌ 三档固定 | 🟡 中等 |
| API 端点发现 | ✅ 端点爬取 + 参数发现 | ❌ 无 | 🟡 中等 |
| JS 深度分析 | ✅ linkfinder + API 提取 | ⚠️ 基础(9 条规则) | 🟡 中等 |
| 截图 | ✅ 原生 | ✅ Playwright | 持平 |
| **风险评分** | ❌ 无 | ✅ **5 维度评分** | **NetProbe 领先** |
| **变更检测** | ❌ 无 | ✅ **diff + 时间线** | **NetProbe 领先** |
| **资产关联** | ❌ 无 | ✅ **6 维度图谱** | **NetProbe 领先** |

### 对标 ARL 灯塔 v2.6（⭐2k+，国产资产侦察标杆）

| 能力 | ARL | NetProbe | 差距 |
|---|---|---|---|
| 指纹库 | ✅ **7649 条** | ⚠️ 42 条 | 🔴 严重 |
| 子域名字典 | ✅ 8W+ | ⚠️ 内置小字典 | 🟡 |
| 漏洞 POC | ✅ POC 验证 | ❌ 无 | 🔴 |
| 持久化 | ✅ MongoDB | ✅ SQLite | 持平(更轻) |
| 可视化 | ⚠️ 简单 | ✅ ECharts 丰富 | **NetProbe 领先** |

---

## 三、开发阶段规划

### 阶段总览

```
Phase 0  工程修复（补短板）        ──→  让现有功能真正跑通
    ↓
Phase 1  漏洞扫描集成（核心）      ──→  补齐安全工具核心价值
    ↓
Phase 2  指纹库扩充（数据）        ──→  达到生产级识别率
    ↓
Phase 3  扫描引擎可配置化（体验）  ──→  对齐 reNgine 灵活性
    ↓
Phase 4  深度检测能力（增强）      ──→  API 发现 + JS 深度 + POC
    ↓
Phase 5  工程化收尾（交付）        ──→  Docker + 文档 + 测试
```

---

### Phase 0：工程修复（让现有功能真正跑通）

**目标**：修复审查发现的隐蔽 bug 和死代码，让"看似完成"的功能真正可用。

| 任务 | 问题 | 修复方案 | 验收标准 |
|---|---|---|---|
| 0.1 修复 masscan 导入 bug | `masscan.py:33` `from tools.registry` 导入路径错误，导致 masscan 永远静默失效 | 改为相对导入 `from .registry import ...` | masscan 引擎能真正被调用 |
| 0.2 删除 app.py 死代码 | 废弃 Flask v2.0 服务，与新引擎脱节，占 flask 依赖 | 删除 app.py + 从 requirements 移除 flask | 无残留引用 |
| 0.3 补齐 bson 依赖 | `banner_grab.py` import bson 但未声明 | requirements.txt 加 `bson` 或改用标准库 | banner 抓取不报错 |
| 0.4 修复 DER 证书解析 | `web_probe.py:244` 传 bytes 给需要路径的函数 | 改用 cryptography 库解析，或写临时文件 | DER 证书能解析出 subject/SAN |
| 0.5 SSE 加 heartbeat | 长扫描 >60s 无输出被代理掐断 | scan.py 的 event_generator 每 30s 发 heartbeat | 长扫描不断连 |
| 0.6 cert_expiry 告警补全 | alert_service 忽略 threshold 天数，只判 expired | 加"即将过期(<N天)"判断 | 告警规则 threshold 生效 |

**交付物**：所有现有功能无隐蔽 bug，masscan/DER 证书/长扫描 SSE 真正可用。

---

### Phase 1：漏洞扫描集成（核心价值）

**目标**：集成 nuclei 漏洞扫描引擎，让 NetProbe 从"资产发现"升级为"资产发现 + 漏洞检测"。

**效果**：扫描完成后，每个资产能展示发现的漏洞列表（CVE/严重度/PoC 详情），风险评分纳入漏洞维度。

| 任务 | 说明 | 验收标准 |
|---|---|---|
| 1.1 nuclei 工具封装 | `netprobe/tools/nuclei_tool.py`：检测 nuclei 安装 → 调用 `nuclei -u <target> -j` → 解析 JSON 输出 | 单独运行能对目标输出漏洞列表 |
| 1.2 扫描流程集成 | engine.py 新增漏洞扫描阶段（Web 探测后），对发现的站点批量跑 nuclei | 扫描结果含漏洞数据 |
| 1.3 DB 存储漏洞 | 新增 `vulnerabilities` 表（host_id/vuln_id/name/severity/cve/template/url/matched_at） | 漏洞持久化，历史可查 |
| 1.4 前端展示漏洞 | ScanDetail 加漏洞 tab/section（严重度着色表格 + CVE 链接 + 模板名） | 用户能查看每个资产的漏洞 |
| 1.5 风险评分纳入漏洞 | risk.py 加"漏洞"维度（critical=20/high=10/medium=5 each，封顶并入总分） | 风险分反映漏洞情况 |
| 1.6 漏洞 API | GET /api/vulnerabilities（跨扫描漏洞汇总）+ result.py 返回漏洞 | API 可查漏洞 |

**交付物**：完整的"扫描→发现漏洞→评分→展示"链路。用户扫一个目标能看到它的漏洞。

**nuclei 模板分级**：
- 默认跑 `nuclei-templates/cves/` + `nuclei-templates/vulnerabilities/` + `nuclei-templates/misconfiguration/`
- 可选跑 `exposures/`（敏感信息泄露）+ `default-logins/`（默认凭据）
- severity 过滤：默认 info 以上，可配 critical/high only

---

### Phase 2：指纹库扩充（识别率提升）

**目标**：从演示级（42 条）提升到生产级（1000+ 条），对齐 Wappalyzer/EHole。

| 任务 | 来源 | 目标规模 | 验收标准 |
|---|---|---|---|
| 2.1 导入 Wappalyzer 指纹 | Wappalyzer 官方 JSON（~3000 技术）→ 转换为 NetProbe 格式 | +3000 条 | 主流 Web 技术识别率 >85% |
| 2.2 导入 EHole/Finger 规则 | EHole finger.json + Finger 规则（CMS/框架/OA/路由器） | +500 条 | 国内产品识别率提升 |
| 2.3 扩充敏感路径 | 常见后台/配置/备份/API 文档路径（参考 dirsearch/dbug 字典） | 目标 300+ 条 | 覆盖 OWASP Top 10 敏感配置 |
| 2.4 扩充接管指纹 | can-i-take-over-xyz 项目（~50+ SaaS 服务） | 目标 50+ 条 | 覆盖主流 SaaS 接管场景 |
| 2.5 指纹自动更新 | 可选：从 GitHub 拉取 Wappalyzer 最新 release 更新 | 定期同步 | 指纹不过时 |

**交付物**：指纹库从 42→3500+ 条，敏感路径 53→300+ 条，接管 10→50+ 条。

---

### Phase 3：扫描引擎可配置化（体验对齐）

**目标**：从固定三档（快速/标准/深度）升级为 reNgine 式可自定义扫描引擎。

| 任务 | 说明 | 验收标准 |
|---|---|---|
| 3.1 扫描引擎模型 | `scan_engines` 表（name/配置 JSON：启用哪些阶段、哪些工具、什么参数） | 可创建/保存自定义引擎 |
| 3.2 引擎配置 UI | Tasks 表单加"扫描引擎"选择器（预设 + 自定义） | 用户能选/配引擎 |
| 3.3 阶段开关 | 每个扫描阶段（子域名/端口/Web/指纹/敏感路径/漏洞/截图）可独立开关 | 精细控制扫描范围 |
| 3.4 nuclei 模板选择 | 引擎配置里选跑哪些 nuclei 模板分类 + severity 过滤 | 漏洞扫描可定制 |
| 3.5 端口范围配置 | 自定义端口/预设端口范围（common/top1000/all/custom）已有，完善 UI | 端口可控 |

**交付物**：用户能像 reNgine 一样创建"只跑子域名+端口"或"全量+深度漏洞"的自定义引擎。

---

### Phase 4：深度检测能力（差异化增强）

**目标**：补齐 API 发现、JS 深度分析、POC 验证等现代 Web 安全必备能力。

| 任务 | 说明 | 验收标准 |
|---|---|---|
| 4.1 API 端点发现 | 从 JS/spider 提取 REST/GraphQL/WSDL 端点 + 参数 | 发现隐藏 API |
| 4.2 JS 深度分析增强 | 集成 linkfinder 正则 + SecretFinder，扩充密钥检测规则 | 密钥泄露检出率提升 |
| 4.3 POC 漏洞验证 | 对 NVD 匹配到的 CVE，可选调 nuclei 对应模板验证（降低误报）| CVE 命中能主动验证 |
| 4.4 目录爆破 | 集成 ffuf/dirsearch 式目录爆破（现有 sensitive_probe 只查固定路径） | 发现更多隐藏路径 |

**交付物**：API 发现 + JS 密钥 + POC 验证 + 目录爆破，深度检测能力对齐商业工具。

---

### Phase 5：工程化收尾（生产交付）

| 任务 | 说明 |
|---|---|
| 5.1 Docker 部署 | docker-compose 一键启动（含 chromium for 截图 + nuclei + 数据卷） |
| 5.2 用户文档 | README + 安装指南 + API 文档（Swagger 已有）+ 使用教程 |
| 5.3 单元测试 | 核心服务（scan_service/diff_service/correlation_service）pytest 覆盖 |
| 5.4 CI 流水线 | GitHub Actions：lint + build + test + docker publish |
| 5.5 性能优化 | 大目标扫描的并发/内存/超时优化 |

---

## 四、优先级与依赖关系

```
Phase 0（工程修复）── 无依赖，可立即开始
    │
    ├──→ Phase 1（漏洞扫描）── 依赖 Phase 0 的 nuclei 工具修复
    │        │
    │        └──→ Phase 4.3（POC 验证）── 依赖 Phase 1 的 nuclei 集成
    │
    ├──→ Phase 2（指纹扩充）── 无依赖，可与 Phase 1 并行
    │
    └──→ Phase 3（引擎配置）── 依赖 Phase 1（漏洞扫描作为可选阶段）
             │
             └──→ Phase 4（深度检测）── 依赖 Phase 3 的引擎框架
                      │
                      └──→ Phase 5（工程化）── 最后收尾
```

**建议顺序**：Phase 0 → Phase 1 + Phase 2（并行）→ Phase 3 → Phase 4 → Phase 5

---

## 五、各阶段效果预期

| 阶段 | 完成后用户能做什么 | 对标 |
|---|---|---|
| **Phase 0** | 现有功能无 bug，masscan/证书/长扫描真正可用 | 修复基线 |
| **Phase 1** | 扫描后看到漏洞列表（CVE/严重度/PoC），风险分纳入漏洞 | **对齐 reNgine 核心** |
| **Phase 2** | 识别 3500+ Web 技术（vs 现在 42），敏感路径 300+ | **对齐 ARL 指纹库** |
| **Phase 3** | 自定义"只扫端口"或"全量+漏洞"的扫描引擎 | **对齐 reNgine 灵活性** |
| **Phase 4** | 发现 API 端点 + JS 密钥 + POC 验证 + 目录爆破 | **超越多数开源工具** |
| **Phase 5** | Docker 一键部署 + 文档 + 测试，生产可用 | **开源交付标准** |

---

## 六、NetProbe 的最终定位（完成全部阶段后）

```
                    资产发现能力
                 完整 ←────────→ 单一
                  │
     ARL(停更)    │    reNgine(7k★)
     SpiderFoot   │      ★ NetProbe ★
                  │    nuclei(22k★)
                  │
     有WebUI ←────┼────→ 纯CLI
     +持久化      │
     +变更检测    │
     +风险评分    │

NetProbe 完成全部阶段后的差异化：
  ✅ 唯一同时具备「漏洞扫描 + 风险评分 + 变更检测 + 资产关联」的开源工具
  ✅ 比 reNgine 多：风险评分 + 变更检测时间线 + 6维关联图谱
  ✅ 比 ARL 多：漏洞扫描 + 风险评分 + 现代前端 + CI/CD
  ✅ 比 nuclei 多：一站式管道（资产发现→漏洞→评分→告警）
```
