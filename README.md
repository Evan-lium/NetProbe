# NetProbe

多引擎域名探测平台，集成 Subfinder、Nmap、Masscan、RustScan、Httpx、DNSx 六大扫描引擎，自动检测可用引擎并按优先级调度。支持子域名发现、端口扫描、服务版本检测、Web 技术指纹识别、敏感路径探测、SSL 证书分析、Banner 抓取、JS 文件分析，提供 Web 界面和命令行两种使用方式。跨平台支持 Windows、macOS、Linux。

## 功能特性

- **跨平台支持** — 支持 Windows、macOS、Linux，自动适配不同平台的工具安装路径
- **多引擎支持** — 集成 6 个扫描引擎，自动检测已安装工具，按可靠性优先级调度，优雅降级
- **智能路径检测** — 自动搜索 GOPATH/bin、Homebrew、系统目录等平台特定路径，无需手动配置 PATH
- **DNS 容错** — dnspython 解析失败时自动 fallback 到系统 DNS，确保不会因 DNS 超时跳过目标
- **被动情报收集** — crt.sh 证书透明度日志（免费）、FOFA 网络空间搜索、Hunter 奇安信鹰图，多源聚合子域名
- **子域名枚举** — Subfinder（被动聚合 30+ 数据源）+ Nmap dns-brute（主动字典枚举），结果合并去重
- **端口扫描** — 两步扫描策略（快速发现 + 服务版本检测），auto 模式按可靠性优先级自动降级
- **Web 技术指纹** — 42 条指纹规则，覆盖 CMS、前端框架、Web 服务器、CDN、WAF、统计分析等 8 大类，支持 HTTP 头部 + HTML 内容 + Cookie 多维度匹配
- **敏感路径探测** — 53 条规则，检测 Git/SVN 泄露、配置文件、备份文件、管理后台、API 文档、Spring Actuator 等，并发探测提升速度
- **JS 文件分析** — 从页面 JavaScript 中提取 API 端点和泄露的密钥/Token（AWS Key、GitHub Token、JWT 等）
- **SSL/TLS 证书分析** — 提取证书主体、颁发者、有效期、SAN 域名、加密套件、协议版本
- **Banner 抓取** — 支持 FTP、SSH、SMTP、MySQL、Redis、MongoDB 等 12 种协议的 Banner 识别
- **DNS 验证** — dnspython（最可靠）> DNSx（批量快速），验证子域名可解析性
- **域名过滤** — 自动过滤不属于目标域名的结果，支持多段 TLD（如 .com.cn、.co.uk）
- **多目标输入** — 支持逗号、换行、空格分隔多个目标，按目标分组展示结果
- **IP 输入支持** — 输入 IP 自动反向 DNS 解析出域名，再进行子域名枚举
- **结果导出** — 支持 TXT、CSV、JSON 三种格式，文件名自动按域名+时间命名
- **中文编码** — 自动检测网页编码（GBK/GB2312/UTF-8），正确显示中文标题
- **实时进度** — Web 界面通过 SSE 实时推送扫描进度，显示每个引擎的运行状态

## 扫描引擎

| 引擎 | 能力 | 安装方式 | 说明 |
|------|------|---------|------|
| **Nmap** | 子域名 + 端口 | [官网下载](https://nmap.org/download.html) | dns-brute 字典枚举 + 两步端口扫描（快速发现 + -sV 版本检测），最可靠 |
| **Subfinder** | 子域名枚举 | `go install` | 被动聚合 crt.sh、VirusTotal 等 30+ 数据源，发现率高 |
| **Masscan** | 端口扫描 | 下载二进制 | 世界最快端口扫描器，需 root/管理员权限 |
| **RustScan** | 端口扫描 | 下载二进制 | 快速端口发现 + 自动调用 nmap 做服务检测 |
| **Httpx** | Web 探测 | `go install` | 批量探测 Web 存活、状态码、标题、技术栈 |
| **DNSx** | DNS 验证 | `go install` | 批量 DNS 解析验证 |

### Auto 模式调度策略

auto 模式下按**可靠性从高到低**逐个尝试引擎，第一个成功返回结果的引擎即停，失败自动降级到下一个：

```
子域名枚举: Subfinder + Nmap dns-brute（两个都跑，结果合并去重）
端口扫描:   Nmap（最可靠）→ RustScan → Masscan
DNS 验证:   dnspython（最可靠）→ DNSx
Web 探测:   Python requests（最可靠）→ Httpx
```

也可以在 Web 界面手动指定某个引擎，指定引擎失败时会降级到 Python 内置引擎。

### 端口扫描两步策略

Nmap 端口扫描采用两步策略，兼顾速度和准确性：

1. **快速端口发现** — 不做版本检测，快速扫描 COMMON_PORTS 中的 23 个常见端口，筛选出 `open` 状态的端口
2. **服务版本检测** — 仅对已发现的 open 端口做 `-sV` 版本检测，避免全量 -sV 导致的超时

## 探测流程

```
输入目标 (域名/IP，支持多个)
    │
    ├─ IP? ──→ 反向 DNS 解析 → 提取根域名
    │
    ▼
阶段1: 被动情报收集
    ├─ crt.sh 证书透明度日志（免费，无需 API Key）
    ├─ FOFA 网络空间搜索（需 API Key）
    └─ Hunter 奇安信鹰图（需 API Key）
    │
    ▼
阶段2: 子域名枚举
    ├─ Subfinder（被动枚举，发现率高）
    ├─ Nmap dns-brute（主动字典枚举，内置 210 条字典）
    └─ 合并去重 → DNS 验证过滤
    │
    ▼
阶段3: 端口扫描 + 服务检测
    ├─ Nmap 两步扫描（快速发现 + -sV 版本检测）
    └─ OS 指纹识别
    │
    ▼
阶段4: Web 站点探测
    ├─ Python requests / Httpx（按可用性自动选择）
    ├─ 技术栈指纹识别（42 条规则，8 大类）
    ├─ SSL/TLS 证书信息提取
    ├─ 敏感路径探测（53 条规则，并发扫描）
    └─ JS 文件分析（API 端点提取 + 密钥泄露检测）
    │
    ▼
阶段5: Banner 抓取
    ├─ 并发 TCP Banner 获取（12 种协议）
    └─ FTP、SSH、SMTP、MySQL、Redis 等
    │
    ▼
结果展示 + 导出文件 (TXT/CSV/JSON)
```

## 前置要求

- **Python 3.10+**
- **依赖包** — `pip install -r requirements.txt`

### 工具安装

**必选（至少装一个扫描器）：**

- **Nmap** — [下载地址](https://nmap.org/download.html)
  - Windows：安装时勾选 "Add to PATH"
  - macOS：`brew install nmap` 或官网下载
  - Linux：`sudo apt install nmap` / `sudo yum install nmap`

**推荐安装（Go 工具）：**

```bash
# 安装 Go（如未安装）：https://go.dev/dl/
# 国内加速
go env -w GOPROXY=https://goproxy.cn,direct

# 安装 Subfinder、Httpx、DNSx
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

**可选安装：**

- **Masscan** — [下载](https://github.com/robertdavidgraham/masscan/releases)
  - Linux：`sudo apt install masscan`
  - macOS：`brew install masscan`
  - Windows：需自行编译或获取预编译二进制
- **RustScan** — [下载](https://github.com/RustScan/RustScan/releases)
  - 下载对应平台的二进制，放入 `$GOPATH/bin` 或任意 PATH 目录

### Python 依赖

```bash
pip install -r requirements.txt
```

requirements.txt 内容：

```
python-nmap>=0.7.1
dnspython>=2.8.0
flask>=3.0
requests>=2.28
```

### 被动情报 API（可选）

被动情报收集功能需要配置 API Key，通过环境变量设置：

| 服务 | 环境变量 | 说明 |
|------|---------|------|
| **crt.sh** | 无需配置 | 证书透明度日志，免费，直接使用 |
| **FOFA** | `FOFA_EMAIL` + `FOFA_KEY` | [注册](https://fofa.info/)获取免费额度 |
| **Hunter** | `HUNTER_KEY` | [注册](https://hunter.qianxin.com/)获取免费额度 |

不配置 API Key 时，crt.sh 仍可正常使用，FOFA/Hunter 自动跳过。

## 使用方式

### 方式一：Web 界面（推荐）

```bash
python app.py
```

浏览器访问 **http://127.0.0.1:5000**

Web 界面功能：
- 多目标输入（逗号或换行分隔）
- 引擎选择（子域名/端口/DNS/Web 各阶段可单独指定引擎，或选 auto 自动调度）
- 勾选控制：子域名枚举 / Web 探测 / DNS 验证
- 实时进度日志，显示每个引擎的运行状态和降级情况
- 结果按目标分组展示（主机、端口、服务、Web 站点、技术栈标签、SSL 证书、敏感路径、JS 分析、Banner）
- 一键导出 TXT / CSV / JSON 文件

### 方式二：命令行

```bash
# 完整探测（被动情报 + 子域名 + 端口 + Web + 敏感路径 + JS 分析 + Banner）
python main.py example.com

# 多目标探测
python main.py example.com baidu.com qq.com

# 输入 IP，自动反向解析后探测
python main.py 8.8.8.8

# 保存结果为 JSON
python main.py example.com -f json

# 保存结果为 CSV
python main.py example.com -f csv -o my_report.csv

# 使用自定义子域名字典
python main.py example.com -w custom_wordlist.txt

# 只探测主域名，跳过子域名枚举
python main.py example.com --no-dns-brute

# 跳过 Web 探测
python main.py example.com --no-web
```

命令行参数说明：

| 参数 | 说明 |
|------|------|
| `targets` | 目标域名或 IP，多个用空格分隔（必填）|
| `-f, --format` | 输出格式：txt / csv / json（默认 txt）|
| `-o, --output` | 自定义输出文件路径（不指定则自动按 `域名_时间.格式` 命名）|
| `-w, --wordlist` | 外部子域名字典文件（不指定则使用内置 210 条字典）|
| `--no-dns-brute` | 跳过子域名枚举，只探测主域名 |
| `--no-web` | 跳过 Web 站点探测 |
| `--no-validate` | 跳过 DNS 解析验证 |
| `--timeout` | 扫描超时秒数（默认 300）|

## 项目结构

```
domain-Identify/
├── app.py                  # Web 入口 (Flask 路由 + 任务管理 + SSE)
├── main.py                 # CLI 入口 (argparse)
├── netprobe/               # 核心包
│   ├── __init__.py         # 包定义
│   ├── engine.py           # 扫描引擎 (统一流水线，CLI/Web 共用)
│   ├── scanner.py          # Nmap 交互层 (dns-brute + 两步端口扫描)
│   ├── dns_utils.py        # DNS 工具 (反向查询、A 记录、域名过滤，含系统 DNS fallback)
│   ├── utils.py            # 输入校验 (IP/域名判断、根域名提取)
│   ├── web_probe.py        # Web 探测 (HTTP/HTTPS + SSL 证书 + 编码检测 + JS URL 提取)
│   ├── fingerprint.py      # 技术栈指纹识别 (从 JSON 加载规则)
│   ├── sensitive_probe.py  # 敏感路径探测 (从 JSON 加载规则，并发扫描)
│   ├── js_analyzer.py      # JS 文件分析 (API 端点提取 + 密钥泄露检测)
│   ├── banner_grab.py      # Banner 抓取 (12 种协议)
│   ├── formatter.py        # 结果格式化 (终端表格 + TXT/CSV/JSON)
│   ├── wordlist.py         # 内置 210 条子域名字典
│   ├── data/
│   │   ├── fingerprints.json     # 42 条技术指纹规则
│   │   └── sensitive_paths.json  # 53 条敏感路径规则
│   └── tools/
│       ├── registry.py     # 工具注册表 (跨平台路径检测、能力查询)
│       ├── subfinder.py    # Subfinder — 被动子域名枚举
│       ├── masscan.py      # Masscan — 快速端口扫描
│       ├── rustscan.py     # RustScan — 快速端口发现 + nmap 服务检测
│       ├── httpx_tool.py   # Httpx — 批量 Web 探测
│       ├── dnsx.py         # DNSx — 快速 DNS 解析验证
│       ├── crtsh.py        # crt.sh — 证书透明度日志查询
│       ├── fofa.py         # FOFA — 网络空间搜索
│       └── hunter.py       # Hunter — 奇安信鹰图
├── static/
│   └── favicon.svg         # 网站图标
├── templates/
│   └── index.html          # Web 前端页面
├── requirements.txt
└── README.md
```

## 工具路径自动检测

程序会根据运行平台自动搜索工具安装路径，无需手动配置。搜索顺序：

**Windows：**
- `$GOPATH/bin`、`~/go/bin`
- `{C,D,E}:\Program Files\Nmap`、`{C,D,E}:\Program Files (x86)\Nmap`
- `~/scoop/shims`

**macOS：**
- `$GOPATH/bin`、`~/go/bin`
- `/usr/local/bin`
- `/opt/homebrew/bin`、`/opt/homebrew/sbin`（Apple Silicon Homebrew）
- `/opt/local/bin`、`/opt/local/sbin`（MacPorts）

**Linux：**
- `$GOPATH/bin`、`~/go/bin`
- `/usr/bin`、`/usr/local/bin`
- `/usr/sbin`、`/usr/local/sbin`
- `/snap/bin`、`~/.local/bin`

优先从以上路径查找（避免同名程序冲突，如 hermes 的 httpx），找不到再查系统 PATH。

如果工具安装在其他位置，可以：
1. 将工具所在目录加入系统 PATH 环境变量
2. 在 `netprobe/tools/registry.py` 的 `_get_extra_paths()` 函数中添加自定义路径

## Web API

Web 后端提供以下 API，可用于集成：

| 接口 | 方法 | 说明 |
|------|------|------|
| `/` | GET | Web 界面 |
| `/api/tools` | GET | 获取可用扫描引擎列表（含路径和状态）|
| `/api/scan` | POST | 提交扫描任务，返回 task_id |
| `/api/stream/<task_id>` | GET | SSE 实时推送扫描进度 |
| `/api/result/<task_id>` | GET | 获取扫描结果 JSON |
| `/api/download/<task_id>/<fmt>` | GET | 下载结果文件 (txt/csv/json) |

提交扫描示例：

```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "subdomain_tool": "auto",
    "portscan_tool": "auto",
    "web_tool": "auto",
    "dns_tool": "auto"
  }'
```

`*_tool` 参数可选值：`auto`（按可靠性优先级自动调度）、`nmap`、`subfinder`、`masscan`、`rustscan`、`httpx`、`dnsx`。

## 输出示例

Web 日志（显示引擎调度和降级）：

```
[12:30:01] 可用工具: Nmap, Subfinder, Httpx, DNSx
[12:30:01] 共 1 个目标: example.com
[12:30:01] ━━━ 目标 [1/1] example.com ━━━
[12:30:02]   被动情报收集 (example.com)...
[12:30:04]   [crt.sh] 发现 15 个子域名
[12:30:05]   子域名枚举 (example.com)...
[12:30:08]   [subfinder] 发现 12 个子域名
[12:30:11]   [nmap dns-brute] 发现 3 个 (共 8 条)
[12:30:13]   [dnspython] 验证完成: 18/26 可解析
[12:30:13]   子域名枚举完成: 18 个有效
[12:30:14]   端口扫描 (19 个主机)...
[12:30:28]   [nmap] 扫描完成: 24 个端口
[12:30:29]   [python] Web 探测...
[12:30:33]   [python] 发现 10 个 Web 站点
[12:30:34]   敏感路径探测...
[12:30:40]   敏感路径探测完成: 5 条发现
[12:30:41]   JavaScript 文件分析...
[12:30:43]   JS 分析完成: 3 个文件, 1 条泄露
[12:30:44]   Banner 抓取完成: 8 条
```

Web 界面展示内容包括：
- 主机列表（主机名、IP、操作系统）
- 开放端口表（端口/协议、状态、服务/版本）
- Web 站点表（URL、状态码、标题、技术栈标签、HTTP 指纹、SSL 证书信息、重定向）
- 敏感路径表（路径、说明、状态码、风险等级）
- JS 文件分析表（JS 文件 URL、API 端点、泄露密钥/Token）
- Banner 信息表（端口、服务、Banner 内容）

技术栈标签按类别颜色区分：CMS（紫色）、Framework（蓝色）、Server（绿色）、CDN（黄色）、WAF（红色）、Analytics（靛蓝）、Runtime（粉色）。

## 常见问题

### 工具已安装但检测不到？

程序会根据平台自动搜索常见安装路径（见「工具路径自动检测」章节）。如果工具安装在其他位置：

1. 将工具所在目录加入系统 PATH 环境变量
2. 在 `netprobe/tools/registry.py` 的 `_get_extra_paths()` 函数中添加自定义路径

### Httpx 检测到错误的程序？

如果系统中存在其他同名程序（如 hermes-agent 的 httpx），程序会优先从 GOPATH/bin 查找 ProjectDiscovery 的 httpx，避免冲突。

### 域名解析失败？

程序使用 dnspython 进行 DNS 解析，部分域名的 DNS 服务器可能对 dnspython 的查询超时。此时程序会自动 fallback 到系统 DNS（`socket.getaddrinfo`），确保不会因 DNS 超时而跳过目标。

### 中文标题显示乱码？

Web 探测模块已内置多编码检测：优先检查 HTTP Content-Type 头中的 charset 声明，再检查 HTML meta 标签中的 charset，最后使用 apparent_encoding 自动检测。支持 GBK、GB2312、UTF-8 等常见中文编码。

### 如何添加自定义指纹规则？

编辑 `netprobe/data/fingerprints.json`，按现有格式添加新的规则对象即可，无需修改 Python 代码。每条规则包含 `name`（名称）、`category`（类别）、`patterns`（匹配模式数组）。

### 如何添加自定义敏感路径？

编辑 `netprobe/data/sensitive_paths.json`，按现有格式添加新的路径规则即可。每条规则包含 `path`（路径）、`description`（说明）、`indicator`（响应内容指示器）、`severity`（风险等级：high/medium/low/info）。

### JS 文件分析支持哪些检测？

JS 分析模块从页面中提取 JavaScript 文件并分析：
- **API 端点** — `/api/...`、`/v1/...`、`fetch()`、`axios`、`XMLHttpRequest` 等调用
- **密钥泄露** — AWS Key、GitHub Token、JWT、API Key、硬编码密码、Private Key 等 9 类
- 自动跳过第三方 CDN（googleapis、cloudflare 等），减少噪音

### 国内 Go 工具安装失败？

```bash
# 设置 Go 代理
go env -w GOPROXY=https://goproxy.cn,direct

# 如果 sumdb 验证超时（PowerShell）
$env:GONOSUMDB="*"
$env:GONOSUMCHECK="*"

# 如果 sumdb 验证超时（Bash）
export GONOSUMDB="*"
export GONOSUMCHECK="*"
```

## 法律与免责声明

**请务必阅读以下内容后再使用本工具。**

### 合法使用要求

本工具涉及域名枚举、端口扫描、服务探测等网络行为，在许多国家和地区，未经授权对他人网络系统进行扫描可能构成违法行为。使用本工具前，请确保：

1. **已获得明确授权** — 仅对你拥有或已获得所有者书面授权的目标进行扫描
2. **遵守当地法律法规** — 不同国家/地区对网络扫描的法律定义不同，使用前请了解并遵守你所在地区的相关法律
3. **仅用于合法目的** — 包括但不限于：自有资产安全审计、授权渗透测试、安全教学与研究、CTF 竞赛

### 禁止用途

严禁将本工具用于以下用途：

- 未经授权扫描任何第三方系统或网络
- 非法获取他人网络信息或系统访问权限
- 任何形式的网络攻击或破坏行为
- 侵犯他人隐私或商业秘密
- 其他违反法律法规的行为

### 法律风险提示

在中国大陆地区，未经授权的网络扫描行为可能涉及以下法律：

- **《中华人民共和国网络安全法》** — 禁止非法侵入他人网络、干扰他人网络正常功能
- **《中华人民共和国刑法》第 285 条** — 非法侵入计算机信息系统罪、非法获取计算机信息系统数据罪
- **《中华人民共和国刑法》第 286 条** — 破坏计算机信息系统罪
- **《治安管理处罚法》第 29 条** — 对计算机信息系统造成危害的行政处罚

### 免责声明

- 本工具仅供**合法的安全研究和授权测试**使用
- 使用者因不当使用本工具而产生的一切法律责任，由使用者**自行承担**
- 本工具开发者**不承担**任何因使用本工具造成的直接或间接法律责任
- 使用本工具即视为你已阅读、理解并同意以上全部内容

**如果你不确定自己的使用行为是否合法，请不要使用本工具。**
