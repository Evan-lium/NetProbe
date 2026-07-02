/** 扫描请求 */
export interface ScanRequest {
  target: string
  name?: string
  no_dns_brute?: boolean
  no_web?: boolean
  no_validate?: boolean
  timeout?: number
  subdomain_tool?: string
  portscan_tool?: string
  web_tool?: string
  dns_tool?: string
  port_preset?: string
  custom_ports?: string
}

/** 扫描响应 */
export interface ScanResponse {
  task_id: string
  status: string
}

/** 端口信息 */
export interface Port {
  port: number
  proto: string
  state: string
  service: string
  product: string
  version: string
}

/** Banner 信息 */
export interface Banner {
  port: number
  service: string
  banner: string
}

/** Web 站点信息 */
export interface WebInfo {
  port: number
  url: string
  status: number | null
  title: string
  redirect: string
  headers: Record<string, string>
  tech: TechItem[]
  ssl: SSLInfo | null
}

export interface TechItem {
  name: string
  version?: string
  category?: string
}

export interface SSLInfo {
  subject: string
  issuer: string
  protocol: string
  expired?: boolean
}

/** 敏感路径 */
export interface SensitivePath {
  path: string
  description: string
  severity: string
  status_code: number | null
}

/** JS 分析结果 */
export interface JSFinding {
  js_url: string
  api_endpoints: string[]
  secrets: SecretFinding[]
}

export interface SecretFinding {
  type: string
  match: string
  severity: string
}

/** 主机结果 */
export interface Host {
  hostname: string
  ip: string
  os: string
  ports: Port[]
  banners: Banner[]
  web_info: WebInfo[]
  sensitive: SensitivePath[]
  js_findings: JSFinding[]
}

/** 扫描结果 */
export interface ScanResult {
  scan_id: string
  status: string
  base_domain: string
  hosts: Host[]
}

/** SSE 事件 */
export interface SSEEvent {
  event: string
  [key: string]: any
}

/** 历史记录项 */
export interface HistoryItem {
  scan_id: string
  name: string
  target_raw: string
  base_domain: string
  status: string
  host_count: number
  port_count: number
  web_count: number
  sensitive_count: number
  error_msg: string
  started_at: string
  finished_at: string | null
  duration_secs: number | null
}

/** 历史列表 */
export interface HistoryList {
  items: HistoryItem[]
  total: number
  page: number
  per_page: number
}

/** 资产汇总 */
export interface AssetSummary {
  ip: string
  hostname: string
  scan_count: number
  port_count: number
  web_count: number
}

/** 工具状态 */
export interface ToolStatus {
  name: string
  label: string
  available: boolean
  caps: string[]
}

/** 设置 */
export interface Settings {
  layout: 'sidebar' | 'topnav'
  theme: 'light' | 'dark'
  api_keys: Record<string, string>
}

/** 任务信息 */
export interface TaskInfo {
  id: string
  scan_id: string
  name: string
  target: string
  status: 'running' | 'done' | 'error' | 'cancelled'
  host_count: number
  port_count: number
  web_count: number
  started_at: string
  finished_at: string | null
  duration_secs: number | null
  progress: string
  options: Record<string, any> | null
  error_msg: string
}

/** 任务列表 */
export interface TaskList {
  items: TaskInfo[]
  total: number
}
