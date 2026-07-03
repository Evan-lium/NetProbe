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
  screenshot?: boolean
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
  cpe?: string
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
  risk_score?: number
  risk_factors?: Record<string, any>
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
  risk_score?: number
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

/** 定时任务规则 */
export interface ScheduleTask {
  id: number
  name: string
  target_raw: string
  cron_expr: string
  options: Record<string, any>
  enabled: boolean
  last_run_at: string | null
  next_run_at: string | null
  created_at: string | null
}

/** 定时任务列表 */
export interface ScheduleList {
  items: ScheduleTask[]
  total: number
}

/** 创建/更新定时任务请求 */
export interface ScheduleRequest {
  name: string
  target: string
  cron_expr: string
  options: Record<string, any>
  enabled: boolean
}

// ── 扫描对比 Diff ──

/** 单维度差异（端口/敏感路径等），added/removed 为原始项 */
export interface DimensionDiff<T = any> {
  added: T[]
  removed: T[]
}

/** 端口差异（额外含 changed） */
export interface PortDiff extends DimensionDiff {
  changed: { key: (number | string)[]; from: Port; to: Port }[]
}

/** Web 站点差异（额外含 changed，changed 描述字段变化与技术栈增删） */
export interface WebDiff extends DimensionDiff {
  changed: { url: string; changes: Record<string, any> }[]
}

/** 主机维度差异 */
export interface HostDiff {
  key: string[]
  hostname: string
  ip: string
  status: 'added' | 'removed' | 'changed'
  ports: PortDiff
  web: WebDiff
  sensitive: DimensionDiff
  js: DimensionDiff
  banners: DimensionDiff
}

/** Diff 汇总统计 */
export interface DiffSummary {
  hosts_added: number
  hosts_removed: number
  hosts_changed: number
  ports_added: number
  ports_removed: number
  ports_changed: number
  web_added: number
  web_removed: number
  tech_changed: number
}

/** Diff 完整响应 */
export interface ScanDiff {
  scan_a: { scan_id: string; base_domain: string }
  scan_b: { scan_id: string; base_domain: string }
  summary: DiffSummary
  hosts: HostDiff[]
}

// ── 资产关联 ──

/** 关联类型 */
export type CorrelationType = 'ip' | 'cert' | 'tech' | 'service' | 'favicon' | 'banner'

/** 关联簇成员 */
export interface CorrelationMember {
  hostname: string
  ip: string
  url?: string
}

/** 关联簇 */
export interface CorrelationCluster {
  type: CorrelationType
  key: string
  count: number
  members: CorrelationMember[]
  // 各类型特有字段（可选）
  issuer?: string
  not_after?: string
  expired?: boolean
  names?: string[]
  product?: string
  version?: string
}

/** 关联查询响应（按类型分组） */
export interface CorrelationResult {
  groups: Partial<Record<CorrelationType, CorrelationCluster[]>>
  total: number
}
