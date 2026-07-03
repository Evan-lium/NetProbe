import api from './index'
import type { ScanRequest, ScanResponse, ScanResult, HistoryList, AssetSummary, ToolStatus, Settings, TaskInfo, TaskList, ScheduleTask, ScheduleList, ScheduleRequest, ScanDiff, CorrelationResult, CorrelationType } from '../types'

/** 启动扫描 */
export function startScan(req: ScanRequest): Promise<ScanResponse> {
  return api.post('/scan', req)
}

/** 获取扫描结果 */
export function getResult(scanId: string): Promise<ScanResult> {
  return api.get(`/result/${scanId}`)
}

/** 获取历史列表 */
export function getHistory(params: { page?: number; per_page?: number; q?: string; status?: string } = {}): Promise<HistoryList> {
  return api.get('/history', { params })
}

/** 获取历史详情 */
export function getHistoryDetail(scanId: string) {
  return api.get(`/history/${scanId}`)
}

/** 删除历史记录 */
export function deleteHistory(scanId: string) {
  return api.delete(`/history/${scanId}`)
}

/** 获取资产列表 */
export function getAssets(q = '', sort = 'hostname'): Promise<{ items: AssetSummary[]; total: number }> {
  return api.get('/assets', { params: { q, sort } })
}

/** 获取工具状态 */
export function getTools(): Promise<Record<string, ToolStatus>> {
  return api.get('/tools')
}

/** 获取设置 */
export function getSettings(): Promise<Settings> {
  return api.get('/settings')
}

/** 更新设置 */
export function updateSettings(data: Partial<Settings>): Promise<Settings> {
  return api.put('/settings', data)
}

/** 下载报告 */
export function getDownloadUrl(scanId: string, fmt: string): string {
  return `/api/download/${scanId}/${fmt}`
}

/** 获取所有任务 */
export function getTasks(): Promise<TaskList> {
  return api.get('/tasks')
}

/** 获取任务详情 */
export function getTaskDetail(taskId: string): Promise<TaskInfo> {
  return api.get(`/tasks/${taskId}`)
}

/** 取消运行中的任务 */
export function cancelTask(taskId: string): Promise<{ ok: boolean }> {
  return api.post(`/tasks/${taskId}/cancel`)
}

/** 删除任务 */
export function deleteTask(taskId: string): Promise<{ ok: boolean }> {
  return api.delete(`/tasks/${taskId}`)
}

// ── 定时扫描任务 ──

/** 获取定时任务列表 */
export function getSchedules(): Promise<ScheduleList> {
  return api.get('/schedules')
}

/** 创建定时任务 */
export function createSchedule(req: ScheduleRequest): Promise<ScheduleTask> {
  return api.post('/schedules', req)
}

/** 更新定时任务 */
export function updateSchedule(id: number, data: Partial<ScheduleRequest>): Promise<ScheduleTask> {
  return api.put(`/schedules/${id}`, data)
}

/** 删除定时任务 */
export function deleteSchedule(id: number): Promise<{ ok: boolean }> {
  return api.delete(`/schedules/${id}`)
}

/** 启用/暂停切换 */
export function toggleSchedule(id: number, enabled: boolean): Promise<ScheduleTask> {
  return api.post(`/schedules/${id}/toggle`, { enabled })
}

/** 立即手动触发一次 */
export function runScheduleNow(id: number): Promise<{ ok: boolean }> {
  return api.post(`/schedules/${id}/run`)
}

// ── 扫描结果对比 ──

/** 对比两次扫描 */
export function getDiff(scanA: string, scanB: string): Promise<ScanDiff> {
  return api.get('/result/diff', { params: { a: scanA, b: scanB } })
}

/** 获取资产生命周期时间线 */
export function getTimeline(target: string): Promise<any> {
  return api.get('/result/timeline', { params: { target } })
}

// ── 资产关联 ──

/** 获取资产关联簇 */
export function getCorrelations(type?: CorrelationType): Promise<CorrelationResult> {
  return api.get('/correlations', { params: type ? { type } : {} })
}

/** 获取关系图谱数据 */
export function getCorrelationGraph(): Promise<{ nodes: any[]; links: any[]; categories: any[] }> {
  return api.get('/correlations/graph')
}
