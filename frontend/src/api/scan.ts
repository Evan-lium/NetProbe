import api from './index'
import type { ScanRequest, ScanResponse, ScanResult, HistoryList, AssetSummary, ToolStatus, Settings, TaskInfo, TaskList } from '../types'

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
