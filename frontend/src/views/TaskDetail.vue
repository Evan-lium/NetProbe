<template>
  <div class="task-detail-page">
    <div class="np-page-header">
      <div>
        <span class="np-page-title">{{ task?.name || task?.target || '...' }}</span>
        <el-tag :type="statusType(task?.status)" size="small" style="margin-left: 12px">{{ statusLabel(task?.status) }}</el-tag>
      </div>
      <div class="np-page-actions">
        <el-button v-if="task?.status === 'done'" type="primary" size="small" @click="viewResults">
          <el-icon><View /></el-icon> {{ t('taskDetail.viewResults') }}
        </el-button>
        <el-button @click="$router.push('/tasks')" size="small">{{ t('common.back') }}</el-button>
      </div>
    </div>

    <div v-if="loading" class="task-loading">
      <div class="np-skeleton" style="height: 120px; margin-bottom: 12px" />
      <div class="np-skeleton" style="height: 200px" />
    </div>

    <template v-else-if="task">
      <!-- 任务配置 -->
      <el-card class="config-card">
        <template #header>
          <div class="np-card-header">
            <el-icon :size="16"><Setting /></el-icon>
            {{ t('taskDetail.config') }}
          </div>
        </template>
        <div class="config-grid">
          <!-- 扫描目标（解析后的列表） -->
          <div class="config-item config-full">
            <span class="config-label">扫描目标</span>
            <div class="target-list">
              <el-tag v-for="t in (task.targets || [task.target])" :key="t" size="small" class="target-chip mono">{{ t }}</el-tag>
              <span v-if="!task.target" class="config-dash">—</span>
            </div>
          </div>
          <div class="config-item">
            <span class="config-label">{{ t('tasks.mode') }}</span>
            <span class="config-value">
              <el-tag :type="modeTagType(task.scan_mode || task.options?.scan_mode)" size="small">
                {{ modeLabel(task.scan_mode || task.options?.scan_mode) }}
              </el-tag>
            </span>
          </div>
          <div class="config-item">
            <span class="config-label">{{ t('taskDetail.taskId') }}</span>
            <span class="config-value mono">{{ task.scan_id }}</span>
          </div>
          <div class="config-item">
            <span class="config-label">{{ t('taskDetail.started') }}</span>
            <span class="config-value mono">{{ formatTime(task.started_at) }}</span>
          </div>
          <div class="config-item">
            <span class="config-label">{{ t('taskDetail.finished') }}</span>
            <span class="config-value mono">{{ formatTime(task.finished_at) }}</span>
          </div>
          <div class="config-item">
            <span class="config-label">{{ t('tasks.duration') }}</span>
            <span class="config-value mono">{{ formatDuration() }}</span>
          </div>
          <div class="config-item" v-if="task.options?.port_preset">
            <span class="config-label">{{ t('dashboard.portRange') }}</span>
            <span class="config-value">{{ task.options.port_preset }}</span>
          </div>
          <div class="config-item" v-if="task.options?.portscan_tool">
            <span class="config-label">{{ t('dashboard.portscanTool') }}</span>
            <span class="config-value">{{ task.options.portscan_tool }}</span>
          </div>
          <div class="config-item" v-if="task.options?.subdomain_tool">
            <span class="config-label">{{ t('dashboard.subdomainTool') }}</span>
            <span class="config-value">{{ task.options.subdomain_tool }}</span>
          </div>
          <div class="config-item" v-if="task.options?.web_tool">
            <span class="config-label">{{ t('dashboard.webTool') }}</span>
            <span class="config-value">{{ task.options.web_tool }}</span>
          </div>
          <div class="config-item" v-if="task.error_msg">
            <span class="config-label">{{ t('taskDetail.error') }}</span>
            <span class="config-value error-msg">{{ task.error_msg }}</span>
          </div>
        </div>
      </el-card>

      <!-- 扫描结果概要（与下发目标呼应：扫到了什么） -->
      <el-card class="result-card" v-if="task.result_summary || task.discovered_hosts?.length">
        <template #header>
          <div class="np-card-header">
            <el-icon :size="16"><DataLine /></el-icon>
            扫描结果概要
          </div>
        </template>
        <!-- 分项统计 -->
        <div class="result-stats" v-if="task.result_summary">
          <div class="rs-item">
            <span class="rs-num">{{ task.result_summary.host_count || 0 }}</span>
            <span class="rs-label">主机</span>
          </div>
          <div class="rs-item">
            <span class="rs-num">{{ task.result_summary.port_count || 0 }}</span>
            <span class="rs-label">端口</span>
          </div>
          <div class="rs-item">
            <span class="rs-num">{{ task.result_summary.web_count || 0 }}</span>
            <span class="rs-label">Web站点</span>
          </div>
          <div class="rs-item" v-if="task.result_summary.sensitive_count">
            <span class="rs-num warn">{{ task.result_summary.sensitive_count }}</span>
            <span class="rs-label">敏感路径</span>
          </div>
          <div class="rs-item" v-if="task.result_summary.vuln_count">
            <span class="rs-num danger">{{ task.result_summary.vuln_count }}</span>
            <span class="rs-label">漏洞</span>
          </div>
        </div>
        <!-- 发现的主机列表 -->
        <el-table v-if="task.discovered_hosts?.length" :data="task.discovered_hosts" size="small" class="host-mini-table" max-height="240">
          <el-table-column label="主机" min-width="180" show-overflow-tooltip>
            <template #default="{ row }">
              <span class="mono" style="font-weight:600">{{ row.hostname || row.ip }}</span>
              <span v-if="row.hostname && row.ip" class="mono host-ip-mini"> {{ row.ip }}</span>
            </template>
          </el-table-column>
          <el-table-column prop="port_count" label="端口" min-width="70" align="center" sortable />
          <el-table-column prop="web_count" label="Web" min-width="70" align="center" sortable />
          <el-table-column label="漏洞" min-width="70" align="center" sortable :sort-method="(a:any,b:any) => (a.vuln_count||0)-(b.vuln_count||0)">
            <template #default="{ row }">
              <span v-if="row.vuln_count" class="vuln-num">{{ row.vuln_count }}</span>
              <span v-else class="config-dash">—</span>
            </template>
          </el-table-column>
          <el-table-column prop="risk_score" label="风险" min-width="70" align="center" sortable>
            <template #default="{ row }">
              <span class="risk-num" :class="riskLevel(row.risk_score)">{{ row.risk_score }}</span>
            </template>
          </el-table-column>
        </el-table>
        <div v-else-if="task.status !== 'done'" class="result-pending">
          <el-icon class="spin"><Loading /></el-icon>
          扫描进行中，结果待出...
        </div>

        <!-- 主域名 + 子域名（从 hosts 区分） -->
        <div v-if="domainInfo.subdomains.length" class="domain-section">
          <div class="domain-row">
            <span class="domain-label">主域名</span>
            <el-tag type="primary" size="small" class="mono">{{ domainInfo.base }}</el-tag>
          </div>
          <div class="domain-row">
            <span class="domain-label">子域名 ({{ domainInfo.subdomains.length }})</span>
            <div class="subdomain-chips">
              <el-tag v-for="s in domainInfo.subdomains" :key="s" size="small" class="mono subdomain-chip">{{ s }}</el-tag>
            </div>
          </div>
        </div>
      </el-card>

      <!-- Tab：执行日志 + 扫描结果（合并展示） -->
      <el-tabs v-model="detailTab" class="detail-tabs">

        <!-- Tab 1: 执行日志（纯展示，不要统计数字） -->
        <el-tab-pane name="logs">
          <template #label>
            <span class="tab-label">
              <el-icon :class="{ 'spin': isStreaming }"><Monitor /></el-icon>
              执行日志
            </span>
          </template>
          <div class="console-area" ref="logRef">
            <div v-for="(line, i) in liveLogs" :key="i" class="console-line">
              <span class="console-prefix">{{ String(i + 1).padStart(3, '0') }}</span>
              <span :class="logClass(line)">{{ line }}</span>
            </div>
            <div v-if="!liveLogs.length && task.status === 'running'" class="console-empty">
              <span class="cursor-blink">▊</span> {{ t('dashboard.waitingEvents') }}
            </div>
          </div>
        </el-tab-pane>

        <!-- Tab 2: 扫描结果（内联，无需跳转） -->
        <el-tab-pane name="results" :disabled="task.status === 'running' && !scanStore.hosts.length">
          <template #label>
            <span class="tab-label">
              <el-icon><View /></el-icon>
              扫描结果
              <span class="tab-count" v-if="scanStore.hosts.length">{{ scanStore.hosts.length }}</span>
            </span>
          </template>
          <div v-if="scanStore.hosts.length" class="results-area">
            <el-card v-for="(host, i) in scanStore.hosts" :key="i" class="host-card">
              <template #header>
                <div class="host-header">
                  <span class="host-index">#{{ i + 1 }}</span>
                  <span class="host-name">{{ host.hostname || host.ip }}</span>
                  <span class="mono host-ip" v-if="host.ip && host.hostname">{{ host.ip }}</span>
                </div>
              </template>
              <!-- 端口 -->
              <div v-if="host.ports?.length" class="result-section">
                <div class="np-section-title"><el-icon :size="14"><Connection /></el-icon> 端口 <span class="np-badge">{{ host.ports.length }}</span></div>
                <div class="np-table-wrapper">
                  <el-table :data="host.ports" size="small">
                    <el-table-column prop="port" :label="t('table.port')" min-width="70"><template #default="{ row }"><span class="mono">{{ row.port }}</span></template></el-table-column>
                    <el-table-column prop="proto" :label="t('table.proto')" min-width="65" />
                    <el-table-column prop="state" :label="t('table.state')" min-width="80"><template #default="{ row }"><el-tag :type="row.state === 'open' ? 'success' : 'info'" size="small">{{ row.state }}</el-tag></template></el-table-column>
                    <el-table-column prop="service" :label="t('table.service')" />
                    <el-table-column prop="product" :label="t('table.product')" />
                    <el-table-column prop="version" :label="t('table.version')" />
                  </el-table>
                </div>
              </div>
              <!-- Web 站点 -->
              <div v-if="host.web_info?.length" class="result-section">
                <div class="np-section-title"><el-icon :size="14"><Globe /></el-icon> Web 站点 <span class="np-badge">{{ host.web_info.length }}</span></div>
                <div class="np-table-wrapper">
                  <el-table :data="host.web_info" size="small">
                    <el-table-column prop="url" label="URL" min-width="180" show-overflow-tooltip />
                    <el-table-column prop="status" label="状态码" min-width="70" />
                    <el-table-column prop="title" label="标题" min-width="120" show-overflow-tooltip />
                  </el-table>
                </div>
              </div>
            </el-card>
          </div>
          <div v-else class="np-empty">
            <el-icon :size="28" color="var(--np-text-disabled)"><Grid /></el-icon>
            <p>暂无结果数据（{{ task.status === 'running' ? '扫描进行中' : '无结果' }}）</p>
          </div>
        </el-tab-pane>
      </el-tabs>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { getTaskDetail, getHistoryDetail } from '../api/scan'
import api from '../api/index'
import { useScanStore } from '../stores/scan'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const scanStore = useScanStore()

const task = ref<any>(null)
const loading = ref(true)
const liveLogs = ref<string[]>([])
const isStreaming = ref(false)
const logRef = ref<HTMLElement>()
const detailTab = ref('logs')  // logs | results
let eventSource: EventSource | null = null

/** 从 hosts 区分主域名和子域名 */
const domainInfo = computed(() => {
  const base = task.value?.base_domain || task.value?.targets?.[0] || ''
  const hosts = task.value?.discovered_hosts || []
  const seen = new Set<string>()
  const subdomains: string[] = []
  for (const h of hosts) {
    const hn = h.hostname || ''
    if (hn && hn !== base && !seen.has(hn) && hn.endsWith(base)) {
      seen.add(hn)
      subdomains.push(hn)
    }
  }
  return { base, subdomains }
})

function statusType(status?: string) {
  if (status === 'done') return 'success'
  if (status === 'error') return 'danger'
  if (status === 'cancelled') return 'info'
  return 'warning'
}

function statusLabel(status?: string) {
  if (status === 'done') return t('history.statusDone')
  if (status === 'error') return t('history.statusError')
  if (status === 'running') return t('history.statusRunning')
  if (status === 'cancelled') return t('tasks.cancelled')
  return status || ''
}

function modeTagType(mode?: string) {
  if (mode === 'quick') return 'info'
  if (mode === 'deep') return 'danger'
  return 'success'
}

/** 风险分等级（用于着色） */
function riskLevel(score: number): string {
  if (score >= 70) return 'risk-high'
  if (score >= 40) return 'risk-medium'
  return 'risk-low'
}

function modeLabel(mode?: string) {
  if (mode === 'quick') return t('dashboard.modeQuick')
  if (mode === 'deep') return t('dashboard.modeDeep')
  return t('dashboard.modeNormal')
}

function formatTime(s: string | null) {
  if (!s) return '—'
  const d = new Date(s)
  if (isNaN(d.getTime())) return s
  return d.toLocaleString('zh-CN')
}

function formatDuration() {
  if (task.value?.duration_secs != null) return `${task.value.duration_secs}s`
  if (task.value?.status === 'running' && task.value?.started_at) {
    const elapsed = Math.floor((Date.now() - new Date(task.value.started_at).getTime()) / 1000)
    return `${elapsed}s`
  }
  return '—'
}

function logClass(line: string) {
  if (line.includes('[error]') || line.includes('[!]')) return 'log-error'
  if (line.includes('[done]')) return 'log-done'
  if (line.includes('✓') || line.includes('[+]')) return 'log-found'
  return ''
}

function viewResults() {
  router.push(`/scan/${route.params.id}`)
}

function connectSSE(taskId: string) {
  disconnectSSE()
  isStreaming.value = true
  liveLogs.value = []
  const token = localStorage.getItem('netprobe_token') || ''
  eventSource = new EventSource(`/api/stream/${taskId}?token=${encodeURIComponent(token)}`)
  eventSource.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data)
      if (data.event === 'progress' || data.event === 'log') {
        if (data.text) liveLogs.value.push(data.text)
      } else if (data.event === 'done') {
        liveLogs.value.push('[done] 扫描完成')
        isStreaming.value = false
        disconnectSSE()
        loadTask()
      } else if (data.event === 'error') {
        liveLogs.value.push(`[error] ${data.text || ''}`)
        isStreaming.value = false
        disconnectSSE()
      } else if (data.event === 'cancelled') {
        liveLogs.value.push('[cancelled] 任务已取消')
        isStreaming.value = false
        disconnectSSE()
      } else if (data.text) {
        liveLogs.value.push(data.text)
      }
    } catch {
      liveLogs.value.push(e.data)
    }
  }
  eventSource.onerror = () => {
    isStreaming.value = false
    disconnectSSE()
  }
}

function disconnectSSE() {
  if (eventSource) {
    eventSource.close()
    eventSource = null
  }
}

async function loadTask() {
  loading.value = true
  try {
    task.value = await getTaskDetail(route.params.id as string)
    if (task.value?.status === 'running') {
      // 运行中：连 SSE（会自动推历史日志 + 实时）
      liveLogs.value = []
      connectSSE(route.params.id as string)
      // 运行中也连 scanStore 接收实时结果（done 事件带 hosts）
      scanStore.connect(route.params.id as string)
    } else {
      // 已完成/出错/取消：从 DB 拉历史日志
      liveLogs.value = []
      try {
        const data: any = await api.get(`/tasks/${route.params.id}/logs`)
        if (data?.lines?.length) {
          liveLogs.value = data.lines.filter((l: string) => l.trim())
        } else {
          liveLogs.value = ['[info] 该任务无历史日志（可能在日志持久化功能上线前完成）']
        }
      } catch (e: any) {
        liveLogs.value = [`[error] 加载历史日志失败: ${e.message || e}`]
      }
      // 已完成：加载扫描结果数据供「扫描结果」Tab 展示
      await loadResults()
    }
  } catch {
    task.value = null
  } finally {
    loading.value = false
  }
}

watch(liveLogs, async () => {
  await nextTick()
  if (logRef.value) logRef.value.scrollTop = logRef.value.scrollHeight
}, { deep: true })

/** 加载扫描结果数据到 scanStore（已完成任务，不走 SSE） */
async function loadResults() {
  try {
    const result: any = await getHistoryDetail(route.params.id as string)
    if (result) {
      scanStore.scanId = result.scan_id || route.params.id
      scanStore.status = result.status || 'done'
      scanStore.baseDomain = result.base_domain || ''
      scanStore.hosts = result.hosts || []
    }
  } catch {
    /* 结果加载失败不影响日志查看 */
  }
}

onMounted(loadTask)
onUnmounted(() => {
  disconnectSSE()
  scanStore.disconnect()
})
</script>

<style scoped>
.task-detail-page {  }
.np-page-actions { display: flex; gap: 8px; }

.config-card, .log-card, .summary-card, .result-card { margin-bottom: var(--np-space-4); }

/* 扫描目标列表（跨整行） */
.config-full { grid-column: 1 / -1; }
.target-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 4px; }
.target-chip { font-size: 12px; }
.config-dash { color: var(--np-text-disabled); }

/* 扫描结果概要 */
.result-stats {
  display: flex;
  gap: var(--np-space-6);
  flex-wrap: wrap;
  padding-bottom: var(--np-space-3);
  margin-bottom: var(--np-space-3);
  border-bottom: 1px solid var(--np-border);
}
.rs-item { display: flex; flex-direction: column; align-items: center; }
.rs-num { font-size: 28px; font-weight: 800; font-family: var(--np-font-mono); color: var(--np-blue-600); line-height: 1.2; }
.rs-num.warn { color: var(--np-warning); }
.rs-num.danger { color: var(--np-danger); }
.rs-label { font-size: 12px; color: var(--np-text-muted); margin-top: 2px; }

/* 发现的主机迷你表 */
.host-mini-table { margin-top: 4px; }
.host-ip-mini { color: var(--np-text-muted); font-size: 12px; }

/* 主域名/子域名区 */
.domain-section {
  margin-top: var(--np-space-3);
  padding-top: var(--np-space-3);
  border-top: 1px solid var(--np-border);
}
.domain-row {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin-bottom: 8px;
}
.domain-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--np-text-muted);
  min-width: 90px;
  flex-shrink: 0;
  padding-top: 2px;
}
.subdomain-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  flex: 1;
}
.subdomain-chip {
  font-size: 11px;
}
.vuln-num { color: var(--np-danger); font-weight: 700; }
.risk-num { font-weight: 700; font-family: var(--np-font-mono); }
.risk-num.risk-high { color: var(--np-danger); }
.risk-num.risk-medium { color: var(--np-warning); }
.risk-num.risk-low { color: var(--np-success); }
.result-pending {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--np-text-muted);
  font-size: 13px;
  padding: var(--np-space-3) 0;
}

/* Tab 区 */
.detail-tabs { margin-top: var(--np-space-3); }
.tab-label { display: inline-flex; align-items: center; gap: 4px; font-size: 13px; }
.tab-count {
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 18px; height: 18px; padding: 0 5px; border-radius: 9px;
  background: var(--np-bg-elevated); color: var(--np-text-muted);
  font-size: 10px; font-weight: 700; font-family: var(--np-font-mono);
}

/* 概要统计条（紧凑，放 Tab 上方） */
.summary-bar {
  display: flex;
  gap: var(--np-space-6);
  padding: var(--np-space-3) var(--np-space-4);
  background: var(--np-bg-elevated);
  border-radius: var(--np-radius-lg);
  margin-bottom: var(--np-space-3);
}

/* 结果区 */
.results-area { max-height: calc(80vh - 200px); overflow-y: auto; }
.host-card { margin-bottom: var(--np-space-3); }
.host-header { display: flex; align-items: center; gap: var(--np-space-2); }
.host-index { color: var(--np-blue-500); font-weight: 700; font-size: 13px; }
.host-name { font-size: 14px; font-weight: 600; color: var(--np-text-primary); }
.host-ip { color: var(--np-text-muted); font-size: 12px; }
.result-section { margin-top: var(--np-space-3); }
.result-section:first-child { margin-top: 0; }
.np-section-title {
  display: flex; align-items: center; gap: 6px;
  font-size: 13px; font-weight: 600; color: var(--np-text-secondary);
  margin-bottom: var(--np-space-2);
}
.np-badge {
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 18px; height: 18px; padding: 0 5px; border-radius: 9px;
  background: var(--np-info-bg); color: var(--np-blue-500);
  font-size: 10px; font-weight: 700;
}
.config-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: var(--np-space-3); }
.config-item { display: flex; flex-direction: column; gap: 2px; }
.config-label { font-size: 12px; color: var(--np-text-muted); text-transform: uppercase; letter-spacing: 0.03em; }
.config-value { font-size: 14px; color: var(--np-text-primary); }
.config-value.error-msg { color: var(--np-danger); }

.log-count { margin-left: auto; font-size: 12px; color: var(--np-text-muted); font-weight: 400; }

.spin { animation: np-spin 1.5s linear infinite; color: var(--np-blue-500); }
@keyframes np-spin { to { transform: rotate(360deg); } }

.console-area {
  background: #0d1117; color: #7ee787;
  font-family: var(--np-font-mono); font-size: 13px;
  padding: var(--np-space-4); border-radius: var(--np-radius-lg);
  max-height: 400px; overflow-y: auto; line-height: 1.7;
  border: 1px solid #1b2330;
}
.console-line { display: flex; gap: var(--np-space-3); white-space: pre-wrap; word-break: break-all; }
.console-prefix { color: #484f58; flex-shrink: 0; user-select: none; }
.log-error { color: #ff7b72; }
.log-done { color: #79c0ff; font-weight: 600; }
.log-found { color: #ffa657; }
.console-empty { color: #6e7681; }
.cursor-blink { animation: blink 1s step-end infinite; }
@keyframes blink { 50% { opacity: 0; } }

.summary-grid { display: flex; gap: var(--np-space-6); flex-wrap: wrap; }
.summary-item { display: flex; flex-direction: column; align-items: center; }
.summary-num { font-size: 28px; font-weight: 700; font-family: var(--np-font-mono); color: var(--np-text-primary); }
.summary-num.small { font-size: 14px; }
.summary-label { font-size: 12px; color: var(--np-text-muted); margin-top: 2px; }
</style>
