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
          <div class="config-item">
            <span class="config-label">{{ t('taskDetail.target') }}</span>
            <span class="config-value mono">{{ task.target }}</span>
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

      <!-- 执行日志（实时 SSE） -->
      <el-card class="log-card" v-if="task.status === 'running' || liveLogs.length">
        <template #header>
          <div class="np-card-header">
            <el-icon :size="16" :class="{ 'spin': isStreaming }"><Monitor /></el-icon>
            {{ t('taskDetail.executionLog') }}
            <span class="log-count mono" v-if="liveLogs.length">{{ liveLogs.length }} {{ t('scanResult.events', { n: liveLogs.length }) }}</span>
          </div>
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
      </el-card>

      <!-- 概要统计（done 状态） -->
      <el-card v-if="task.status === 'done'" class="summary-card">
        <template #header>
          <div class="np-card-header">
            <el-icon :size="16"><DataLine /></el-icon>
            {{ t('taskDetail.summary') }}
          </div>
        </template>
        <div class="summary-grid">
          <div class="summary-item"><span class="summary-num">{{ task.host_count }}</span><span class="summary-label">{{ t('common.hosts') }}</span></div>
          <div class="summary-item"><span class="summary-num">{{ task.port_count }}</span><span class="summary-label">{{ t('common.ports') }}</span></div>
          <div class="summary-item"><span class="summary-num">{{ task.web_count }}</span><span class="summary-label">{{ t('common.web') }}</span></div>
          <div class="summary-item" v-if="task.progress"><span class="summary-num small">{{ task.progress }}</span><span class="summary-label">{{ t('tasks.progress') }}</span></div>
        </div>
        <el-button type="primary" @click="viewResults" style="margin-top: 16px">
          <el-icon><View /></el-icon> {{ t('taskDetail.viewResults') }}
        </el-button>
      </el-card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { getTaskDetail } from '../api/scan'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()

const task = ref<any>(null)
const loading = ref(true)
const liveLogs = ref<string[]>([])
const isStreaming = ref(false)
const logRef = ref<HTMLElement>()
let eventSource: EventSource | null = null

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
  eventSource = new EventSource(`/api/stream/${taskId}`)
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
      connectSSE(route.params.id as string)
    }
  } finally {
    loading.value = false
  }
}

watch(liveLogs.value, async () => {
  await nextTick()
  if (logRef.value) logRef.value.scrollTop = logRef.value.scrollHeight
})

onMounted(loadTask)
onUnmounted(disconnectSSE)
</script>

<style scoped>
.task-detail-page {  }
.np-page-actions { display: flex; gap: 8px; }

.config-card, .log-card, .summary-card { margin-bottom: var(--np-space-4); }
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
