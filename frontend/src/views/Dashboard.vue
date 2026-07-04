<template>
  <div class="dashboard">
    <!-- Stats overview -->
    <div class="stats-row">
      <div class="stat-card" v-for="stat in stats" :key="stat.labelKey">
        <div class="stat-icon" :style="{ background: stat.bg }">
          <el-icon :size="20" :color="stat.color"><component :is="stat.icon" /></el-icon>
        </div>
        <div class="stat-info">
          <span class="stat-value">{{ stat.value }}</span>
          <span class="stat-label">{{ t(stat.labelKey) }}</span>
        </div>
      </div>
    </div>

    <div class="dashboard-grid">
      <!-- Running tasks -->
      <el-card class="running-card">
        <template #header>
          <div class="np-card-header">
            <el-icon :size="16"><VideoPlay /></el-icon>
            <span>{{ t('dashboard.runningTasks') }}</span>
          </div>
        </template>
        <div v-if="loadingTasks" class="recent-loading">
          <div class="np-skeleton" style="height: 56px; margin-bottom: 8px" />
          <div class="np-skeleton" style="height: 56px" />
        </div>
        <template v-else-if="runningTasks.length">
          <router-link
            v-for="item in runningTasks"
            :key="item.id"
            to="/tasks"
            class="task-item"
          >
            <div class="task-info">
              <span class="task-name">{{ item.name || item.target }}</span>
              <span class="task-meta mono">
                {{ item.target }}
                <template v-if="item.progress"> · {{ item.progress }}</template>
              </span>
            </div>
            <el-tag type="warning" size="small" effect="dark">
              {{ formatElapsed(item) }}
            </el-tag>
          </router-link>
        </template>
        <div v-else class="np-empty">
          <el-icon :size="36" color="var(--np-text-disabled)"><VideoPlay /></el-icon>
          <p>{{ t('dashboard.noRunningTasks') }}</p>
          <router-link to="/tasks" class="empty-action">
            <el-button type="primary" size="small">{{ t('dashboard.createScan') }}</el-button>
          </router-link>
        </div>
        <div v-if="runningTasks.length" class="card-footer">
          <router-link to="/tasks" class="view-all-link">
            {{ t('dashboard.viewAllTasks') }}
            <el-icon><ArrowRight /></el-icon>
          </router-link>
        </div>
      </el-card>

      <!-- Recent activity -->
      <el-card class="recent-card">
        <template #header>
          <div class="np-card-header">
            <el-icon :size="16"><Clock /></el-icon>
            <span>{{ t('dashboard.recentActivity') }}</span>
          </div>
        </template>
        <div v-if="loadingRecent" class="recent-loading">
          <div class="np-skeleton" style="height: 56px; margin-bottom: 8px" />
          <div class="np-skeleton" style="height: 56px" />
        </div>
        <template v-else-if="recentScans.length">
          <router-link
            v-for="item in recentScans"
            :key="item.scan_id"
            :to="`/tasks/${item.scan_id}`"
            class="recent-item"
          >
            <div class="recent-info">
              <span class="recent-name" v-if="item.name">{{ item.name }}</span>
              <span class="recent-target">{{ item.base_domain || item.target_raw }}</span>
              <span class="recent-meta mono">
                {{ item.host_count }} {{ t('common.hosts') }}
                &middot; {{ item.port_count }} {{ t('common.ports') }}
                <template v-if="item.duration_secs"> &middot; {{ item.duration_secs }}s</template>
              </span>
            </div>
            <el-tag :type="statusType(item.status)" size="small">{{ statusLabel(item.status) }}</el-tag>
          </router-link>
        </template>
        <div v-else class="np-empty">
          <el-icon :size="36" color="var(--np-text-disabled)"><Monitor /></el-icon>
          <p>{{ t('dashboard.noScans') }}</p>
        </div>
        <div v-if="recentScans.length" class="card-footer">
          <router-link to="/tasks" class="view-all-link">
            {{ t('dashboard.viewAll') }}
            <el-icon><ArrowRight /></el-icon>
          </router-link>
        </div>
      </el-card>
    </div>

    <!-- 实时控制台输出（有运行中任务时显示） -->
    <el-card v-if="liveTaskId" class="console-card">
      <template #header>
        <div class="np-card-header">
          <el-icon :size="16" :class="{ 'spin': isStreaming }"><Monitor /></el-icon>
          <span>{{ t('dashboard.liveConsole') }}</span>
          <span class="console-task mono" v-if="liveTaskName">{{ liveTaskName }}</span>
          <span class="console-status">
            <el-tag :type="streamStatus === 'done' ? 'success' : streamStatus === 'error' ? 'danger' : 'warning'" size="small">
              {{ streamStatus === 'done' ? t('history.statusDone') : streamStatus === 'error' ? t('history.statusError') : t('history.statusRunning') }}
            </el-tag>
          </span>
          <router-link :to="`/scan/${liveTaskId}`" class="console-detail-link">
            {{ t('dashboard.viewDetail') }} <el-icon><ArrowRight /></el-icon>
          </router-link>
        </div>
      </template>
      <div class="console-area" ref="consoleRef" role="log" aria-live="polite">
        <div v-for="(line, i) in liveLogs" :key="i" class="console-line">
          <span class="console-prefix">{{ String(i + 1).padStart(3, '0') }}</span>
          <span :class="logClass(line)">{{ line }}</span>
        </div>
        <div v-if="liveLogs.length === 0" class="console-empty">
          <span class="cursor-blink">▊</span> {{ t('dashboard.waitingEvents') }}
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import { getTasks, getHistory } from '../api/scan'
import type { TaskInfo, HistoryItem } from '../types'

const { t } = useI18n()

const loadingTasks = ref(true)
const loadingRecent = ref(true)
const runningTasks = ref<TaskInfo[]>([])
const recentScans = ref<HistoryItem[]>([])
let pollTimer: ReturnType<typeof setInterval> | null = null

// ── 实时控制台（SSE 监听运行中任务）──
const liveTaskId = ref('')
const liveTaskName = ref('')
const liveLogs = ref<string[]>([])
const streamStatus = ref<'idle' | 'running' | 'done' | 'error'>('idle')
const isStreaming = computed(() => streamStatus.value === 'running')
const consoleRef = ref<HTMLElement>()
let eventSource: EventSource | null = null

function connectLiveStream(taskId: string, name: string) {
  disconnectLiveStream()
  liveTaskId.value = taskId
  liveTaskName.value = name
  liveLogs.value = []
  streamStatus.value = 'running'

  eventSource = new EventSource(`/api/stream/${taskId}`)
  eventSource.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data)
      const evt = data.event
      if (evt === 'progress' || evt === 'log') {
        if (data.text) liveLogs.value.push(data.text)
      } else if (evt === 'done') {
        liveLogs.value.push('[done] 扫描完成')
        streamStatus.value = 'done'
        disconnectLiveStream()
        fetchRecent()  // 刷新历史
      } else if (evt === 'error') {
        liveLogs.value.push(`[error] ${data.text || ''}`)
        streamStatus.value = 'error'
        disconnectLiveStream()
      } else if (evt === 'cancelled') {
        liveLogs.value.push('[cancelled] 任务已取消')
        streamStatus.value = 'error'
        disconnectLiveStream()
      } else if (data.text) {
        liveLogs.value.push(data.text)
      }
    } catch {
      liveLogs.value.push(e.data)
    }
  }
  eventSource.onerror = () => {
    if (streamStatus.value === 'running') {
      streamStatus.value = 'error'
    }
    disconnectLiveStream()
  }
}

function disconnectLiveStream() {
  if (eventSource) {
    eventSource.close()
    eventSource = null
  }
}

function logClass(line: string) {
  if (line.includes('[error]') || line.includes('[!]')) return 'log-error'
  if (line.includes('[done]')) return 'log-done'
  if (line.includes('[+]') || line.includes('发现') || line.includes('✓')) return 'log-found'
  return ''
}

// 日志自动滚动到底部
watch(liveLogs.value, async () => {
  await nextTick()
  if (consoleRef.value) consoleRef.value.scrollTop = consoleRef.value.scrollHeight
})

const stats = computed(() => [
  { labelKey: 'dashboard.stats.scans', value: recentScans.value.length, icon: 'DataLine', color: '#165dff', bg: 'rgba(22,93,255,0.08)' },
  { labelKey: 'dashboard.stats.hosts', value: recentScans.value.reduce((s, i) => s + i.host_count, 0), icon: 'Monitor', color: '#00b42a', bg: 'rgba(0,180,42,0.08)' },
  { labelKey: 'dashboard.stats.ports', value: recentScans.value.reduce((s, i) => s + i.port_count, 0), icon: 'Connection', color: '#ff7d00', bg: 'rgba(255,125,0,0.08)' },
  { labelKey: 'dashboard.stats.web', value: recentScans.value.reduce((s, i) => s + i.web_count, 0), icon: 'Globe', color: '#722ed1', bg: 'rgba(114,46,209,0.08)' },
])

function statusType(status: string) {
  if (status === 'done') return 'success'
  if (status === 'error') return 'danger'
  if (status === 'cancelled') return 'info'
  return 'warning'
}

function statusLabel(status: string) {
  if (status === 'done') return t('history.statusDone')
  if (status === 'error') return t('history.statusError')
  if (status === 'running') return t('history.statusRunning')
  if (status === 'cancelled') return t('tasks.cancelled')
  return status
}

function formatElapsed(item: TaskInfo) {
  if (item.started_at) {
    const elapsed = Math.floor((Date.now() - new Date(item.started_at).getTime()) / 1000)
    return `${elapsed}s`
  }
  return '-'
}

async function fetchRunning() {
  try {
    const res = await getTasks()
    runningTasks.value = res.items.filter(t => t.status === 'running')
    // 有运行中任务且当前未在监听 → 自动连接 SSE 实时日志
    if (runningTasks.value.length && !eventSource && streamStatus.value !== 'running') {
      const task = runningTasks.value[0]
      connectLiveStream(task.id, task.name || task.target || '')
    }
    // 没有运行中任务但控制台还在显示 → 清除
    if (!runningTasks.value.length && liveTaskId.value && streamStatus.value !== 'running') {
      setTimeout(() => { liveTaskId.value = '' }, 3000)
    }
  } catch {}
}

async function fetchRecent() {
  try {
    const res = await getHistory({ page: 1, per_page: 5 })
    recentScans.value = res.items
  } catch {}
}

function startPolling() {
  if (pollTimer) return
  pollTimer = setInterval(fetchRunning, 3000)
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

onMounted(async () => {
  loadingTasks.value = true
  loadingRecent.value = true
  await Promise.all([fetchRunning(), fetchRecent()])
  loadingTasks.value = false
  loadingRecent.value = false
  if (runningTasks.value.length) startPolling()
})

onUnmounted(() => {
  stopPolling()
  disconnectLiveStream()
})
</script>

<style scoped>
.dashboard {
  max-width: 1200px;
  margin: 0 auto;
}

/* ── Stats Row ─────────────────────────────────────────── */
.stats-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--np-space-4);
  margin-bottom: var(--np-space-5);
}

.stat-card {
  background: var(--np-bg-surface);
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-lg);
  padding: var(--np-space-4) var(--np-space-5);
  display: flex;
  align-items: center;
  gap: var(--np-space-4);
}

.stat-icon {
  width: 40px;
  height: 40px;
  border-radius: var(--np-radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.stat-info {
  display: flex;
  flex-direction: column;
}

.stat-value {
  font-size: 22px;
  font-weight: 700;
  color: var(--np-text-primary);
  font-family: var(--np-font-mono);
  line-height: 1.2;
}

.stat-label {
  font-size: 12px;
  color: var(--np-text-muted);
  letter-spacing: 0.04em;
}

/* ── Dashboard Grid ────────────────────────────────────── */
.dashboard-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--np-space-5);
  align-items: start;
}

/* ── Running Tasks ─────────────────────────────────────── */
.task-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 0;
  text-decoration: none;
}

.task-item + .task-item {
  border-top: 1px solid var(--np-border);
}

.task-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.task-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--np-text-primary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.task-meta {
  font-size: 11px;
  color: var(--np-text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* ── Recent Items ──────────────────────────────────────── */
.recent-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 0;
  text-decoration: none;
}

.recent-item + .recent-item {
  border-top: 1px solid var(--np-border);
}

.recent-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.recent-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--np-text-primary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.recent-target {
  font-size: 13px;
  color: var(--np-blue-400);
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.recent-meta {
  font-size: 11px;
  color: var(--np-text-muted);
}

.recent-loading {
  padding: var(--np-space-2) 0;
}

.card-footer {
  border-top: 1px solid var(--np-border);
  padding-top: var(--np-space-3);
  margin-top: var(--np-space-2);
  text-align: center;
}

.view-all-link {
  font-size: 13px;
  color: var(--np-blue-400);
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.view-all-link:hover {
  color: var(--np-blue-300);
}

.empty-action {
  margin-top: 8px;
}

/* ═══ Responsive ═════════════════════════════════════════ */
@media (max-width: 768px) {
  .stats-row {
    grid-template-columns: repeat(2, 1fr);
  }

  .dashboard-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 480px) {
  .stats-row {
    grid-template-columns: 1fr;
  }
}

/* ═══ 实时控制台 ═════════════════════════════════════════ */
.console-card {
  margin-top: var(--np-space-5);
}

.console-card .np-card-header {
  justify-content: flex-start;
  gap: var(--np-space-2);
}

.console-task {
  color: var(--np-text-secondary);
  font-size: 12px;
  margin-left: var(--np-space-2);
}

.console-status {
  margin-left: auto;
}

.console-detail-link {
  font-size: 12px;
  color: var(--np-blue-500);
  display: inline-flex;
  align-items: center;
  gap: 2px;
}

.spin {
  animation: np-spin 1.5s linear infinite;
  color: var(--np-blue-500);
}

@keyframes np-spin {
  to { transform: rotate(360deg); }
}

.console-area {
  background: #0d1117;
  color: #7ee787;
  font-family: var(--np-font-mono);
  font-size: 13px;
  padding: var(--np-space-4);
  border-radius: var(--np-radius-lg);
  max-height: 320px;
  overflow-y: auto;
  line-height: 1.7;
  border: 1px solid #1b2330;
}

.console-line {
  display: flex;
  gap: var(--np-space-3);
  white-space: pre-wrap;
  word-break: break-all;
}

.console-prefix {
  color: #484f58;
  flex-shrink: 0;
  user-select: none;
}

.log-error { color: #ff7b72; }
.log-done { color: #79c0ff; font-weight: 600; }
.log-found { color: #ffa657; }

.console-empty {
  color: #6e7681;
}

.cursor-blink {
  animation: blink 1s step-end infinite;
}

@keyframes blink {
  50% { opacity: 0; }
}
</style>
