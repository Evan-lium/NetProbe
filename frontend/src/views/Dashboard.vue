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
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { getTasks, getHistory } from '../api/scan'
import type { TaskInfo, HistoryItem } from '../types'

const { t } = useI18n()

const loadingTasks = ref(true)
const loadingRecent = ref(true)
const runningTasks = ref<TaskInfo[]>([])
const recentScans = ref<HistoryItem[]>([])
let pollTimer: ReturnType<typeof setInterval> | null = null

const stats = computed(() => [
  { labelKey: 'dashboard.stats.scans', value: recentScans.value.length, icon: 'DataLine', color: '#60a5fa', bg: 'rgba(96,165,250,0.1)' },
  { labelKey: 'dashboard.stats.hosts', value: recentScans.value.reduce((s, i) => s + i.host_count, 0), icon: 'Monitor', color: '#22c55e', bg: 'rgba(34,197,94,0.1)' },
  { labelKey: 'dashboard.stats.ports', value: recentScans.value.reduce((s, i) => s + i.port_count, 0), icon: 'Connection', color: '#f97316', bg: 'rgba(249,115,22,0.1)' },
  { labelKey: 'dashboard.stats.web', value: recentScans.value.reduce((s, i) => s + i.web_count, 0), icon: 'Globe', color: '#a78bfa', bg: 'rgba(167,139,250,0.1)' },
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
</style>
