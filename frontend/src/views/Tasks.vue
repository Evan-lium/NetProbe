<template>
  <div class="tasks-page">
    <!-- Header -->
    <div class="tasks-header">
      <div>
        <h2 class="np-page-title">{{ t('tasks.title') }}</h2>
        <span class="np-page-desc" v-if="total">{{ t('history.scans', { n: total }) }}</span>
      </div>
      <el-button type="primary" @click="showForm = true">
        <el-icon><Plus /></el-icon>
        {{ t('tasks.newScan') }}
      </el-button>
    </div>

    <!-- Task list -->
    <el-card class="task-list-card">
      <!-- Filter bar -->
      <div class="np-filter-bar">
        <el-input v-model="query" :placeholder="t('history.searchPlaceholder')" clearable style="width: 260px" @clear="loadData" @keyup.enter="loadData">
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <el-select v-model="statusFilter" :placeholder="t('tasks.status')" clearable style="width: 120px" @change="loadData">
          <el-option :label="t('history.statusDone')" value="done" />
          <el-option :label="t('history.statusError')" value="error" />
          <el-option :label="t('history.statusRunning')" value="running" />
        </el-select>
        <el-button type="primary" @click="loadData">{{ t('common.search') }}</el-button>
      </div>

      <div v-if="loading && !items.length" class="task-loading">
        <div class="np-skeleton" style="height: 44px; margin-bottom: 8px" />
        <div class="np-skeleton" style="height: 44px; margin-bottom: 8px" />
        <div class="np-skeleton" style="height: 44px" />
      </div>
      <div class="np-table-wrapper" v-else-if="items.length">
        <el-table :data="items" style="width: 100%" row-class-name="task-row">
          <el-table-column :label="t('tasks.name')" min-width="140">
            <template #default="{ row }">
              <span class="task-name">{{ row.name || row.base_domain || row.target_raw }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('tasks.target')" min-width="180">
            <template #default="{ row }">
              <router-link :to="`/tasks/${row.scan_id}`" class="link">
                {{ row.base_domain || row.target_raw }}
              </router-link>
              <div class="row-sub mono" v-if="row.target_raw && row.target_raw !== row.base_domain">{{ row.target_raw }}</div>
            </template>
          </el-table-column>
          <el-table-column prop="status" :label="t('tasks.status')" width="110" align="center">
            <template #default="{ row }">
              <el-tag :type="statusType(row.status)" size="small" effect="dark">
                {{ statusLabel(row.status) }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column :label="t('tasks.hosts')" width="70" align="center">
            <template #default="{ row }"><span class="mono">{{ row.host_count }}</span></template>
          </el-table-column>
          <el-table-column :label="t('tasks.ports')" width="70" align="center">
            <template #default="{ row }"><span class="mono">{{ row.port_count }}</span></template>
          </el-table-column>
          <el-table-column :label="t('tasks.web')" width="70" align="center">
            <template #default="{ row }"><span class="mono">{{ row.web_count }}</span></template>
          </el-table-column>
          <el-table-column :label="t('tasks.duration')" width="100" align="center">
            <template #default="{ row }">
              <span class="mono">{{ formatDuration(row) }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('history.date')" width="170">
            <template #default="{ row }">{{ formatDate(row.started_at) }}</template>
          </el-table-column>
          <el-table-column :label="t('tasks.actions')" width="160" align="center" fixed="right">
            <template #default="{ row }">
              <el-button
                v-if="row.status === 'running'"
                type="warning"
                size="small"
                text
                @click="handleCancel(row)"
              >
                {{ t('tasks.cancel') }}
              </el-button>
              <router-link :to="`/tasks/${row.scan_id}`">
                <el-button type="primary" size="small" text>
                  {{ t('tasks.detail') }}
                </el-button>
              </router-link>
              <el-button
                v-if="row.status !== 'running'"
                type="danger"
                size="small"
                text
                @click="handleDelete(row)"
              >
                {{ t('common.delete') }}
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>
      <div v-else class="np-empty">
        <el-icon :size="36" color="var(--np-text-disabled)"><List /></el-icon>
        <p>{{ t('tasks.noTasks') }}</p>
      </div>

      <!-- Pagination -->
      <div class="pagination" v-if="total > perPage">
        <el-pagination
          v-model:current-page="page"
          :page-size="perPage"
          :total="total"
          layout="prev, pager, next"
          @current-change="loadData"
        />
      </div>
    </el-card>

    <!-- Create scan dialog -->
    <el-dialog v-model="showForm" :title="t('tasks.newScan')" width="680px" destroy-on-close>
      <div class="scan-form">
        <!-- Task name -->
        <div class="form-field">
          <label class="form-label">{{ t('dashboard.taskName') }}</label>
          <el-input v-model="form.taskName" :placeholder="t('dashboard.taskNamePlaceholder')" clearable />
        </div>
        <!-- Targets -->
        <div class="form-field">
          <label class="form-label">{{ t('dashboard.target') }}</label>
          <el-input v-model="form.target" type="textarea" :rows="4" :placeholder="t('dashboard.targetPlaceholder')" />
        </div>
        <!-- Scan mode -->
        <div class="form-field">
          <label class="form-label">{{ t('dashboard.scanMode') }}</label>
          <div class="mode-group">
            <label v-for="m in scanModes" :key="m.value" class="mode-option" :class="{ active: form.scanMode === m.value }">
              <input type="radio" v-model="form.scanMode" :value="m.value" class="sr-only" />
              <span class="mode-name">{{ t(m.labelKey) }}</span>
              <span class="mode-desc">{{ t(m.descKey) }}</span>
            </label>
          </div>
        </div>
        <!-- Port range -->
        <div class="form-field">
          <label class="form-label">{{ t('dashboard.portRange') }}</label>
          <div class="port-group">
            <label v-for="p in portPresets" :key="p.value" class="port-option" :class="{ active: form.portPreset === p.value }">
              <input type="radio" v-model="form.portPreset" :value="p.value" class="sr-only" />
              <span class="port-name">{{ t(p.labelKey) }}</span>
              <span class="port-desc">{{ t(p.descKey) }}</span>
            </label>
          </div>
          <el-input v-if="form.portPreset === 'custom'" v-model="form.customPorts" :placeholder="t('dashboard.customPortsPlaceholder')" class="custom-ports-input" />
        </div>
        <!-- Advanced options -->
        <el-collapse v-model="form.advOpen" class="adv-collapse">
          <el-collapse-item :title="t('dashboard.advancedOptions')" name="adv">
            <div class="adv-grid">
              <div class="adv-field">
                <label class="form-label">{{ t('dashboard.portscanTool') }}</label>
                <el-select v-model="form.portscanTool" size="default" style="width: 100%">
                  <el-option label="auto" value="auto" />
                  <el-option label="nmap" value="nmap" />
                  <el-option label="masscan" value="masscan" />
                  <el-option label="rustscan" value="rustscan" />
                </el-select>
              </div>
              <div class="adv-field">
                <label class="form-label">{{ t('dashboard.subdomainTool') }}</label>
                <el-select v-model="form.subdomainTool" size="default" style="width: 100%">
                  <el-option label="auto" value="auto" />
                  <el-option label="subfinder" value="subfinder" />
                  <el-option label="dns_brute" value="dns_brute" />
                </el-select>
              </div>
              <div class="adv-field">
                <label class="form-label">{{ t('dashboard.webTool') }}</label>
                <el-select v-model="form.webTool" size="default" style="width: 100%">
                  <el-option label="auto" value="auto" />
                  <el-option label="httpx" value="httpx" />
                  <el-option label="curl" value="curl" />
                </el-select>
              </div>
              <div class="adv-field">
                <label class="form-label">{{ t('dashboard.timeout') }}</label>
                <el-input-number v-model="form.timeout" :min="30" :max="3600" :step="30" style="width: 100%" />
              </div>
            </div>
          </el-collapse-item>
        </el-collapse>
      </div>
      <template #footer>
        <el-button @click="showForm = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="submitting" @click="handleScan">
          {{ t('dashboard.startBtn') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, reactive } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { startScan, getHistory, cancelTask, deleteHistory } from '../api/scan'
import type { HistoryItem, ScanRequest } from '../types'

const { t } = useI18n()

// List
const items = ref<HistoryItem[]>([])
const total = ref(0)
const page = ref(1)
const perPage = 20
const loading = ref(true)
const query = ref('')
const statusFilter = ref('')
let pollTimer: ReturnType<typeof setInterval> | null = null

// Form
const showForm = ref(false)
const submitting = ref(false)
const form = reactive({
  taskName: defaultTaskName(),
  target: '',
  scanMode: 'normal',
  portPreset: 'common',
  customPorts: '',
  portscanTool: 'auto',
  subdomainTool: 'auto',
  webTool: 'auto',
  timeout: 300,
  advOpen: [] as string[],
})

const scanModes = [
  { value: 'quick', labelKey: 'dashboard.modeQuick', descKey: 'dashboard.modeQuickDesc' },
  { value: 'normal', labelKey: 'dashboard.modeNormal', descKey: 'dashboard.modeNormalDesc' },
  { value: 'deep', labelKey: 'dashboard.modeDeep', descKey: 'dashboard.modeDeepDesc' },
]

const portPresets = [
  { value: 'common', labelKey: 'dashboard.portCommon', descKey: 'dashboard.portCommonDesc' },
  { value: 'top1000', labelKey: 'dashboard.portTop1000', descKey: 'dashboard.portTop1000Desc' },
  { value: 'all', labelKey: 'dashboard.portAll', descKey: 'dashboard.portAllDesc' },
  { value: 'custom', labelKey: 'dashboard.portCustom', descKey: 'dashboard.portCustomDesc' },
]

function defaultTaskName() {
  const now = new Date()
  const ts = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}${String(now.getSeconds()).padStart(2, '0')}`
  return `资产扫描_${ts}`
}

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

function formatDuration(row: HistoryItem) {
  if (row.status === 'running' && row.started_at) {
    const elapsed = Math.floor((Date.now() - new Date(row.started_at).getTime()) / 1000)
    return `${elapsed}s`
  }
  if (row.duration_secs != null) return `${row.duration_secs}s`
  return '-'
}

function formatDate(d: string) {
  if (!d) return '-'
  return new Date(d).toLocaleString('zh-CN')
}

async function loadData() {
  loading.value = true
  try {
    const res = await getHistory({ page: page.value, per_page: perPage, q: query.value, status: statusFilter.value })
    items.value = res.items
    total.value = res.total
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

function startPolling() {
  if (pollTimer) return
  pollTimer = setInterval(() => {
    // Only poll if there are running tasks
    const hasRunning = items.value.some(i => i.status === 'running')
    if (hasRunning) loadData()
    else stopPolling()
  }, 3000)
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

async function handleScan() {
  if (!form.target.trim()) {
    ElMessage.warning(t('dashboard.pleaseTarget'))
    return
  }
  submitting.value = true
  try {
    const opts: ScanRequest = {
      target: form.target.trim(),
      name: form.taskName.trim() || defaultTaskName(),
      port_preset: form.portPreset,
      timeout: form.timeout,
    }
    if (form.scanMode === 'quick') {
      opts.portscan_tool = 'masscan'
      opts.no_dns_brute = true
      opts.no_web = true
      opts.timeout = 120
    } else if (form.scanMode === 'deep') {
      opts.portscan_tool = 'nmap'
      opts.timeout = 900
    }
    if (form.portscanTool !== 'auto') opts.portscan_tool = form.portscanTool
    if (form.subdomainTool !== 'auto') opts.subdomain_tool = form.subdomainTool
    if (form.webTool !== 'auto') opts.web_tool = form.webTool
    if (form.portPreset === 'custom') {
      if (!form.customPorts.trim()) {
        ElMessage.warning(t('dashboard.customPortsPlaceholder'))
        return
      }
      opts.custom_ports = form.customPorts.trim()
    }

    await startScan(opts)
    showForm.value = false
    ElMessage.success(t('dashboard.scanning'))
    // Reset form
    form.taskName = defaultTaskName()
    form.target = ''
    // Refresh
    await loadData()
    startPolling()
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    submitting.value = false
  }
}

async function handleCancel(row: HistoryItem) {
  try {
    await ElMessageBox.confirm(t('tasks.cancelConfirm'), { type: 'warning' })
    // Cancel via scan_id (backend handles it)
    await cancelTask(row.scan_id)
    ElMessage.success(t('tasks.cancelled'))
    await loadData()
  } catch {}
}

async function handleDelete(row: HistoryItem) {
  try {
    await ElMessageBox.confirm(t('history.deleteConfirm'), { type: 'warning' })
    await deleteHistory(row.scan_id)
    ElMessage.success(t('history.deleted'))
    await loadData()
  } catch {}
}

onMounted(async () => {
  await loadData()
  if (items.value.some(i => i.status === 'running')) startPolling()
})

onUnmounted(() => {
  stopPolling()
})
</script>

<style scoped>
.tasks-page {
  max-width: 1400px;
  margin: 0 auto;
}

.tasks-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--np-space-5);
}

.np-page-title {
  font-size: 20px;
  font-weight: 600;
  color: var(--np-text-primary);
  margin: 0;
}

.np-page-desc {
  font-size: 13px;
  color: var(--np-text-muted);
  margin-left: 8px;
}

.task-list-card {
  min-height: 200px;
}

.np-filter-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: var(--np-space-4);
}

.task-loading {
  padding: var(--np-space-3) 0;
}

.task-name {
  font-weight: 500;
  color: var(--np-text-primary);
}

.link {
  color: var(--np-blue-400);
  font-weight: 500;
  text-decoration: none;
  transition: color var(--np-transition);
}

.link:hover {
  color: var(--np-blue-500);
}

.row-sub {
  font-size: 11px;
  color: var(--np-text-muted);
  margin-top: 2px;
  max-width: 400px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.pagination {
  margin-top: var(--np-space-4);
  display: flex;
  justify-content: flex-end;
}

/* ── Scan form (dialog) ──────────────────────────────── */
.form-field {
  margin-bottom: var(--np-space-4);
}

.form-label {
  display: block;
  font-size: 13px;
  font-weight: 500;
  color: var(--np-text-secondary);
  margin-bottom: 6px;
}

.mode-group {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
}

.mode-option {
  display: flex;
  flex-direction: column;
  padding: 10px 12px;
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-md);
  cursor: pointer;
  transition: all var(--np-transition);
}

.mode-option:hover { border-color: var(--np-blue-500); }
.mode-option.active {
  border-color: var(--np-blue-500);
  background: rgba(96, 165, 250, 0.08);
}

.mode-name { font-size: 13px; font-weight: 600; color: var(--np-text-primary); }
.mode-desc { font-size: 11px; color: var(--np-text-muted); margin-top: 2px; line-height: 1.4; }

.port-group {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
}

.port-option {
  display: flex;
  flex-direction: column;
  padding: 10px 12px;
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-md);
  cursor: pointer;
  transition: all var(--np-transition);
}

.port-option:hover { border-color: var(--np-blue-500); }
.port-option.active {
  border-color: var(--np-blue-500);
  background: rgba(96, 165, 250, 0.08);
}

.port-name { font-size: 13px; font-weight: 600; color: var(--np-text-primary); }
.port-desc { font-size: 11px; color: var(--np-text-muted); margin-top: 2px; line-height: 1.4; }

.custom-ports-input { margin-top: 8px; }

.adv-collapse { margin-bottom: var(--np-space-2); }
.adv-collapse :deep(.el-collapse-item__header) {
  font-size: 13px; color: var(--np-text-secondary); height: 36px; line-height: 36px;
  border-bottom-color: var(--np-border);
}
.adv-collapse :deep(.el-collapse-item__wrap) { border-bottom-color: var(--np-border); }
.adv-collapse :deep(.el-collapse-item__content) { padding: 12px 0 4px; }

.adv-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.adv-field .form-label { font-size: 12px; margin-bottom: 4px; }

/* ── SR only ─────────────────────────────────────────── */
.sr-only {
  position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
  overflow: hidden; clip: rect(0, 0, 0, 0); border: 0;
}

/* ═══ Responsive ═══════════════════════════════════════ */
@media (max-width: 768px) {
  .mode-group { grid-template-columns: 1fr; }
  .port-group { grid-template-columns: repeat(2, 1fr); }
  .adv-grid { grid-template-columns: 1fr; }
}

@media (max-width: 480px) {
  .port-group { grid-template-columns: 1fr; }
}
</style>
