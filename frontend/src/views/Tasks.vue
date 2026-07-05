<template>
  <div class="tasks-page">
    <!-- Header -->
    <div class="np-page-header">
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
        <el-button
          type="warning"
          :disabled="!canCompare"
          @click="goCompare"
        >
          <el-icon><DataAnalysis /></el-icon>
          {{ t('diff.compare') }}
        </el-button>
      </div>

      <div v-if="loading && !items.length" class="task-loading">
        <div class="np-skeleton" style="height: 44px; margin-bottom: 8px" />
        <div class="np-skeleton" style="height: 44px; margin-bottom: 8px" />
        <div class="np-skeleton" style="height: 44px" />
      </div>
      <div class="np-table-wrapper" v-else-if="items.length">
        <el-table :data="items" style="width: 100%" row-class-name="task-row" @selection-change="onSelectionChange">
          <el-table-column type="selection" width="42" :selectable="canSelectRow" />
          <el-table-column :label="t('tasks.name')" min-width="140">
            <template #default="{ row }">
              <span class="task-name">{{ row.name || row.base_domain || row.target_raw }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('tasks.mode')" width="90" align="center">
            <template #default="{ row }">
              <el-tag :type="modeTagType(row.scan_mode)" size="small" effect="plain">
                {{ modeLabel(row.scan_mode) }}
              </el-tag>
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
      <div class="pagination" v-if="total > 0">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="perPage"
          :total="total"
          :page-sizes="[5, 10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next, jumper"
         
          background
          @current-change="loadData"
          @size-change="onSizeChange"
        />
      </div>
    </el-card>

    <!-- Create scan dialog -->
    <el-dialog v-model="showForm" :title="t('tasks.newScan')" width="680px" destroy-on-close>
      <div class="scan-form np-form">
        <!-- Task name -->
        <div class="np-form-row">
          <label class="np-form-label">{{ t('dashboard.taskName') }}</label>
          <el-input v-model="form.taskName" :placeholder="t('dashboard.taskNamePlaceholder')" clearable />
        </div>
        <!-- Targets -->
        <div class="np-form-row">
          <label class="np-form-label">{{ t('dashboard.target') }}</label>
          <el-input v-model="form.target" type="textarea" :rows="4" :placeholder="t('dashboard.targetPlaceholder')" />
        </div>
        <!-- 扫描引擎选择器（替代旧的 scanMode，更灵活） -->
        <div class="np-form-row">
          <label class="np-form-label">扫描引擎</label>
          <div class="engine-group">
            <label
              v-for="e in engines"
              :key="e.id"
              class="engine-option"
              :class="{ active: form.engineId === e.id }"
            >
              <input type="radio" v-model="form.engineId" :value="e.id" class="sr-only" @change="onEngineChange" />
              <span class="engine-name">
                {{ e.name }}
                <el-tag v-if="e.is_preset" size="small" type="info" effect="plain">预设</el-tag>
              </span>
              <span class="engine-desc">{{ e.description }}</span>
            </label>
          </div>
        </div>
        <!-- Scan mode（保留向后兼容，引擎未指定时用模式） -->
        <div class="np-form-row" v-if="!form.engineId">
          <label class="np-form-label">{{ t('dashboard.scanMode') }}</label>
          <div class="mode-group">
            <label v-for="m in scanModes" :key="m.value" class="mode-option" :class="{ active: form.scanMode === m.value }">
              <input type="radio" v-model="form.scanMode" :value="m.value" class="sr-only" @change="onModeChange" />
              <span class="mode-name">{{ t(m.labelKey) }}</span>
              <span class="mode-desc">{{ t(m.descKey) }}</span>
            </label>
          </div>
        </div>
        <!-- 检测项勾选（可选增强项，可覆盖引擎默认） -->
        <div class="np-form-row">
          <label class="np-form-label">
            检测项
            <span class="np-form-hint">勾选要执行的检测（可覆盖引擎默认）</span>
          </label>
          <div class="stages-group">
            <!-- 基础项（始终启用，灰显不可取消） -->
            <div class="stage-item base">
              <el-checkbox v-model="stages.subdomain" disabled>子域名枚举</el-checkbox>
            </div>
            <div class="stage-item base">
              <el-checkbox v-model="stages.port" disabled>端口扫描</el-checkbox>
            </div>
            <div class="stage-item base">
              <el-checkbox v-model="stages.web" disabled>Web 探测</el-checkbox>
            </div>
            <!-- 可选增强项 -->
            <div class="stage-item"><el-checkbox v-model="stages.fingerprint">指纹识别</el-checkbox></div>
            <div class="stage-item"><el-checkbox v-model="stages.sensitive">敏感路径</el-checkbox></div>
            <div class="stage-item warn"><el-checkbox v-model="stages.dirBrute">目录爆破</el-checkbox></div>
            <div class="stage-item warn"><el-checkbox v-model="stages.takeover">接管检测</el-checkbox></div>
            <div class="stage-item"><el-checkbox v-model="stages.js">JS 分析</el-checkbox></div>
            <div class="stage-item warn"><el-checkbox v-model="stages.vuln">漏洞扫描</el-checkbox></div>
            <div class="stage-item"><el-checkbox v-model="stages.banner">Banner 抓取</el-checkbox></div>
            <div class="stage-item"><el-checkbox v-model="stages.screenshot">截图</el-checkbox></div>
          </div>
        </div>
        <!-- Port range -->
        <div class="np-form-row">
          <label class="np-form-label">{{ t('dashboard.portRange') }}</label>
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
                <label class="np-form-label">{{ t('dashboard.portscanTool') }}</label>
                <el-select v-model="form.portscanTool" size="default" style="width: 100%">
                  <el-option label="auto" value="auto" />
                  <el-option label="nmap" value="nmap" />
                  <el-option label="masscan" value="masscan" />
                  <el-option label="rustscan" value="rustscan" />
                </el-select>
              </div>
              <div class="adv-field">
                <label class="np-form-label">{{ t('dashboard.subdomainTool') }}</label>
                <el-select v-model="form.subdomainTool" size="default" style="width: 100%">
                  <el-option label="auto" value="auto" />
                  <el-option label="subfinder" value="subfinder" />
                  <el-option label="dns_brute" value="dns_brute" />
                </el-select>
              </div>
              <div class="adv-field">
                <label class="np-form-label">{{ t('dashboard.webTool') }}</label>
                <el-select v-model="form.webTool" size="default" style="width: 100%">
                  <el-option label="auto" value="auto" />
                  <el-option label="httpx" value="httpx" />
                  <el-option label="curl" value="curl" />
                </el-select>
              </div>
              <div class="adv-field">
                <label class="np-form-label">{{ t('dashboard.timeout') }}</label>
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
import { ref, onMounted, onUnmounted, reactive, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { startScan, getHistory, cancelTask, deleteHistory } from '../api/scan'
import api from '../api/index'
import { usePageSize } from '../composables/usePageSetting'
import type { HistoryItem, ScanRequest } from '../types'

const { t } = useI18n()
const router = useRouter()

// List
const items = ref<HistoryItem[]>([])
const total = ref(0)
const page = ref(1)
const perPage = usePageSize('tasks')
function onSizeChange() { page.value = 1; loadData() }
const loading = ref(true)
const query = ref('')
const statusFilter = ref('')
let pollTimer: ReturnType<typeof setInterval> | null = null

// 多选对比 Diff
const selected = ref<HistoryItem[]>([])
function canSelectRow(row: HistoryItem) {
  return row.status === 'done'
}
function onSelectionChange(rows: HistoryItem[]) {
  selected.value = rows
}
const canCompare = computed(() => selected.value.length === 2)
function goCompare() {
  if (!canCompare.value) return
  const [a, b] = selected.value
  router.push({ path: '/diff', query: { a: a.scan_id, b: b.scan_id } })
}

// Form
const showForm = ref(false)
const submitting = ref(false)
const engines = ref<any[]>([])
const form = reactive({
  taskName: defaultTaskName(),
  target: '',
  scanMode: 'normal',
  engineId: null as number | null,  // 扫描引擎 ID（null=用旧版 scanMode）
  portPreset: 'common',
  customPorts: '',
  portscanTool: 'auto',
  subdomainTool: 'auto',
  webTool: 'auto',
  timeout: 300,
  screenshot: false,
  advOpen: [] as string[],
})

/** 检测项勾选（可选增强项可手动改，选引擎时联动） */
const stages = reactive({
  subdomain: true,   // 基础项（始终启用）
  port: true,
  web: true,
  fingerprint: true,
  sensitive: true,
  dirBrute: false,   // 耗时噪音项，默认关
  takeover: true,
  js: true,
  vuln: false,       // nuclei 较慢，默认关（深度引擎才开）
  banner: true,
  screenshot: false,
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

function modeTagType(mode: string) {
  if (mode === 'quick') return 'info'
  if (mode === 'deep') return 'danger'
  return 'success'
}

function modeLabel(mode: string) {
  if (mode === 'quick') return t('dashboard.modeQuick')
  if (mode === 'deep') return t('dashboard.modeDeep')
  return t('dashboard.modeNormal')
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
    // 超过 1 小时的 running 视为僵尸，不显示天文数字
    if (elapsed > 3600) return t('tasks.timeout')
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
    const res = await getHistory({ page: page.value, per_page: perPage.value, q: query.value, status: statusFilter.value })
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
      screenshot: form.screenshot,
      scan_mode: form.scanMode,
    } as any
    // 选了扫描引擎：传 engine_id，引擎 config 在后端覆盖阶段/工具/参数
    if (form.engineId) {
      (opts as any).engine_id = form.engineId
      // 用户勾选覆盖引擎默认 stages（勾选框优先级 > 引擎 config）
      ;(opts as any).stages = {
        subdomain: stages.subdomain,
        port: stages.port,
        web: stages.web,
        fingerprint: stages.fingerprint,
        sensitive: stages.sensitive,
        takeover: stages.takeover,
        js: stages.js,
        vuln: stages.vuln,
        banner: stages.banner,
        screenshot: stages.screenshot,
      }
    } else {
      // 未选引擎：用旧版模式逻辑
      if (form.scanMode === 'quick') {
        opts.portscan_tool = 'masscan'
        opts.no_dns_brute = true
        opts.no_web = true
        opts.timeout = 120
      } else if (form.scanMode === 'deep') {
        opts.portscan_tool = 'nmap'
        opts.timeout = 900
      }
      // 旧模式也传 stages（勾选框）
      ;(opts as any).stages = {
        subdomain: stages.subdomain,
        port: stages.port,
        web: stages.web,
        fingerprint: stages.fingerprint,
        sensitive: stages.sensitive,
        takeover: stages.takeover,
        js: stages.js,
        vuln: stages.vuln,
        banner: stages.banner,
        screenshot: stages.screenshot,
      }
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

/** 加载扫描引擎列表（预设 + 自定义） */
async function loadEngines() {
  try {
    const res: any = await api.get('/scan-engines')
    engines.value = res.items || []
    // 默认选中「标准」预设引擎，并联动设置勾选项
    if (!form.engineId && engines.value.length) {
      const standard = engines.value.find(e => e.name === '标准')
      form.engineId = standard ? standard.id : engines.value[0].id
      applyEngineStages(form.engineId)
    }
  } catch {
    /* 引擎加载失败不阻塞，回退到旧版 scanMode */
  }
}

/** 引擎切换时联动勾选项：从引擎 config 的 stages 读取默认勾选 */
function onEngineChange() {
  applyEngineStages(form.engineId)
}

/** 扫描模式切换时联动勾选项（引擎未选时生效） */
function onModeChange() {
  if (form.engineId) return  // 选了引擎时模式不生效
  if (form.scanMode === 'quick') {
    // 快速：只跑子域名+端口+Banner，跳过所有 Web 增强
    stages.fingerprint = false
    stages.sensitive = false
    stages.dirBrute = false
    stages.takeover = false
    stages.js = false
    stages.vuln = false
    stages.banner = true
    stages.screenshot = false
  } else if (form.scanMode === 'deep') {
    // 深度：全量 + 漏洞 + 目录爆破 + 截图
    stages.fingerprint = true
    stages.sensitive = true
    stages.dirBrute = true
    stages.takeover = true
    stages.js = true
    stages.vuln = true
    stages.banner = true
    stages.screenshot = true
  } else {
    // 标准：默认增强项，跳过耗时项
    stages.fingerprint = true
    stages.sensitive = true
    stages.dirBrute = false
    stages.takeover = true
    stages.js = true
    stages.vuln = false
    stages.banner = true
    stages.screenshot = false
  }
}

/** 把引擎 config 的 stages 映射到勾选框 */
function applyEngineStages(engineId: number | null) {
  if (!engineId) return
  const engine = engines.value.find(e => e.id === engineId)
  if (!engine?.config?.stages) return
  const s = engine.config.stages
  stages.fingerprint = s.fingerprint !== false
  stages.sensitive = s.sensitive !== false
  stages.dirBrute = s.dirBrute === true
  stages.takeover = s.takeover !== false
  stages.js = s.js !== false
  stages.vuln = s.vuln === true
  stages.banner = s.banner !== false
  stages.screenshot = s.screenshot === true
}

onMounted(async () => {
  await Promise.all([loadData(), loadEngines()])
  if (items.value.some(i => i.status === 'running')) startPolling()
})

onUnmounted(() => {
  stopPolling()
})
</script>

<style scoped>
.tasks-page {
  
  
}

.task-list-card {
  min-height: 200px;
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

/* 扫描引擎选项（复用 mode 风格，3列网格） */
.engine-group {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
}
.engine-option {
  display: flex;
  flex-direction: column;
  padding: 10px 12px;
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-md);
  cursor: pointer;
  transition: all var(--np-transition);
}
.engine-option:hover { border-color: var(--np-blue-500); }
.engine-option.active {
  border-color: var(--np-blue-500);
  background: rgba(96, 165, 250, 0.08);
}
.engine-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--np-text-primary);
  display: flex;
  align-items: center;
  gap: 6px;
}
.engine-desc { font-size: 11px; color: var(--np-text-muted); margin-top: 2px; line-height: 1.4; }

/* 检测项勾选区 */
.stages-group {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px 12px;
  padding: 12px;
  background: var(--np-bg-elevated);
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-md);
}
.stage-item {
  display: flex;
  align-items: center;
}
.stage-item.base :deep(.el-checkbox__label) {
  color: var(--np-text-disabled);
}
.stage-item.base :deep(.el-checkbox.is-disabled .el-checkbox__inner) {
  background-color: var(--np-blue-500);
  border-color: var(--np-blue-500);
}
.stage-item.base :deep(.el-checkbox.is-disabled.is-checked .el-checkbox__inner::after) {
  border-color: #fff;
}
/* 警示项（目录爆破/漏洞扫描，耗时长，标签标橙） */
.stage-item.warn :deep(.el-checkbox__label) {
  color: var(--np-text-secondary);
}
.stage-item.warn :deep(.el-checkbox__input.is-checked .el-checkbox__inner) {
  background-color: var(--np-warning);
  border-color: var(--np-warning);
}

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

.adv-field .np-form-label { font-size: 12px; margin-bottom: var(--np-space-1); }

/* ── SR only ─────────────────────────────────────────── */
.sr-only {
  position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
  overflow: hidden; clip: rect(0, 0, 0, 0); border: 0;
}

/* ═══ Responsive ═══════════════════════════════════════ */
@media (max-width: 768px) {
  .mode-group { grid-template-columns: 1fr; }
  .engine-group { grid-template-columns: 1fr; }
  .stages-group { grid-template-columns: repeat(2, 1fr); }
  .port-group { grid-template-columns: repeat(2, 1fr); }
  .adv-grid { grid-template-columns: 1fr; }
}

@media (max-width: 480px) {
  .port-group { grid-template-columns: 1fr; }
}
</style>
