<template>
  <div class="schedules-page">
    <!-- Header -->
    <div class="np-page-header">
      <div>
        <h2 class="np-page-title">{{ t('schedules.title') }}</h2>
        <span class="np-page-desc">{{ t('schedules.desc') }}</span>
      </div>
      <el-button type="primary" @click="openCreate">
        <el-icon><Plus /></el-icon>
        {{ t('schedules.newSchedule') }}
      </el-button>
    </div>

    <!-- Schedule list -->
    <el-card class="task-list-card">
      <div v-if="loading && !items.length" class="task-loading">
        <div class="np-skeleton" style="height: 44px; margin-bottom: 8px" />
        <div class="np-skeleton" style="height: 44px; margin-bottom: 8px" />
        <div class="np-skeleton" style="height: 44px" />
      </div>
      <div class="np-table-wrapper" v-else-if="items.length">
        <el-table :data="pagedItems" style="width: 100%">
          <el-table-column :label="t('schedules.name')" min-width="140" show-overflow-tooltip>
            <template #default="{ row }">
              <strong>{{ row.name || '—' }}</strong>
            </template>
          </el-table-column>
          <el-table-column prop="target_raw" :label="t('schedules.target')" min-width="160" show-overflow-tooltip />
          <el-table-column :label="t('schedules.cronExpr')" min-width="130" show-overflow-tooltip>
            <template #default="{ row }">
              <code class="cron-code">{{ row.cron_expr }}</code>
            </template>
          </el-table-column>
          <el-table-column :label="t('schedules.enabled')" width="100" align="center">
            <template #default="{ row }">
              <el-switch :model-value="row.enabled" @change="(v: boolean) => handleToggle(row, v)" />
            </template>
          </el-table-column>
          <el-table-column :label="t('schedules.lastRun')" width="170">
            <template #default="{ row }">{{ formatTime(row.last_run_at) }}</template>
          </el-table-column>
          <el-table-column :label="t('schedules.nextRun')" width="170">
            <template #default="{ row }">{{ formatTime(row.next_run_at) }}</template>
          </el-table-column>
          <el-table-column :label="t('schedules.actions')" width="220" fixed="right">
            <template #default="{ row }">
              <el-button size="small" link @click="handleRunNow(row)">
                <el-icon><VideoPlay /></el-icon> {{ t('schedules.runNow') }}
              </el-button>
              <el-button size="small" link @click="openEdit(row)">
                <el-icon><Edit /></el-icon> {{ t('schedules.edit') }}
              </el-button>
              <el-button size="small" link type="danger" @click="handleDelete(row)">
                <el-icon><Delete /></el-icon>
              </el-button>
            </template>
          </el-table-column>
        </el-table>
        <div class="np-pagination" v-if="items.length">
          <el-pagination v-model:current-page="page" v-model:page-size="perPage"
            :total="items.length" :page-sizes="[5, 10, 20, 50, 100]"
            layout="total, sizes, prev, pager, next, jumper" background />
        </div>
      </div>
      <el-empty v-else :description="t('schedules.noSchedules')" />
    </el-card>

    <!-- Create / Edit dialog -->
    <el-dialog v-model="showForm" :title="editing ? t('schedules.edit') : t('schedules.newSchedule')" width="620px" @close="resetForm">
      <div class="schedule-form np-form">
        <!-- Cron -->
        <div class="np-form-row">
          <label class="np-form-label">{{ t('schedules.cronExpr') }}</label>
          <el-input v-model="form.cron_expr" :placeholder="t('schedules.cronPlaceholder')">
            <template #append>
              <el-select v-model="cronPreset" :placeholder="t('schedules.cronPresets')" style="width: 150px" @change="applyPreset">
                <el-option :label="t('schedules.presetDaily2')" value="0 2 * * *" />
                <el-option :label="t('schedules.presetDaily6')" value="0 6 * * *" />
                <el-option :label="t('schedules.presetWeekly')" value="0 0 * * 1" />
                <el-option :label="t('schedules.preset6h')" value="0 */6 * * *" />
              </el-select>
            </template>
          </el-input>
        </div>

        <!-- Name -->
        <div class="np-form-row">
          <label class="np-form-label">{{ t('schedules.name') }}</label>
          <el-input v-model="form.name" :placeholder="t('dashboard.taskNamePlaceholder')" />
        </div>

        <!-- Target -->
        <div class="np-form-row">
          <label class="np-form-label">{{ t('schedules.target') }}</label>
          <el-input v-model="form.target" type="textarea" :rows="2" :placeholder="t('dashboard.targetPlaceholder')" />
        </div>

        <!-- 扫描引擎（和新建任务一致） -->
        <div class="np-form-row">
          <label class="np-form-label">扫描引擎</label>
          <div class="engine-group">
            <label v-for="e in engines" :key="e.id" class="engine-option" :class="{ active: form.engineId === e.id }">
              <input type="radio" v-model="form.engineId" :value="e.id" class="sr-only" @change="onEngineChange" />
              <span class="engine-name">{{ e.name }}<el-tag v-if="e.is_preset" size="small" type="info" effect="plain">预设</el-tag></span>
              <span class="engine-desc">{{ e.description }}</span>
            </label>
          </div>
        </div>

        <!-- 检测项勾选（和新建任务一致） -->
        <div class="np-form-row">
          <label class="np-form-label">
            检测项
            <span class="np-form-hint">勾选要执行的检测</span>
          </label>
          <div class="stages-group">
            <div class="stage-item base"><el-checkbox v-model="stages.subdomain" disabled>子域名枚举</el-checkbox></div>
            <div class="stage-item base"><el-checkbox v-model="stages.port" disabled>端口扫描</el-checkbox></div>
            <div class="stage-item base"><el-checkbox v-model="stages.web" disabled>Web 探测</el-checkbox></div>
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
          <div class="mode-cards">
            <div v-for="p in portPresets" :key="p.value" class="mode-card port-card" :class="{ active: form.portPreset === p.value }" @click="form.portPreset = p.value">
              <div class="mode-card-title">{{ t(p.labelKey) }}</div>
              <div class="mode-card-desc">{{ t(p.descKey) }}</div>
            </div>
          </div>
          <el-input v-if="form.portPreset === 'custom'" v-model="form.customPorts" :placeholder="t('dashboard.customPortsPlaceholder')" style="margin-top: 8px" />
        </div>

        <!-- Enabled -->
        <div class="np-form-row">
          <label class="np-form-label">{{ t('schedules.enabled') }}</label>
          <el-switch v-model="form.enabled" />
        </div>
      </div>

      <template #footer>
        <el-button @click="showForm = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="submitting" @click="handleSubmit">{{ t('common.confirm') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  getSchedules, createSchedule, updateSchedule,
  deleteSchedule, toggleSchedule, runScheduleNow,
} from '../api/scan'
import api from '../api/index'
import type { ScheduleTask } from '../types'
import { usePageSize } from '../composables/usePageSetting'

const { t } = useI18n()

const items = ref<ScheduleTask[]>([])
const page = ref(1)
const perPage = usePageSize('schedules')
const pagedItems = computed(() => {
  const s = (page.value - 1) * perPage.value
  return items.value.slice(s, s + perPage.value)
})
const loading = ref(true)
const showForm = ref(false)
const submitting = ref(false)
const editing = ref<ScheduleTask | null>(null)
const cronPreset = ref('')

const portPresets = [
  { value: 'common', labelKey: 'dashboard.portCommon', descKey: 'dashboard.portCommonDesc' },
  { value: 'top1000', labelKey: 'dashboard.portTop1000', descKey: 'dashboard.portTop1000Desc' },
  { value: 'all', labelKey: 'dashboard.portAll', descKey: 'dashboard.portAllDesc' },
  { value: 'custom', labelKey: 'dashboard.portCustom', descKey: 'dashboard.portCustomDesc' },
]

const form = reactive({
  cron_expr: '0 2 * * *',
  name: '',
  target: '',
  engineId: null as number | null,
  scanMode: 'normal',
  portPreset: 'common',
  customPorts: '',
  portscanTool: 'auto',
  subdomainTool: 'auto',
  webTool: 'auto',
  timeout: 300,
  enabled: true,
})

/** 引擎列表 + 检测项勾选（和新建任务一致） */
const engines = ref<any[]>([])
const stages = reactive({
  subdomain: true, port: true, web: true, fingerprint: true,
  sensitive: true, dirBrute: false, takeover: true, js: true,
  vuln: false, banner: true, screenshot: false,
})

function onEngineChange() {
  const engine = engines.value.find(e => e.id === form.engineId)
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

async function loadEngines() {
  try {
    const res: any = await api.get('/scan-engines')
    engines.value = res.items || []
    if (!form.engineId && engines.value.length) {
      const std = engines.value.find(e => e.name === '标准')
      form.engineId = std ? std.id : engines.value[0].id
      onEngineChange()
    }
  } catch { /* 不阻塞 */ }
}

function defaultForm() {
  return {
    cron_expr: '0 2 * * *',
    name: '',
    target: '',
    scanMode: 'normal',
    portPreset: 'common',
    customPorts: '',
    portscanTool: 'auto',
    subdomainTool: 'auto',
    webTool: 'auto',
    timeout: 300,
    enabled: true,
  }
}

function applyPreset(val: string) {
  if (val) form.cron_expr = val
}

/** 把 form 组装成后端 options（和新建任务一致：传 engine_id + stages）。 */
function buildOptions() {
  const opts: Record<string, any> = {
    port_preset: form.portPreset,
    timeout: form.timeout,
  }
  if (form.engineId) {
    opts.engine_id = form.engineId
    opts.stages = {
      subdomain: stages.subdomain, port: stages.port, web: stages.web,
      fingerprint: stages.fingerprint, sensitive: stages.sensitive,
      takeover: stages.takeover, js: stages.js, vuln: stages.vuln,
      banner: stages.banner, screenshot: stages.screenshot,
    }
  } else {
    if (form.scanMode === 'quick') {
      opts.portscan_tool = 'masscan'
      opts.no_dns_brute = true
      opts.no_web = true
      opts.timeout = 120
    } else if (form.scanMode === 'deep') {
      opts.portscan_tool = 'nmap'
      opts.timeout = 900
    }
  }
  if (form.portscanTool !== 'auto') opts.portscan_tool = form.portscanTool
  if (form.subdomainTool !== 'auto') opts.subdomain_tool = form.subdomainTool
  if (form.webTool !== 'auto') opts.web_tool = form.webTool
  if (form.portPreset === 'custom' && form.customPorts.trim()) {
    opts.custom_ports = form.customPorts.trim()
  }
  return opts
}

function resetForm() {
  Object.assign(form, defaultForm())
  editing.value = null
  cronPreset.value = ''
}

function openCreate() {
  resetForm()
  showForm.value = true
}

function openEdit(row: ScheduleTask) {
  editing.value = row
  Object.assign(form, {
    cron_expr: row.cron_expr,
    name: row.name,
    target: row.target_raw,
    scanMode: 'normal',
    portPreset: row.options?.port_preset || 'common',
    customPorts: row.options?.custom_ports || '',
    portscanTool: row.options?.portscan_tool || 'auto',
    subdomainTool: row.options?.subdomain_tool || 'auto',
    webTool: row.options?.web_tool || 'auto',
    timeout: row.options?.timeout || 300,
    enabled: row.enabled,
  })
  showForm.value = true
}

async function loadData() {
  loading.value = true
  try {
    const data = await getSchedules()
    items.value = data.items
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

async function handleSubmit() {
  if (!form.target.trim()) {
    ElMessage.warning(t('dashboard.pleaseTarget'))
    return
  }
  if (!form.cron_expr.trim()) {
    ElMessage.warning(t('schedules.invalidCron'))
    return
  }
  submitting.value = true
  try {
    const payload = {
      name: form.name.trim(),
      target: form.target.trim(),
      cron_expr: form.cron_expr.trim(),
      options: buildOptions(),
      enabled: form.enabled,
    }
    if (editing.value) {
      await updateSchedule(editing.value.id, payload)
      ElMessage.success(t('schedules.updated'))
    } else {
      await createSchedule(payload)
      ElMessage.success(t('schedules.created'))
    }
    showForm.value = false
    await loadData()
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    submitting.value = false
  }
}

async function handleToggle(row: ScheduleTask, enabled: boolean) {
  try {
    await toggleSchedule(row.id, enabled)
    await loadData()
  } catch (e: any) {
    ElMessage.error(e.message)
  }
}

async function handleRunNow(row: ScheduleTask) {
  try {
    await ElMessageBox.confirm(t('schedules.runNowConfirm'), { type: 'warning' })
    await runScheduleNow(row.id)
    ElMessage.success(t('schedules.ran'))
    setTimeout(loadData, 1500)
  } catch {
    /* 用户取消 */
  }
}

async function handleDelete(row: ScheduleTask) {
  try {
    await ElMessageBox.confirm(t('schedules.deleteConfirm'), { type: 'warning' })
    await deleteSchedule(row.id)
    ElMessage.success(t('schedules.deleted'))
    await loadData()
  } catch {
    /* 用户取消 */
  }
}

function formatTime(s: string | null): string {
  if (!s) return '—'
  const d = new Date(s)
  if (isNaN(d.getTime())) return s
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

onMounted(async () => {
  await Promise.all([loadData(), loadEngines()])
})
</script>

<style scoped>
.schedules-page {
  
  
}

.cron-code {
  font-family: 'SFMono-Regular', Consolas, monospace;
  background: var(--np-bg-surface);
  padding: 2px 8px;
  border-radius: var(--np-radius-sm);
  font-size: 13px;
}

.mode-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: var(--np-space-2);
}

.mode-card {
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-md);
  padding: var(--np-space-3);
  cursor: pointer;
  transition: all var(--np-transition);
}

.mode-card:hover {
  border-color: var(--np-blue-500);
}

.mode-card.active {
  border-color: var(--np-blue-500);
  background: rgba(37, 99, 235, 0.1);
}

.mode-card-title {
  font-size: 14px;
  font-weight: 500;
  margin-bottom: 2px;
}

.mode-card-desc {
  font-size: 12px;
  color: var(--np-text-secondary);
}

/* 引擎选择器（和 Tasks.vue 一致） */
.engine-group {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
}
.engine-option {
  display: flex; flex-direction: column;
  padding: 10px 12px; border: 1px solid var(--np-border);
  border-radius: var(--np-radius-md); cursor: pointer;
  transition: all var(--np-transition);
}
.engine-option:hover { border-color: var(--np-blue-400); }
.engine-option.active {
  border-color: var(--np-blue-500);
  background: rgba(59, 130, 246, 0.08);
}
.engine-name {
  font-size: 13px; font-weight: 600; color: var(--np-text-primary);
  display: flex; align-items: center; gap: 6px;
}
.engine-desc { font-size: 11px; color: var(--np-text-muted); margin-top: 2px; }

/* 检测项勾选 */
.stages-group {
  display: grid; grid-template-columns: repeat(4, 1fr);
  gap: 8px 12px; padding: 12px;
  background: var(--np-bg-elevated); border: 1px solid var(--np-border);
  border-radius: var(--np-radius-md);
}
.stage-item { display: flex; align-items: center; }
.stage-item.base :deep(.el-checkbox__label) { color: var(--np-text-disabled); }
.stage-item.warn :deep(.el-checkbox__label) { color: var(--np-text-secondary); }

@media (max-width: 768px) {
  .engine-group { grid-template-columns: 1fr; }
  .stages-group { grid-template-columns: repeat(2, 1fr); }
}
</style>
