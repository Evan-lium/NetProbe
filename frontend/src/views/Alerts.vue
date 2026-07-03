<template>
  <div class="alerts-page">
    <div class="np-page-header">
      <div>
        <h2 class="np-page-title">{{ t('alerts.title') }}</h2>
        <span class="np-page-desc">{{ t('alerts.desc') }}</span>
      </div>
      <el-button type="primary" @click="showForm = true">
        <el-icon><Plus /></el-icon>
        {{ t('alerts.newRule') }}
      </el-button>
    </div>

    <el-tabs v-model="activeTab">
      <!-- 规则列表 -->
      <el-tab-pane :label="t('alerts.rules') + ` (${rules.length})`" name="rules">
        <el-card>
          <el-table :data="rules" v-loading="loading" style="width: 100%">
            <el-table-column prop="name" :label="t('alerts.name')" min-width="160" />
            <el-table-column :label="t('alerts.condition')" width="180">
              <template #default="{ row }">
                <el-tag size="small">{{ conditionLabel(row.condition_type) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="target" :label="t('alerts.target')" min-width="140" show-overflow-tooltip />
            <el-table-column :label="t('alerts.enabled')" width="90" align="center">
              <template #default="{ row }">
                <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
                  {{ row.enabled ? t('alerts.enabledOn') : t('alerts.enabledOff') }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column :label="t('alerts.lastTriggered')" width="170">
              <template #default="{ row }">{{ formatTime(row.last_triggered_at) }}</template>
            </el-table-column>
            <el-table-column :label="t('tasks.actions')" width="90" fixed="right">
              <template #default="{ row }">
                <el-button size="small" link type="danger" @click="handleDelete(row)">
                  <el-icon><Delete /></el-icon>
                </el-button>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-if="!loading && !rules.length" :description="t('alerts.noRules')" />
        </el-card>
      </el-tab-pane>

      <!-- 触发历史 -->
      <el-tab-pane :label="t('alerts.history') + ` (${events.length})`" name="events">
        <el-card>
          <el-timeline v-if="events.length">
            <el-timeline-item
              v-for="e in events" :key="e.id"
              :timestamp="formatTime(e.triggered_at)"
              type="danger"
            >
              <div class="event-summary">{{ e.summary }}</div>
              <div class="event-meta" v-if="e.channels.length">
                <el-tag v-for="(c, i) in e.channels" :key="i" size="small"
                  :type="c.success ? 'success' : 'danger'">
                  {{ c.channel }}: {{ c.success ? '✓' : '✗' }}
                </el-tag>
              </div>
            </el-timeline-item>
          </el-timeline>
          <el-empty v-else :description="t('alerts.noEvents')" />
        </el-card>
      </el-tab-pane>
    </el-tabs>

    <!-- 创建规则对话框 -->
    <el-dialog v-model="showForm" :title="t('alerts.newRule')" width="500px">
      <div class="alert-form np-form">
        <div class="np-form-row">
          <label class="np-form-label">{{ t('alerts.name') }}</label>
          <el-input v-model="form.name" :placeholder="t('alerts.namePlaceholder')" />
        </div>
        <div class="np-form-row">
          <label class="np-form-label">{{ t('alerts.condition') }}</label>
          <el-select v-model="form.condition_type" style="width: 100%">
            <el-option :label="t('alerts.condNewPort')" value="new_port" />
            <el-option :label="t('alerts.condNewSubdomain')" value="new_subdomain" />
            <el-option :label="t('alerts.condHighRiskPath')" value="high_risk_path" />
            <el-option :label="t('alerts.condCertExpiry')" value="cert_expiry" />
            <el-option :label="t('alerts.condTechChange')" value="tech_change" />
          </el-select>
        </div>
        <div class="np-form-row">
          <label class="np-form-label">{{ t('alerts.target') }}</label>
          <el-input v-model="form.target" :placeholder="t('alerts.targetPlaceholder')" />
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
import { ref, reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getAlerts, createAlert, deleteAlert, getAlertEvents } from '../api/scan'

const { t } = useI18n()
const activeTab = ref('rules')
const rules = ref<any[]>([])
const events = ref<any[]>([])
const loading = ref(true)
const showForm = ref(false)
const submitting = ref(false)

const form = reactive({
  name: '',
  condition_type: 'new_port',
  target: '',
})

const conditionLabels: Record<string, string> = {
  new_port: 'alerts.condNewPort',
  new_subdomain: 'alerts.condNewSubdomain',
  high_risk_path: 'alerts.condHighRiskPath',
  cert_expiry: 'alerts.condCertExpiry',
  tech_change: 'alerts.condTechChange',
}

function conditionLabel(type: string): string {
  return t(conditionLabels[type] || type)
}

function formatTime(s: string | null): string {
  if (!s) return '—'
  const d = new Date(s)
  if (isNaN(d.getTime())) return s
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

async function loadData() {
  loading.value = true
  try {
    const [r, e] = await Promise.all([getAlerts(), getAlertEvents()])
    rules.value = r.items
    events.value = e.items
  } catch (err: any) {
    ElMessage.error(err.message)
  } finally {
    loading.value = false
  }
}

async function handleSubmit() {
  if (!form.name.trim()) {
    ElMessage.warning(t('alerts.namePlaceholder'))
    return
  }
  submitting.value = true
  try {
    await createAlert({ name: form.name.trim(), condition_type: form.condition_type, target: form.target.trim() })
    ElMessage.success(t('alerts.created'))
    showForm.value = false
    form.name = ''
    form.target = ''
    await loadData()
  } catch (err: any) {
    ElMessage.error(err.message)
  } finally {
    submitting.value = false
  }
}

async function handleDelete(row: any) {
  try {
    await ElMessageBox.confirm(t('alerts.deleteConfirm'), { type: 'warning' })
    await deleteAlert(row.id)
    ElMessage.success(t('alerts.deleted'))
    await loadData()
  } catch { /* 用户取消 */ }
}

onMounted(loadData)
</script>

<style scoped>
.alerts-page { max-width: 1200px; margin: 0 auto; }
.event-summary { font-size: 14px; margin-bottom: 4px; }
.event-meta { display: flex; gap: 6px; }
</style>
