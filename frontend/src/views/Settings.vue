<template>
  <div class="settings">
    <div class="np-page-header">
      <span class="np-page-title">{{ t('settings.title') }}</span>
    </div>

    <div class="settings-grid">
      <!-- Layout -->
      <el-card>
        <template #header>
          <div class="np-card-header">
            <el-icon :size="16"><Monitor /></el-icon>
            <span>{{ t('settings.layout') }}</span>
          </div>
        </template>
        <el-radio-group v-model="layout" @change="handleLayoutChange">
          <el-radio-button value="sidebar">{{ t('settings.layoutSidebar') }}</el-radio-button>
          <el-radio-button value="topnav">{{ t('settings.layoutTopNav') }}</el-radio-button>
        </el-radio-group>
        <p class="helper">{{ t('settings.layoutHelp') }}</p>
      </el-card>

      <!-- External Tools -->
      <el-card>
        <template #header>
          <div class="np-card-header">
            <el-icon :size="16"><SetUp /></el-icon>
            <span>{{ t('settings.externalTools') }}</span>
          </div>
        </template>
        <div class="np-table-wrapper">
          <el-table :data="toolList" v-loading="toolsLoading" size="small">
            <el-table-column prop="label" :label="t('settings.tool')" width="120" />
            <el-table-column prop="name" :label="t('settings.command')" width="120">
              <template #default="{ row }"><span class="mono">{{ row.name }}</span></template>
            </el-table-column>
            <el-table-column :label="t('settings.status')" width="100">
              <template #default="{ row }">
                <el-tag :type="row.available ? 'success' : 'danger'" size="small">{{ row.available ? t('common.available') : t('common.missing') }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column :label="t('settings.capabilities')">
              <template #default="{ row }">
                <el-tag v-for="cap in row.caps" :key="cap" size="small" type="info" style="margin-right:4px">{{ cap }}</el-tag>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-card>

      <!-- API Keys -->
      <el-card class="full-width">
        <template #header>
          <div class="np-card-header">
            <el-icon :size="16"><Key /></el-icon>
            <span>{{ t('settings.apiKeys') }}</span>
          </div>
        </template>
        <el-form label-width="140px">
          <el-form-item :label="t('settings.shodanKey')">
            <el-input v-model="apiKeys.shodan" :placeholder="t('settings.enterKey')" show-password style="max-width:400px" />
          </el-form-item>
          <el-form-item :label="t('settings.fofaEmail')">
            <el-input v-model="apiKeys.fofa_email" :placeholder="t('settings.email')" style="max-width:400px" />
          </el-form-item>
          <el-form-item :label="t('settings.fofaKey')">
            <el-input v-model="apiKeys.fofa_key" :placeholder="t('settings.enterKey')" show-password style="max-width:400px" />
          </el-form-item>
        </el-form>
        <div class="form-actions">
          <el-button type="primary" :loading="saving" @click="saveSettings">
            <el-icon v-if="!saving"><Check /></el-icon>
            <span>{{ saving ? t('common.saving') : t('common.save') }}</span>
          </el-button>
        </div>
      </el-card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { useAppStore } from '../stores/app'
import { getTools, getSettings, updateSettings } from '../api/scan'
import type { ToolStatus } from '../types'

const { t } = useI18n()
const appStore = useAppStore()
const layout = ref(appStore.layout)
const toolsLoading = ref(false)
const toolList = ref<(ToolStatus & { name: string })[]>([])
const saving = ref(false)
const apiKeys = reactive({ shodan: '', fofa_email: '', fofa_key: '' })

function handleLayoutChange(val: any) {
  appStore.setLayout(val as 'sidebar' | 'topnav')
}

async function saveSettings() {
  saving.value = true
  try {
    await updateSettings({ api_keys: { ...apiKeys } })
    ElMessage.success(t('settings.saved'))
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    saving.value = false
  }
}

onMounted(async () => {
  toolsLoading.value = true
  try {
    const [tools, settings] = await Promise.all([getTools(), getSettings()])
    toolList.value = Object.values(tools)
    if (settings.api_keys) Object.assign(apiKeys, settings.api_keys)
  } finally {
    toolsLoading.value = false
  }
})
</script>

<style scoped>
.settings {
  max-width: 1200px;
  margin: 0 auto;
}

.settings-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--np-space-4);
}

.settings-grid .full-width {
  grid-column: 1 / -1;
}

.helper {
  margin-top: var(--np-space-3);
  font-size: 13px;
  color: var(--np-text-muted);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  padding-top: var(--np-space-2);
}

.form-actions .el-button {
  display: flex;
  align-items: center;
  gap: var(--np-space-2);
}

@media (max-width: 768px) {
  .settings-grid {
    grid-template-columns: 1fr;
  }
}
</style>
