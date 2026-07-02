<template>
  <div class="corr-page">
    <!-- Header -->
    <div class="tasks-header">
      <div>
        <h2 class="np-page-title">{{ t('correlations.title') }}</h2>
        <span class="np-page-desc">{{ t('correlations.desc') }}</span>
      </div>
    </div>

    <el-card>
      <!-- 类型切换 tabs -->
      <el-tabs v-model="activeType" @tab-change="loadData">
        <el-tab-pane
          v-for="tab in tabs"
          :key="tab.value"
          :label="`${t(tab.labelKey)} (${counts[tab.value] || 0})`"
          :name="tab.value"
        />
      </el-tabs>

      <div v-if="loading" class="task-loading">
        <div class="np-skeleton" style="height: 120px; margin-bottom: 12px" />
        <div class="np-skeleton" style="height: 120px" />
      </div>

      <div v-else-if="clusters.length" class="cluster-grid">
        <div v-for="(c, idx) in clusters" :key="activeType + idx" class="cluster-card">
          <div class="cluster-head">
            <span class="cluster-key mono">{{ c.key }}</span>
            <el-tag size="small" type="info">{{ c.count }} {{ t('correlations.assets') }}</el-tag>
          </div>

          <!-- 证书簇附加信息 -->
          <div v-if="c.type === 'cert'" class="cluster-meta">
            <span v-if="c.issuer">{{ t('table.ssl') }}: {{ c.issuer }}</span>
            <span v-if="c.not_after">{{ t('correlations.expiry') }}: {{ c.not_after }}</span>
            <el-tag v-if="c.expired" size="small" type="danger" effect="dark">{{ t('correlations.expired') }}</el-tag>
          </div>

          <!-- 服务簇附加信息 -->
          <div v-else-if="c.type === 'service'" class="cluster-meta">
            <span v-if="c.product">{{ c.product }}</span>
            <span v-if="c.version">v{{ c.version }}</span>
          </div>

          <!-- 成员资产列表 -->
          <div class="member-list">
            <span v-for="(m, i) in c.members" :key="i" class="member-chip">
              <el-icon><Monitor /></el-icon>
              {{ m.hostname || m.ip }}
              <span v-if="m.hostname && m.ip" class="member-ip">{{ m.ip }}</span>
            </span>
          </div>
        </div>
      </div>

      <div v-else class="np-empty">
        <el-icon :size="36" color="var(--np-text-disabled)"><Share /></el-icon>
        <p>{{ t('correlations.empty') }}</p>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { getCorrelations } from '../api/scan'
import type { CorrelationType, CorrelationCluster } from '../types'

const { t } = useI18n()

const tabs = [
  { value: 'ip' as CorrelationType, labelKey: 'correlations.tabIp' },
  { value: 'cert' as CorrelationType, labelKey: 'correlations.tabCert' },
  { value: 'tech' as CorrelationType, labelKey: 'correlations.tabTech' },
  { value: 'service' as CorrelationType, labelKey: 'correlations.tabService' },
]

const activeType = ref<CorrelationType>('ip')
const loading = ref(false)
const groups = ref<Partial<Record<CorrelationType, CorrelationCluster[]>>>({})

const clusters = computed(() => groups.value[activeType.value] || [])
const counts = computed(() => {
  const result: Record<string, number> = {}
  for (const tab of tabs) {
    result[tab.value] = (groups.value[tab.value] || []).length
  }
  return result
})

async function loadData() {
  loading.value = true
  try {
    const data = await getCorrelations()
    groups.value = data.groups
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

onMounted(loadData)
</script>

<style scoped>
.corr-page {
  max-width: 1400px;
  margin: 0 auto;
}

.tasks-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 20px;
}

.cluster-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
  gap: 14px;
}

.cluster-card {
  border: 1px solid var(--el-border-color);
  border-radius: 8px;
  padding: 14px 16px;
  background: var(--el-bg-color-page);
}

.cluster-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.cluster-key {
  font-weight: 600;
  font-size: 14px;
  word-break: break-all;
}

.cluster-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-bottom: 10px;
}

.member-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.member-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 10px;
  border-radius: 4px;
  background: var(--el-fill-color-light);
  font-size: 13px;
}

.member-chip .el-icon {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.member-ip {
  color: var(--el-text-color-secondary);
  font-size: 12px;
  margin-left: 2px;
}
</style>
