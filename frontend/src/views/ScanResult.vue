<template>
  <div class="scan-result">
    <div class="np-page-header">
      <div>
        <span class="np-page-title">{{ scanStore.baseDomain || '...' }}</span>
        <span class="np-page-desc mono">{{ scanStore.scanId }}</span>
      </div>
      <div class="np-page-actions">
        <el-tag :type="statusType" size="large">{{ scanStore.status }}</el-tag>
      </div>
    </div>

    <!-- Progress log -->
    <el-card class="log-card">
      <template #header>
        <div class="np-card-header">
          <el-icon :size="16"><Monitor /></el-icon>
          <span>{{ t('scanResult.progressLog') }}</span>
          <span class="log-count mono" v-if="scanStore.logs.length">{{ t('scanResult.events', { n: scanStore.logs.length }) }}</span>
        </div>
      </template>
      <div class="log-area" ref="logRef" role="log" aria-live="polite">
        <div v-for="(line, i) in scanStore.logs" :key="i" class="log-line">
          <span class="log-prefix">{{ String(i + 1).padStart(3, '0') }}</span>
          <span :class="logClass(line)">{{ line }}</span>
        </div>
        <div v-if="scanStore.logs.length === 0" class="log-empty">
          <span class="cursor-blink">_</span> {{ t('scanResult.waiting') }}
        </div>
      </div>
    </el-card>

    <!-- Host results -->
    <el-card v-for="(host, i) in scanStore.hosts" :key="i" class="host-card">
      <template #header>
        <div class="host-header">
          <span class="host-index">#{{ i + 1 }}</span>
          <span class="host-name">{{ host.hostname || host.ip }}</span>
          <span class="mono host-ip" v-if="host.ip && host.hostname">{{ host.ip }}</span>
        </div>
      </template>
      <p v-if="host.os" class="info-line"><span class="info-label">{{ t('scanResult.os') }}</span> {{ host.os }}</p>

      <div v-if="host.ports?.length" class="section">
        <div class="np-section-title">
          <el-icon :size="14"><Connection /></el-icon> {{ t('scanResult.ports') }} <span class="np-badge">{{ host.ports.length }}</span>
        </div>
        <div class="np-table-wrapper">
          <el-table :data="host.ports" size="small">
            <el-table-column prop="port" :label="t('table.port')" width="70"><template #default="{ row }"><span class="mono">{{ row.port }}</span></template></el-table-column>
            <el-table-column prop="proto" :label="t('table.proto')" width="65" />
            <el-table-column prop="state" :label="t('table.state')" width="80"><template #default="{ row }"><el-tag :type="row.state === 'open' ? 'success' : 'info'" size="small">{{ row.state }}</el-tag></template></el-table-column>
            <el-table-column prop="service" :label="t('table.service')" />
            <el-table-column prop="product" :label="t('table.product')" />
            <el-table-column prop="version" :label="t('table.version')" />
          </el-table>
        </div>
      </div>

      <div v-if="host.web_info?.length" class="section">
        <div class="np-section-title">
          <el-icon :size="14"><Globe /></el-icon> {{ t('scanResult.webSites') }} <span class="np-badge">{{ host.web_info.length }}</span>
        </div>
        <div class="np-table-wrapper">
          <el-table :data="host.web_info" size="small">
            <el-table-column prop="url" :label="t('table.url')" min-width="180" show-overflow-tooltip />
            <el-table-column prop="status" :label="t('table.status')" width="75"><template #default="{ row }"><span class="mono">{{ row.status }}</span></template></el-table-column>
            <el-table-column prop="title" :label="t('table.title')" show-overflow-tooltip />
            <el-table-column :label="t('table.tech')" min-width="120">
              <template #default="{ row }">
                <template v-if="row.tech?.length">
                  <el-tag v-for="t_item in row.tech.slice(0, 3)" :key="t_item.name" size="small" type="info" style="margin-right:4px">{{ t_item.name }}{{ t_item.version ? ' ' + t_item.version : '' }}</el-tag>
                  <el-tag v-if="row.tech.length > 3" size="small" type="info">+{{ row.tech.length - 3 }}</el-tag>
                </template>
                <span v-else class="mono" style="color:var(--np-text-muted)">-</span>
              </template>
            </el-table-column>
            <el-table-column :label="t('table.ssl')" width="80">
              <template #default="{ row }">
                <el-tag v-if="row.ssl" :type="row.ssl.expired ? 'danger' : 'success'" size="small">{{ row.ssl.protocol || 'SSL' }}</el-tag>
                <span v-else class="mono" style="color:var(--np-text-muted)">-</span>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </div>

      <div v-if="host.sensitive?.length" class="section">
        <div class="np-section-title">
          <el-icon :size="14"><Warning /></el-icon> {{ t('scanResult.sensitivePaths') }} <span class="np-badge np-badge--warn">{{ host.sensitive.length }}</span>
        </div>
        <div class="np-table-wrapper">
          <el-table :data="host.sensitive" size="small">
            <el-table-column prop="path" :label="t('table.path')" show-overflow-tooltip><template #default="{ row }"><span class="mono">{{ row.path }}</span></template></el-table-column>
            <el-table-column prop="description" :label="t('table.description')" />
            <el-table-column prop="severity" :label="t('table.severity')" width="85"><template #default="{ row }"><el-tag :type="severityType(row.severity)" size="small">{{ row.severity }}</el-tag></template></el-table-column>
            <el-table-column prop="status_code" :label="t('table.statusCode')" width="85"><template #default="{ row }"><span class="mono">{{ row.status_code ?? '-' }}</span></template></el-table-column>
          </el-table>
        </div>
      </div>

      <div v-if="host.banners?.length" class="section">
        <div class="np-section-title">
          <el-icon :size="14"><Document /></el-icon> {{ t('scanResult.banners') }} <span class="np-badge">{{ host.banners.length }}</span>
        </div>
        <div class="np-table-wrapper">
          <el-table :data="host.banners" size="small">
            <el-table-column prop="port" :label="t('table.port')" width="70"><template #default="{ row }"><span class="mono">{{ row.port }}</span></template></el-table-column>
            <el-table-column prop="service" :label="t('table.service')" width="120" />
            <el-table-column prop="banner" :label="t('table.banner')" show-overflow-tooltip><template #default="{ row }"><span class="mono">{{ row.banner }}</span></template></el-table-column>
          </el-table>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, watch, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useScanStore } from '../stores/scan'

const { t } = useI18n()
const route = useRoute()
const scanStore = useScanStore()
const logRef = ref<HTMLElement>()

const statusType = computed(() => {
  if (scanStore.status === 'done') return 'success'
  if (scanStore.status === 'error') return 'danger'
  return 'warning'
})

function severityType(sev: string) {
  if (sev === 'high' || sev === 'critical') return 'danger'
  if (sev === 'medium') return 'warning'
  return 'info'
}

function logClass(line: string) {
  if (line.includes('[error]') || line.includes('[!]')) return 'log-error'
  if (line.includes('[done]')) return 'log-done'
  if (line.includes('[+]') || line.includes('found')) return 'log-found'
  return ''
}

watch(() => scanStore.logs.length, async () => {
  await nextTick()
  if (logRef.value) logRef.value.scrollTop = logRef.value.scrollHeight
})

onMounted(() => {
  const id = route.params.id as string
  if (id) scanStore.connect(id)
})

onUnmounted(() => scanStore.disconnect())
</script>

<style scoped>
.scan-result {
  max-width: 1400px;
  margin: 0 auto;
}

.log-card {
  margin-bottom: var(--np-space-4);
}

.log-count {
  margin-left: auto;
  font-size: 12px;
  color: var(--np-text-muted);
  font-weight: 400;
}

.log-area {
  background: #020617;
  color: var(--np-success);
  font-family: var(--np-font-mono);
  font-size: 13px;
  padding: var(--np-space-4);
  border-radius: var(--np-radius-lg);
  max-height: 300px;
  overflow-y: auto;
  line-height: 1.7;
  border: 1px solid var(--np-border);
}

.log-line {
  display: flex;
  gap: var(--np-space-3);
  white-space: pre-wrap;
  word-break: break-all;
}

.log-prefix {
  color: var(--np-text-disabled);
  flex-shrink: 0;
  user-select: none;
}

.log-error { color: var(--np-danger); }
.log-done { color: var(--np-blue-400); font-weight: 600; }
.log-found { color: var(--np-amber-400); }
.log-empty { color: var(--np-text-muted); }

.cursor-blink {
  animation: blink 1s step-end infinite;
}

@keyframes blink {
  50% { opacity: 0; }
}

.host-card {
  margin-bottom: var(--np-space-4);
}

.host-header {
  display: flex;
  align-items: center;
  gap: var(--np-space-2);
}

.host-index {
  color: var(--np-blue-400);
  font-weight: 700;
  font-size: 13px;
}

.host-name {
  font-weight: 600;
}

.host-ip {
  margin-left: auto;
  font-size: 12px;
  color: var(--np-text-muted);
}

.info-line {
  display: flex;
  gap: var(--np-space-3);
  color: var(--np-text-secondary);
}

.info-label {
  color: var(--np-text-muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  min-width: 28px;
}

.section {
  margin-top: var(--np-space-5);
}
</style>
