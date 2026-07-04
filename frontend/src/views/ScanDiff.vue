<template>
  <div class="diff-page">
    <!-- Header -->
    <div class="np-page-header">
      <div>
        <h2 class="np-page-title">{{ t('diff.title') }}</h2>
        <span class="np-page-desc">{{ t('diff.desc') }}</span>
      </div>
    </div>

    <!-- 扫描选择栏 -->
    <el-card class="diff-select-card">
      <div class="select-bar">
        <div class="select-item">
          <label class="select-label">{{ t('diff.selectA') }}</label>
          <el-select v-model="scanA" filterable :placeholder="t('diff.selectA')" style="width: 100%">
            <el-option
              v-for="s in candidates"
              :key="s.scan_id"
              :label="`${s.name || s.base_domain || s.target_raw} (${s.scan_id.slice(0, 8)})`"
              :value="s.scan_id"
              :disabled="s.scan_id === scanB"
            />
          </el-select>
        </div>
        <el-icon class="select-arrow"><Right /></el-icon>
        <div class="select-item">
          <label class="select-label">{{ t('diff.selectB') }}</label>
          <el-select v-model="scanB" filterable :placeholder="t('diff.selectB')" style="width: 100%">
            <el-option
              v-for="s in candidates"
              :key="s.scan_id"
              :label="`${s.name || s.base_domain || s.target_raw} (${s.scan_id.slice(0, 8)})`"
              :value="s.scan_id"
              :disabled="s.scan_id === scanA"
            />
          </el-select>
        </div>
        <el-button type="primary" :loading="loading" :disabled="!scanA || !scanB" @click="doCompare">
          <el-icon><DataAnalysis /></el-icon>
          {{ t('diff.compare') }}
        </el-button>
      </div>
    </el-card>

    <!-- 加载态 -->
    <el-card v-if="loading" class="task-list-card">
      <div class="task-loading">
        <div class="np-skeleton" style="height: 44px; margin-bottom: 8px" />
        <div class="np-skeleton" style="height: 44px; margin-bottom: 8px" />
        <div class="np-skeleton" style="height: 44px" />
      </div>
    </el-card>

    <!-- 空态 -->
    <el-card v-else-if="!diff" class="task-list-card">
      <el-empty :description="t('diff.empty')" />
    </el-card>

    <!-- 无差异 -->
    <el-card v-else-if="!diff.hosts.length" class="task-list-card">
      <el-empty :description="t('diff.noDiff')" />
    </el-card>

    <!-- 对比结果 -->
    <template v-else>
      <!-- Summary 卡片 -->
      <div class="np-stat-grid">
        <div class="np-stat-card np-stat-card--success">
          <div class="np-stat-num">{{ diff.summary.hosts_added }}</div>
          <div class="np-stat-label">{{ t('diff.hostsAdded') }}</div>
        </div>
        <div class="np-stat-card np-stat-card--danger">
          <div class="np-stat-num">{{ diff.summary.hosts_removed }}</div>
          <div class="np-stat-label">{{ t('diff.hostsRemoved') }}</div>
        </div>
        <div class="np-stat-card np-stat-card--warning">
          <div class="np-stat-num">{{ diff.summary.ports_added + diff.summary.ports_removed + diff.summary.ports_changed }}</div>
          <div class="np-stat-label">{{ t('diff.portsChanged') }}</div>
        </div>
        <div class="np-stat-card np-stat-card--warning">
          <div class="np-stat-num">{{ diff.summary.tech_changed }}</div>
          <div class="np-stat-label">{{ t('diff.techChanged') }}</div>
        </div>
      </div>

      <!-- 主机差异列表 -->
      <el-card v-for="h in diff.hosts" :key="h.hostname + h.ip" class="host-diff-card">
        <div class="host-diff-header">
          <span class="host-name">{{ h.hostname }}</span>
          <span class="host-ip" v-if="h.ip">{{ h.ip }}</span>
          <el-tag :type="statusTagType(h.status)" size="small" effect="dark">
            {{ t(`diff.status${cap(h.status)}`) }}
          </el-tag>
        </div>

        <div class="host-diff-body">
          <!-- 端口差异 -->
          <div class="dim-section" v-if="hasDim(h.ports)">
            <div class="dim-title">{{ t('scanResult.ports') }}</div>
            <div class="np-tag-group">
              <span v-for="p in h.ports.added" :key="'pa' + p.port + p.proto" class="np-tag-add">
                + {{ p.port }}/{{ p.proto }} {{ p.service }}
              </span>
              <span v-for="p in h.ports.removed" :key="'pr' + p.port + p.proto" class="np-tag-remove">
                − {{ p.port }}/{{ p.proto }} {{ p.service }}
              </span>
              <span v-for="(c, i) in h.ports.changed" :key="'pc' + i" class="np-tag-change">
                ~ {{ c.key[0] }}/{{ c.key[1] }}: {{ c.from.service || '?' }} → {{ c.to.service || '?' }}
              </span>
            </div>
          </div>

          <!-- Web 站点差异 -->
          <div class="dim-section" v-if="hasWeb(h.web)">
            <div class="dim-title">{{ t('scanResult.webSites') }}</div>
            <div class="np-tag-group">
              <span v-for="w in h.web.added" :key="'wa' + w.url" class="np-tag-add">
                + {{ w.title || w.url }} [{{ w.status }}]
              </span>
              <span v-for="w in h.web.removed" :key="'wr' + w.url" class="np-tag-remove">
                − {{ w.title || w.url }} [{{ w.status }}]
              </span>
              <span v-for="c in h.web.changed" :key="'wc' + c.url" class="np-tag-change">
                ~ {{ c.url }}
                <template v-if="c.changes.tech">
                  ({{ c.changes.tech.added?.length || 0 }}+ / {{ c.changes.tech.removed?.length || 0 }}−)
                </template>
              </span>
            </div>
          </div>

          <!-- 敏感路径差异 -->
          <div class="dim-section" v-if="h.sensitive.added.length || h.sensitive.removed.length">
            <div class="dim-title">{{ t('scanResult.sensitivePaths') }}</div>
            <div class="np-tag-group">
              <span v-for="s in h.sensitive.added" :key="'sa' + s.path" class="np-tag-add">+ {{ s.path }}</span>
              <span v-for="s in h.sensitive.removed" :key="'sr' + s.path" class="np-tag-remove">− {{ s.path }}</span>
            </div>
          </div>

          <!-- JS 分析差异 -->
          <div class="dim-section" v-if="h.js.added.length || h.js.removed.length">
            <div class="dim-title">{{ t('scanResult.jsFindings') }}</div>
            <div class="np-tag-group">
              <span v-for="j in h.js.added" :key="'ja' + j.js_url" class="np-tag-add">+ {{ j.js_url }}</span>
              <span v-for="j in h.js.removed" :key="'jr' + j.js_url" class="np-tag-remove">− {{ j.js_url }}</span>
            </div>
          </div>

          <!-- Banner 差异 -->
          <div class="dim-section" v-if="h.banners.added.length || h.banners.removed.length">
            <div class="dim-title">{{ t('scanResult.banners') }}</div>
            <div class="np-tag-group">
              <span v-for="b in h.banners.added" :key="'ba' + b.port + b.service" class="np-tag-add">+ {{ b.port }} {{ b.service }}</span>
              <span v-for="b in h.banners.removed" :key="'br' + b.port + b.service" class="np-tag-remove">− {{ b.port }} {{ b.service }}</span>
            </div>
          </div>
        </div>
      </el-card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { getHistory, getDiff } from '../api/scan'
import type { HistoryItem, ScanDiff, PortDiff, WebDiff } from '../types'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()

const candidates = ref<HistoryItem[]>([])
const scanA = ref('')
const scanB = ref('')
const diff = ref<ScanDiff | null>(null)
const loading = ref(false)

function cap(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1)
}

function statusTagType(status: string): 'success' | 'danger' | 'warning' {
  if (status === 'added') return 'success'
  if (status === 'removed') return 'danger'
  return 'warning'
}

function hasDim(p: PortDiff): boolean {
  return p.added.length > 0 || p.removed.length > 0 || p.changed.length > 0
}

function hasWeb(w: WebDiff): boolean {
  return w.added.length > 0 || w.removed.length > 0 || w.changed.length > 0
}

async function loadCandidates() {
  try {
    // 只对比已完成的扫描，取较多条以便选择
    const data = await getHistory({ per_page: 100, status: 'done' })
    candidates.value = data.items
  } catch (e: any) {
    ElMessage.error(e.message)
  }
}

async function doCompare() {
  if (!scanA.value || !scanB.value) return
  loading.value = true
  diff.value = null
  try {
    diff.value = await getDiff(scanA.value, scanB.value)
    // 同步到 URL query，便于分享/刷新
    router.replace({ query: { a: scanA.value, b: scanB.value } })
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

// 路由 query 参数变化时自动加载（从 Tasks 多选跳转 / 直接访问 URL）
watch(
  () => [route.query.a, route.query.b],
  ([a, b]) => {
    if (a && b && typeof a === 'string' && typeof b === 'string') {
      scanA.value = a
      scanB.value = b
      doCompare()
    }
  },
  { immediate: true },
)

onMounted(loadCandidates)
</script>

<style scoped>
.diff-page {
  
  
}

.diff-select-card {
  margin-bottom: var(--np-space-5);
}

.select-bar {
  display: flex;
  align-items: flex-end;
  gap: var(--np-space-3);
}

.select-item {
  flex: 1;
}

.select-label {
  display: block;
  font-size: 13px;
  color: var(--np-text-secondary);
  margin-bottom: 6px;
}

.select-arrow {
  font-size: 20px;
  color: var(--np-text-secondary);
  padding-bottom: 8px;
}

.host-diff-card {
  margin-bottom: var(--np-space-3);
}

.host-diff-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: var(--np-space-3);
}

.host-name {
  font-size: 15px;
  font-weight: 600;
}

.host-ip {
  font-size: 13px;
  color: var(--np-text-secondary);
  font-family: var(--np-font-mono);
}

.dim-section {
  margin-bottom: var(--np-space-2);
}

.dim-section:last-child {
  margin-bottom: 0;
}

.dim-title {
  font-size: 12px;
  color: var(--np-text-secondary);
  margin-bottom: 6px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
</style>
