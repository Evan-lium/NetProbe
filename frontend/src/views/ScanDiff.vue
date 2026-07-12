<template>
  <div class="diff-page">
    <!-- Header -->
    <div class="np-page-header">
      <div>
        <h2 class="np-page-title">{{ t('diff.title') }}</h2>
        <span class="np-page-desc">{{ t('diff.desc') }}</span>
      </div>
      <div class="np-page-actions">
        <el-button @click="goBack">
          <el-icon><ArrowLeft /></el-icon>
          返回
        </el-button>
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

    <!-- 对比结果：左右分栏 -->
    <template v-else>
      <!-- Summary 统计条 -->
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

      <!-- 左右对比表头 -->
      <div class="diff-columns-header">
        <div class="diff-col-header diff-col-a">
          <span class="diff-col-label">扫描 A</span>
          <span class="diff-col-id mono">{{ diff.scan_a?.scan_id?.slice(0, 8) || scanA.slice(0, 8) }}</span>
        </div>
        <div class="diff-col-divider"></div>
        <div class="diff-col-header diff-col-b">
          <span class="diff-col-label">扫描 B</span>
          <span class="diff-col-id mono">{{ diff.scan_b?.scan_id?.slice(0, 8) || scanB.slice(0, 8) }}</span>
        </div>
      </div>

      <!-- 主机差异：左右对比 -->
      <div class="diff-host-list">
        <div v-for="h in diff.hosts" :key="h.hostname + h.ip" class="host-diff-row">
          <!-- 主机名行（跨两列） -->
          <div class="host-diff-title">
            <span class="host-name">{{ h.hostname }}</span>
            <span class="host-ip" v-if="h.ip">{{ h.ip }}</span>
            <el-tag :type="statusTagType(h.status)" size="small" effect="dark">
              {{ t(`diff.status${cap(h.status)}`) }}
            </el-tag>
          </div>

          <!-- 左右分栏内容 -->
          <div class="host-diff-columns">
            <!-- 左：扫描 A -->
            <div class="diff-side diff-side-a">
              <template v-if="h.status === 'added'">
                <span class="diff-empty">— 不存在 —</span>
              </template>
              <template v-else>
                <!-- 端口 -->
                <div class="dim-section" v-if="h.ports.removed.length || h.ports.changed.length">
                  <div class="dim-title">{{ t('scanResult.ports') }}</div>
                  <div class="np-tag-group">
                    <span v-for="p in h.ports.removed" :key="'pr' + p.port + p.proto" class="np-tag-remove">
                      − {{ p.port }}/{{ p.proto }} {{ p.service }}
                    </span>
                    <span v-for="(c, i) in h.ports.changed" :key="'pc' + i" class="np-tag-change">
                      ~ {{ c.key[0] }}/{{ c.key[1] }}: {{ c.from.service || '?' }} {{ c.from.version || '' }}
                    </span>
                  </div>
                </div>
                <!-- Web -->
                <div class="dim-section" v-if="h.web.removed.length || h.web.changed.length">
                  <div class="dim-title">{{ t('scanResult.webSites') }}</div>
                  <div class="np-tag-group">
                    <span v-for="w in h.web.removed" :key="'wr' + w.url" class="np-tag-remove">
                      − {{ w.title || w.url }} [{{ w.status }}]
                    </span>
                    <span v-for="c in h.web.changed" :key="'wc' + c.url" class="np-tag-change">
                      ~ {{ c.url }}
                      <template v-if="c.changes.tech">
                        ({{ c.changes.tech.removed?.length || 0 }} 技术)
                      </template>
                    </span>
                  </div>
                </div>
                <!-- 敏感路径 -->
                <div class="dim-section" v-if="h.sensitive.removed.length">
                  <div class="dim-title">{{ t('scanResult.sensitivePaths') }}</div>
                  <div class="np-tag-group">
                    <span v-for="s in h.sensitive.removed" :key="'sr' + s.path" class="np-tag-remove">− {{ s.path }}</span>
                  </div>
                </div>
                <!-- JS -->
                <div class="dim-section" v-if="h.js.removed.length">
                  <div class="dim-title">{{ t('scanResult.jsFindings') }}</div>
                  <div class="np-tag-group">
                    <span v-for="j in h.js.removed" :key="'jr' + j.js_url" class="np-tag-remove">− {{ j.js_url }}</span>
                  </div>
                </div>
                <!-- Banner -->
                <div class="dim-section" v-if="h.banners.removed.length">
                  <div class="dim-title">{{ t('scanResult.banners') }}</div>
                  <div class="np-tag-group">
                    <span v-for="b in h.banners.removed" :key="'br' + b.port + b.service" class="np-tag-remove">− {{ b.port }} {{ b.service }}</span>
                  </div>
                </div>
                <span v-if="isHostEmptyOnSide(h, 'a')" class="diff-empty">无变化</span>
              </template>
            </div>

            <!-- 分隔线 -->
            <div class="diff-side-divider"></div>

            <!-- 右：扫描 B -->
            <div class="diff-side diff-side-b">
              <template v-if="h.status === 'removed'">
                <span class="diff-empty">— 不存在 —</span>
              </template>
              <template v-else>
                <!-- 端口 -->
                <div class="dim-section" v-if="h.ports.added.length || h.ports.changed.length">
                  <div class="dim-title">{{ t('scanResult.ports') }}</div>
                  <div class="np-tag-group">
                    <span v-for="p in h.ports.added" :key="'pa' + p.port + p.proto" class="np-tag-add">
                      + {{ p.port }}/{{ p.proto }} {{ p.service }}
                    </span>
                    <span v-for="(c, i) in h.ports.changed" :key="'pcb' + i" class="np-tag-change">
                      ~ {{ c.key[0] }}/{{ c.key[1] }}: {{ c.to.service || '?' }} {{ c.to.version || '' }}
                    </span>
                  </div>
                </div>
                <!-- Web -->
                <div class="dim-section" v-if="h.web.added.length || h.web.changed.length">
                  <div class="dim-title">{{ t('scanResult.webSites') }}</div>
                  <div class="np-tag-group">
                    <span v-for="w in h.web.added" :key="'wa' + w.url" class="np-tag-add">
                      + {{ w.title || w.url }} [{{ w.status }}]
                    </span>
                    <span v-for="c in h.web.changed" :key="'wcb' + c.url" class="np-tag-change">
                      ~ {{ c.url }}
                      <template v-if="c.changes.tech">
                        ({{ c.changes.tech.added?.length || 0 }} 技术)
                      </template>
                    </span>
                  </div>
                </div>
                <!-- 敏感路径 -->
                <div class="dim-section" v-if="h.sensitive.added.length">
                  <div class="dim-title">{{ t('scanResult.sensitivePaths') }}</div>
                  <div class="np-tag-group">
                    <span v-for="s in h.sensitive.added" :key="'sa' + s.path" class="np-tag-add">+ {{ s.path }}</span>
                  </div>
                </div>
                <!-- JS -->
                <div class="dim-section" v-if="h.js.added.length">
                  <div class="dim-title">{{ t('scanResult.jsFindings') }}</div>
                  <div class="np-tag-group">
                    <span v-for="j in h.js.added" :key="'ja' + j.js_url" class="np-tag-add">+ {{ j.js_url }}</span>
                  </div>
                </div>
                <!-- Banner -->
                <div class="dim-section" v-if="h.banners.added.length">
                  <div class="dim-title">{{ t('scanResult.banners') }}</div>
                  <div class="np-tag-group">
                    <span v-for="b in h.banners.added" :key="'ba' + b.port + b.service" class="np-tag-add">+ {{ b.port }} {{ b.service }}</span>
                  </div>
                </div>
                <span v-if="isHostEmptyOnSide(h, 'b')" class="diff-empty">无变化</span>
              </template>
            </div>
          </div>
        </div>
      </div>
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

/** 判断某侧是否有任何变化内容 */
function isHostEmptyOnSide(h: any, side: 'a' | 'b'): boolean {
  if (side === 'a') {
    return !h.ports.removed.length && !h.ports.changed.length
      && !h.web.removed.length && !h.web.changed.length
      && !h.sensitive.removed.length && !h.js.removed.length
      && !h.banners.removed.length
  }
  return !h.ports.added.length && !h.ports.changed.length
    && !h.web.added.length && !h.web.changed.length
    && !h.sensitive.added.length && !h.js.added.length
    && !h.banners.added.length
}

async function loadCandidates() {
  try {
    const data = await getHistory({ per_page: 100, status: 'done' })
    candidates.value = data.items
  } catch (e: any) {
    ElMessage.error(e.message)
  }
}

function goBack() {
  // 优先返回上一页，没有历史则回任务列表
  if (window.history.length > 1) {
    router.back()
  } else {
    router.push('/tasks')
  }
}

async function doCompare() {
  if (!scanA.value || !scanB.value) return
  loading.value = true
  diff.value = null
  try {
    diff.value = await getDiff(scanA.value, scanB.value)
    router.replace({ query: { a: scanA.value, b: scanB.value } })
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

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

/* ── 左右对比表头 ── */
.diff-columns-header {
  display: flex;
  align-items: center;
  margin-bottom: var(--np-space-3);
  padding: 0 4px;
}

.diff-col-header {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  border-radius: var(--np-radius-md);
  font-size: 14px;
  font-weight: 600;
}

.diff-col-a {
  background: rgba(239, 68, 68, 0.06);
  color: #dc2626;
}

.diff-col-b {
  background: rgba(16, 185, 129, 0.06);
  color: #059669;
}

.diff-col-id {
  font-size: 12px;
  font-weight: 400;
  opacity: 0.7;
}

.diff-col-divider {
  width: 24px;
  flex-shrink: 0;
}

/* ── 主机差异行 ── */
.diff-host-list {
  display: flex;
  flex-direction: column;
  gap: var(--np-space-3);
}

.host-diff-row {
  background: var(--np-bg-surface);
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-lg);
  overflow: hidden;
}

.host-diff-title {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--np-border);
  background: var(--np-bg-app);
}

.host-name {
  font-size: 15px;
  font-weight: 600;
  color: var(--np-text-primary);
}

.host-ip {
  font-size: 13px;
  color: var(--np-text-secondary);
  font-family: var(--np-font-mono);
}

/* ── 左右分栏 ── */
.host-diff-columns {
  display: flex;
  min-height: 48px;
}

.diff-side {
  flex: 1;
  padding: 12px 16px;
  min-width: 0;
}

.diff-side-a {
  background: rgba(239, 68, 68, 0.02);
}

.diff-side-b {
  background: rgba(16, 185, 129, 0.02);
}

.diff-side-divider {
  width: 1px;
  background: var(--np-border);
  flex-shrink: 0;
}

.diff-empty {
  color: var(--np-text-muted);
  font-size: 13px;
  font-style: italic;
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
