<template>
  <div class="assets">
    <div class="np-page-header">
      <div>
        <span class="np-page-title">{{ t('assets.title') }}</span>
        <span class="np-page-desc" v-if="items.length">{{ t('assets.assets', { n: items.length }) }}</span>
      </div>
    </div>

    <el-card>
      <!-- 搜索栏 + 排序 -->
      <div class="np-filter-bar">
        <el-input v-model="query" :placeholder="t('assets.searchPlaceholder')" clearable style="width: 260px" @keyup.enter="loadData">
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <el-select v-model="sortBy" style="width: 160px" @change="loadData">
          <el-option :label="t('assets.sortHostname')" value="hostname" />
          <el-option :label="t('assets.sortPortCount')" value="port_count" />
          <el-option :label="t('assets.sortScanCount')" value="scan_count" />
          <el-option :label="t('assets.sortRiskScore')" value="risk_score" />
        </el-select>
        <el-button type="primary" @click="loadData">{{ t('common.search') }}</el-button>
      </div>

      <!-- 卡片网格 -->
      <div class="asset-grid" v-loading="loading">
        <div
          v-for="row in items"
          :key="row.rowKey"
          class="asset-card"
          :class="riskBorderClass(row.risk_score || 0)"
          @click="openDetail(row)"
        >
          <!-- 头部行：IP + 主机名 / 风险徽章 -->
          <div class="card-head">
            <div class="card-id">
              <span class="card-ip mono">{{ row.ip }}</span>
              <span class="card-host" v-if="row.hostname && row.hostname !== row.ip">{{ row.hostname }}</span>
            </div>
            <span class="risk-badge" :class="riskClass(row.risk_score || 0)">
              {{ riskLabel(row.risk_score || 0) }} {{ row.risk_score || 0 }}
            </span>
          </div>

          <!-- Web 站点区（预取详情后有则展示） -->
          <div class="card-web" v-if="row._preview?.firstSite">
            <div class="web-line">
              <el-icon class="web-ico"><Monitor /></el-icon>
              <a :href="row._preview.firstSite.url" target="_blank" rel="noopener" class="web-url mono" @click.stop>
                {{ row._preview.firstSite.url }}
              </a>
              <el-tag v-if="row._preview.firstSite.status" :type="statusTagType(row._preview.firstSite.status)" size="small" effect="dark" class="status-tag">
                {{ row._preview.firstSite.status }}
              </el-tag>
            </div>
            <div class="web-title" v-if="row._preview.firstSite.title">“{{ row._preview.firstSite.title }}”</div>
            <div class="tech-tags" v-if="row._preview.firstSite.tech?.length">
              <el-tag
                v-for="(tech, ti) in row._preview.firstSite.tech.slice(0, 5)"
                :key="ti"
                size="small"
                type="info"
                class="tech-tag"
              >{{ tech }}</el-tag>
            </div>
          </div>

          <!-- 端口区 -->
          <div class="card-ports" v-if="row._preview?.ports?.length">
            <el-icon class="ports-ico"><Connection /></el-icon>
            <span class="ports-list mono">
              <span v-for="(p, i) in row._preview.ports.slice(0, 10)" :key="i" class="port-chip">
                {{ p.port }}/{{ p.proto }}
              </span>
              <span class="port-more" v-if="row._preview.ports.length > 10">
                +{{ row._preview.ports.length - 10 }}
              </span>
            </span>
          </div>

          <!-- 底部行：扫描次数 + 最后扫描时间 -->
          <div class="card-foot">
            <span class="foot-meta">
              <el-icon><Aim /></el-icon>
              {{ t('assets.scans') }} {{ row.scan_count }}
            </span>
            <span class="foot-meta" v-if="row._preview?.lastScan">
              <el-icon><Clock /></el-icon>
              {{ row._preview.lastScan }}
            </span>
          </div>
        </div>
      </div>

      <!-- 空状态 -->
      <div v-if="!loading && items.length === 0" class="np-empty">
        <el-icon :size="36" color="var(--np-text-disabled)"><Grid /></el-icon>
        <p>{{ t('assets.empty') }}</p>
      </div>
    </el-card>

    <!-- 详情抽屉 -->
    <el-drawer
      v-model="drawerVisible"
      :title="drawerTitle"
      direction="rtl"
      size="640px"
      class="asset-drawer"
    >
      <div v-loading="detailLoading" class="drawer-body">
        <!-- 加载失败 -->
        <div v-if="detailError" class="drawer-error">
          <el-icon :size="22" color="var(--np-danger)"><WarningFilled /></el-icon>
          <span>{{ detailError }}</span>
        </div>

        <template v-else-if="detail">
          <!-- 概览数字条 -->
          <div class="detail-overview">
            <span class="ov-item"><b class="mono">{{ detail.port_count }}</b>{{ t('assets.ports') }}</span>
            <span class="ov-item"><b class="mono">{{ detail.web_count }}</b>{{ t('assets.web') }}</span>
            <span class="ov-item" v-if="detail.vuln_count">
              <b class="mono" style="color:var(--np-danger)">{{ detail.vuln_count }}</b>{{ t('assets.detail.vulns') }}
            </span>
            <span class="ov-item"><b class="mono">{{ detail.scan_count }}</b>{{ t('assets.scans') }}</span>
          </div>

          <!-- Tab 分区 -->
          <el-tabs v-model="detailTab" class="detail-tabs">
            <!-- 漏洞（如果有，放第一个 Tab 最醒目） -->
            <el-tab-pane v-if="detail.vulnerabilities?.length" :name="'vulns'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Warning /></el-icon>
                  {{ t('assets.detail.vulns') }}
                  <span class="tab-count danger">{{ detail.vulnerabilities.length }}</span>
                </span>
              </template>
              <div class="tab-content">
                <div v-for="(v, i) in detail.vulnerabilities" :key="i" class="vuln-row">
                  <el-tag :type="vulnSeverityType(v.severity)" size="small" effect="dark">{{ v.severity }}</el-tag>
                  <span class="vuln-name">{{ v.name }}</span>
                  <a v-if="v.cve" :href="`https://nvd.nist.gov/vuln/detail/${v.cve}`" target="_blank" rel="noopener" class="mono vuln-cve">{{ v.cve }}</a>
                  <span class="mono cvss" v-if="v.cvss_score">CVSS {{ v.cvss_score }}</span>
                </div>
              </div>
            </el-tab-pane>

            <!-- 端口服务 -->
            <el-tab-pane v-if="detail.ports?.length" :name="'ports'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Connection /></el-icon>
                  {{ t('assets.detail.portsServices') }}
                  <span class="tab-count">{{ detail.ports.length }}</span>
                </span>
              </template>
              <div class="tab-content">
                <el-table :data="detail.ports" size="small" stripe>
                  <el-table-column prop="port" :label="t('table.port')" width="90">
                    <template #default="{ row: p }"><span class="mono">{{ p.port }}/{{ p.proto }}</span></template>
                  </el-table-column>
                  <el-table-column prop="state" :label="t('table.state')" width="80">
                    <template #default="{ row: p }">
                      <el-tag v-if="p.state === 'open'" type="success" size="small">{{ p.state }}</el-tag>
                      <span v-else class="mono">{{ p.state }}</span>
                    </template>
                  </el-table-column>
                  <el-table-column prop="service" :label="t('table.service')" width="100">
                    <template #default="{ row: p }">{{ p.service || '—' }}</template>
                  </el-table-column>
                  <el-table-column prop="product" :label="t('table.product')" min-width="140">
                    <template #default="{ row: p }">
                      <span class="mono">{{ [p.product, p.version].filter(Boolean).join(' ') || '—' }}</span>
                    </template>
                  </el-table-column>
                </el-table>
              </div>
            </el-tab-pane>

            <!-- Web 站点 -->
            <el-tab-pane v-if="detail.web_info?.length" :name="'web'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Monitor /></el-icon>
                  {{ t('assets.detail.webSites') }}
                  <span class="tab-count">{{ detail.web_info.length }}</span>
                </span>
              </template>
              <div class="tab-content web-list">
                <div v-for="(site, i) in detail.web_info" :key="i" class="web-card">
                  <div class="web-head">
                    <a :href="site.url" target="_blank" rel="noopener" class="web-url mono">{{ site.url }}</a>
                    <el-tag v-if="site.status" :type="statusTagType(site.status)" size="small" effect="dark">{{ site.status }}</el-tag>
                  </div>
                  <div class="web-title" v-if="site.title">{{ site.title }}</div>
                  <div class="web-tags" v-if="site.tech?.length">
                    <el-tag v-for="(tech, ti) in site.tech" :key="ti" size="small" type="info" class="tech-tag">
                      {{ typeof tech === 'string' ? tech : tech.name }}
                    </el-tag>
                  </div>
                </div>
              </div>
            </el-tab-pane>

            <!-- 敏感路径 -->
            <el-tab-pane v-if="detail.sensitive?.length" :name="'sensitive'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Lock /></el-icon>
                  {{ t('assets.detail.sensitive') }}
                  <span class="tab-count warn">{{ detail.sensitive.length }}</span>
                </span>
              </template>
              <div class="tab-content">
                <el-table :data="detail.sensitive" size="small" stripe>
                  <el-table-column prop="path" :label="t('table.path')" min-width="200">
                    <template #default="{ row: s }"><span class="mono">{{ s.path }}</span></template>
                  </el-table-column>
                  <el-table-column prop="severity" :label="t('table.severity')" width="90">
                    <template #default="{ row: s }">
                      <el-tag :type="severityType(s.severity)" size="small">{{ s.severity }}</el-tag>
                    </template>
                  </el-table-column>
                  <el-table-column prop="description" :label="t('table.description')" min-width="160">
                    <template #default="{ row: s }">{{ s.description || '—' }}</template>
                  </el-table-column>
                </el-table>
              </div>
            </el-tab-pane>

            <!-- 技术栈 -->
            <el-tab-pane v-if="detail.tech_stack?.length" :name="'tech'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Cpu /></el-icon>
                  {{ t('assets.detail.techStack') }}
                  <span class="tab-count">{{ detail.tech_stack.length }}</span>
                </span>
              </template>
              <div class="tab-content">
                <div class="np-tag-group tech-tags-detail">
                  <el-tag v-for="(tech, i) in detail.tech_stack" :key="i" size="default" type="info">{{ tech }}</el-tag>
                </div>
              </div>
            </el-tab-pane>

            <!-- Banner -->
            <el-tab-pane v-if="detail.banners?.length" :name="'banners'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Document /></el-icon>
                  {{ t('assets.detail.banners') }}
                  <span class="tab-count">{{ detail.banners.length }}</span>
                </span>
              </template>
              <div class="tab-content">
                <div v-for="(b, i) in detail.banners" :key="i" class="banner-row">
                  <span class="mono banner-port">{{ b.port }}</span>
                  <span class="banner-service">{{ b.service || '—' }}</span>
                  <pre class="mono banner-text">{{ b.banner }}</pre>
                </div>
              </div>
            </el-tab-pane>
          </el-tabs>

          <!-- 全空兜底 -->
          <div
            v-if="!detail.ports?.length && !detail.web_info?.length
              && !detail.vulnerabilities?.length && !detail.tech_stack?.length
              && !detail.sensitive?.length && !detail.banners?.length"
            class="np-empty"
          >
            <el-icon :size="28" color="var(--np-text-disabled)"><Grid /></el-icon>
            <p>{{ t('common.noData') }}</p>
          </div>
        </template>
      </div>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { getAssets, getAssetDetail } from '../api/scan'
import type { AssetSummary } from '../types'

const { t } = useI18n()

/** 卡片预览数据：从详情接口抽取用于卡片展示的轻量字段 */
interface CardPreview {
  firstSite?: { url: string; status: number | null; title: string; tech: string[] }
  ports?: { port: number; proto: string }[]
  lastScan?: string
}

/** 行数据：在 AssetSummary 上挂载预取态字段 */
interface AssetRow extends AssetSummary {
  rowKey: string
  _preview?: CardPreview
  _previewed?: boolean
}

const items = ref<AssetRow[]>([])
const loading = ref(false)
const query = ref('')
const sortBy = ref('hostname')

/** 抽屉态 */
const drawerVisible = ref(false)
const detailTab = ref('vulns')
const detailLoading = ref(false)
const detail = ref<any>(null)
const detailError = ref<string>('')
const activeRow = ref<AssetRow | null>(null)
const drawerTitle = computed(() =>
  activeRow.value ? `${activeRow.value.ip}${activeRow.value.hostname && activeRow.value.hostname !== activeRow.value.ip ? ' · ' + activeRow.value.hostname : ''}` : t('assets.title')
)

async function loadData() {
  loading.value = true
  try {
    const res = await getAssets(query.value, sortBy.value)
    items.value = (res.items || []).map(it => ({
      ...it,
      rowKey: `${it.hostname}::${it.ip}`,
      _previewed: false,
    }))
    // 后台并发预取详情（限流，避免瞬间打爆后端）
    prefetchPreviews(items.value)
  } finally {
    loading.value = false
  }
}

/** 限制并发的预取：让卡片逐步显示 web 站点/端口等富信息 */
async function prefetchPreviews(rows: AssetRow[]) {
  const CONCURRENCY = 6
  let cursor = 0
  const worker = async () => {
    while (cursor < rows.length) {
      const idx = cursor++
      const row = rows[idx]
      if (row._previewed) continue
      try {
        const d = await getAssetDetail(row.hostname, row.ip)
        row._preview = extractPreview(d)
      } catch {
        /* 预取失败静默，点击卡片时再正式加载 */
      } finally {
        row._previewed = true
      }
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()))
}

/** 从详情响应抽取卡片展示所需的轻量结构 */
function extractPreview(d: any): CardPreview {
  if (!d) return {}
  const firstSite = (d.web_info?.length
    ? {
        url: d.web_info[0].url,
        status: d.web_info[0].status ?? null,
        title: d.web_info[0].title || '',
        tech: (d.web_info[0].tech || []).map((x: any) => (typeof x === 'string' ? x : x.name)).filter(Boolean),
      }
    : undefined)
  const ports = (d.ports || []).slice(0, 12).map((p: any) => ({ port: p.port, proto: p.proto }))
  const lastScan = d.last_scan || d.updated_at || ''
  return { firstSite, ports, lastScan }
}

/** 点击卡片：打开抽屉并加载完整详情 */
async function openDetail(row: AssetRow) {
  activeRow.value = row
  drawerVisible.value = true
  detail.value = null
  detailError.value = ''
  detailLoading.value = true
  try {
    const d = await getAssetDetail(row.hostname, row.ip)
    detail.value = d || {}
    // 自动选第一个有数据的 Tab
    if (d.vulnerabilities?.length) detailTab.value = 'vulns'
    else if (d.ports?.length) detailTab.value = 'ports'
    else if (d.web_info?.length) detailTab.value = 'web'
    else if (d.sensitive?.length) detailTab.value = 'sensitive'
    else if (d.tech_stack?.length) detailTab.value = 'tech'
    else if (d.banners?.length) detailTab.value = 'banners'
    // 同步补齐预览
    if (!row._previewed) {
      row._preview = extractPreview(d)
      row._previewed = true
    }
  } catch (e: any) {
    detailError.value = e?.message || t('assets.detail.loadError')
  } finally {
    detailLoading.value = false
  }
}

function riskClass(score: number): string {
  if (score >= 70) return 'risk-high'
  if (score >= 40) return 'risk-medium'
  return 'risk-low'
}

/** 卡片左侧色条（按风险着色，强化视觉分级） */
function riskBorderClass(score: number): string {
  if (score >= 70) return 'border-risk-high'
  if (score >= 40) return 'border-risk-medium'
  return 'border-risk-low'
}

function riskLabel(score: number): string {
  if (score >= 70) return t('assets.riskHigh')
  if (score >= 40) return t('assets.riskMedium')
  return t('assets.riskLow')
}

/** HTTP 状态码 → el-tag 类型 */
function statusTagType(status: number) {
  if (status >= 200 && status < 300) return 'success'
  if (status >= 300 && status < 400) return 'warning'
  return 'danger'
}

/** 敏感路径等级 → el-tag 类型 */
function severityType(sev: string) {
  const s = (sev || '').toLowerCase()
  if (s === 'high' || s === 'critical') return 'danger'
  if (s === 'medium') return 'warning'
  return 'info'
}

/** 漏洞等级 → el-tag 类型 */
function vulnSeverityType(sev: string) {
  const s = (sev || '').toLowerCase()
  if (s === 'critical') return 'danger'
  if (s === 'high') return 'danger'
  if (s === 'medium') return 'warning'
  return 'info'
}

onMounted(loadData)
</script>

<style scoped>
.assets {
  max-width: 1400px;
  margin: 0 auto;
}

/* ═══ 风险徽章 ═══ */
.risk-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 4px;
  font-weight: 600;
  font-size: 12px;
  white-space: nowrap;
  flex-shrink: 0;
}
.risk-high {
  background: var(--np-danger-bg);
  color: var(--np-danger);
}
.risk-medium {
  background: var(--np-warning-bg);
  color: var(--np-warning);
}
.risk-low {
  background: var(--np-success-bg);
  color: var(--np-success);
}

/* ═══ 卡片网格 ═══ */
.asset-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
  gap: 16px;
}

.asset-card {
  position: relative;
  background: var(--np-bg-surface);
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-lg);
  padding: 16px;
  cursor: pointer;
  transition: box-shadow 0.2s, border-color 0.2s;
  display: flex;
  flex-direction: column;
  gap: 12px;
  overflow: hidden;
}
/* 左侧风险色条（覆盖左边框） */
.asset-card::before {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 3px;
  background: transparent;
}
.asset-card.border-risk-high::before { background: var(--np-danger); }
.asset-card.border-risk-medium::before { background: var(--np-warning); }
.asset-card.border-risk-low::before { background: var(--np-success); }

.asset-card:hover {
  border-color: var(--np-blue-400);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
}

/* ── 头部行 ── */
.card-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}
.card-id {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}
.card-ip {
  font-family: var(--np-font-mono);
  font-weight: 700;
  font-size: 16px;
  color: var(--np-text-primary);
  word-break: break-all;
  line-height: 1.3;
}
.card-host {
  font-size: 12px;
  color: var(--np-text-muted);
  word-break: break-all;
}

/* ── Web 站点区 ── */
.card-web {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 10px 12px;
  background: var(--np-bg-app);
  border-radius: var(--np-radius-md);
}
.web-line {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.web-ico {
  color: var(--np-blue-500);
  flex-shrink: 0;
}
.web-url {
  font-size: 13px;
  font-weight: 500;
  color: var(--np-blue-500);
  word-break: break-all;
}
.web-url:hover {
  color: var(--np-blue-600);
}
.status-tag {
  flex-shrink: 0;
}
.web-title {
  font-size: 12px;
  color: var(--np-text-muted);
  font-style: italic;
  word-break: break-all;
}
.tech-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}
.tech-tag {
  font-family: var(--np-font-mono);
  font-size: 11px;
}

/* ── 端口区 ── */
.card-ports {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  flex-wrap: wrap;
}
.ports-ico {
  color: var(--np-text-muted);
  flex-shrink: 0;
  margin-top: 1px;
}
.ports-list {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 8px;
  color: var(--np-text-muted);
  font-size: 12px;
}
.port-chip {
  background: var(--np-bg-elevated);
  padding: 1px 6px;
  border-radius: var(--np-radius-sm);
}
.port-more {
  color: var(--np-text-secondary);
  font-weight: 600;
  padding: 1px 2px;
}

/* ── 底部行 ── */
.card-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding-top: 10px;
  border-top: 1px solid var(--np-border);
  font-size: 12px;
  color: var(--np-text-muted);
}
.foot-meta {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

/* ═══ 详情抽屉 ═══ */
.drawer-body {
  min-height: 120px;
}
.drawer-error {
  display: flex;
  align-items: center;
  gap: var(--np-space-2);
  color: var(--np-danger);
  padding: var(--np-space-4) 0;
}

/* 顶部概览数字条 */
.detail-overview {
  display: flex;
  flex-wrap: wrap;
  gap: var(--np-space-5);
  padding-bottom: var(--np-space-3);
  margin-bottom: var(--np-space-4);
  border-bottom: 1px solid var(--np-border);
}
.detail-overview .ov-item {
  display: inline-flex;
  align-items: baseline;
  gap: var(--np-space-1);
  font-size: 13px;
  color: var(--np-text-muted);
}
.detail-overview .ov-item b {
  font-size: 18px;
  font-weight: 700;
  color: var(--np-text-primary);
}

/* 详情网格 */
.detail-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: var(--np-space-5);
}
.detail-section {
  min-width: 0;
}

/* 嵌套小表格 */
.mini-table {
  font-size: 12px;
}

/* Web 站点列表 */
.web-list {
  display: flex;
  flex-direction: column;
  gap: var(--np-space-3);
}
.web-card {
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-md);
  padding: var(--np-space-3);
  background: var(--np-bg-app);
}
.web-head {
  display: flex;
  align-items: center;
  gap: var(--np-space-2);
  flex-wrap: wrap;
}
.web-url {
  font-size: 13px;
  font-weight: 500;
  color: var(--np-blue-500);
  word-break: break-all;
}
.web-url:hover {
  color: var(--np-blue-600);
}
.web-title {
  margin-top: var(--np-space-1);
  font-size: 13px;
  color: var(--np-text-secondary);
}
.web-meta {
  display: flex;
  gap: var(--np-space-3);
  margin-top: var(--np-space-2);
  color: var(--np-text-muted);
  font-size: 12px;
}
.web-meta .meta-item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.web-tags {
  display: flex;
  flex-wrap: wrap;
  gap: var(--np-space-1);
  margin-top: var(--np-space-2);
}

/* 漏洞列表 */
.vuln-list {
  display: flex;
  flex-direction: column;
  gap: var(--np-space-2);
}
.vuln-row {
  display: flex;
  align-items: center;
  gap: var(--np-space-2);
  flex-wrap: wrap;
  padding: var(--np-space-2);
  border-radius: var(--np-radius-sm);
  background: var(--np-danger-bg);
}
.vuln-name {
  font-size: 13px;
  color: var(--np-text-primary);
  flex: 1;
  min-width: 120px;
}
.vuln-cve {
  font-size: 12px;
  color: var(--np-blue-500);
}
.vuln-cve:hover {
  color: var(--np-blue-600);
  text-decoration: underline;
}
.cvss {
  font-size: 12px;
  color: var(--np-text-muted);
}

/* Banner 列表 */
.banner-list {
  display: flex;
  flex-direction: column;
  gap: var(--np-space-2);
}
.banner-row {
  display: grid;
  grid-template-columns: 70px 90px 1fr;
  gap: var(--np-space-2);
  align-items: start;
  padding: var(--np-space-2);
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-sm);
  background: var(--np-bg-app);
}
.banner-port {
  color: var(--np-text-secondary);
  font-weight: 600;
}
.banner-service {
  color: var(--np-text-secondary);
  font-size: 13px;
}
.banner-text {
  margin: 0;
  font-size: 12px;
  color: var(--np-text-muted);
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 120px;
  overflow-y: auto;
}

/* 响应式 */
@media (max-width: 768px) {
  .asset-grid {
    grid-template-columns: 1fr;
  }
  .banner-row {
    grid-template-columns: 1fr;
  }
}

/* ── Tab 样式 ── */
.detail-tabs {
  margin-top: var(--np-space-4);
}

.detail-tabs :deep(.el-tabs__header) {
  margin-bottom: var(--np-space-3);
}

.detail-tabs :deep(.el-tabs__nav-wrap::after) {
  background-color: var(--np-border);
}

.tab-label {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 13px;
}

.tab-count {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 18px;
  height: 18px;
  padding: 0 5px;
  border-radius: 9px;
  background: var(--np-bg-elevated);
  color: var(--np-text-muted);
  font-size: 10px;
  font-weight: 700;
  font-family: var(--np-font-mono);
}

.tab-count.danger {
  background: var(--np-danger-bg);
  color: var(--np-danger);
}

.tab-count.warn {
  background: var(--np-warning-bg);
  color: var(--np-warning);
}

.tab-content {
  min-height: 100px;
}

.tech-tags-detail {
  gap: var(--np-space-2);
}

.tech-tags-detail .el-tag {
  font-size: 13px;
  padding: 4px 12px;
}
</style>
