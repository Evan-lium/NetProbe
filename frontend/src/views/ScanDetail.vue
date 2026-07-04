<template>
  <div class="scan-detail" v-loading="loading">
    <div v-if="result" class="content">
      <!-- Header -->
      <div class="np-page-header">
        <div>
          <span class="np-page-title">{{ result.base_domain }}</span>
          <span class="np-page-desc mono">
            {{ t('scanDetail.summary', { hosts: detail?.host_count ?? result.hosts.length, ports: detail?.port_count ?? totalPorts, web: detail?.web_count ?? totalWeb }) }}
            <span v-if="detail?.duration_secs">{{ t('scanDetail.duration', { secs: detail.duration_secs }) }}</span>
          </span>
        </div>
        <div class="np-page-actions">
          <el-dropdown @command="handleDownload">
            <el-button type="primary">
              <el-icon><Download /></el-icon>
              {{ t('common.export') }}
              <el-icon class="el-icon--right"><ArrowDown /></el-icon>
            </el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="txt">{{ t('export.txt') }}</el-dropdown-item>
                <el-dropdown-item command="csv">{{ t('export.csv') }}</el-dropdown-item>
                <el-dropdown-item command="json">{{ t('export.json') }}</el-dropdown-item>
                <el-dropdown-item command="pdf">{{ t('export.pdf') }}</el-dropdown-item>
                <el-dropdown-item command="html">{{ t('export.html') }}</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </div>

      <!-- Two-column layout -->
      <div class="detail-layout">
        <!-- LEFT: Stats panel -->
        <aside class="stats-panel">
          <!-- Overview -->
          <div class="stats-card">
            <h3 class="stats-title">{{ t('scanDetail.overview') }}</h3>
            <div class="overview-grid">
              <div class="overview-item">
                <span class="overview-value">{{ result.hosts.length }}</span>
                <span class="overview-label">{{ t('scanResult.hosts') }}</span>
              </div>
              <div class="overview-item">
                <span class="overview-value">{{ totalPorts }}</span>
                <span class="overview-label">{{ t('scanDetail.openPorts') }}</span>
              </div>
              <div class="overview-item">
                <span class="overview-value">{{ totalWeb }}</span>
                <span class="overview-label">{{ t('scanResult.webSites') }}</span>
              </div>
              <div class="overview-item">
                <span class="overview-value">{{ totalSensitive }}</span>
                <span class="overview-label">{{ t('scanResult.sensitivePaths') }}</span>
              </div>
            </div>
          </div>

          <!-- Port distribution -->
          <div class="stats-card" v-if="portDist.length">
            <h3 class="stats-title">{{ t('scanDetail.portDist') }}</h3>
            <div class="dist-list">
              <div class="dist-row" v-for="item in portDist" :key="item.label">
                <span class="dist-label mono">{{ item.label }}</span>
                <div class="dist-bar-wrap">
                  <div class="dist-bar" :style="{ width: item.pct + '%' }" />
                </div>
                <span class="dist-count mono">{{ item.count }}</span>
              </div>
            </div>
          </div>

          <!-- Service distribution -->
          <div class="stats-card" v-if="serviceDist.length">
            <h3 class="stats-title">{{ t('scanDetail.serviceDist') }}</h3>
            <div class="dist-list">
              <div class="dist-row" v-for="item in serviceDist" :key="item.label">
                <span class="dist-label">{{ item.label }}</span>
                <div class="dist-bar-wrap">
                  <div class="dist-bar" :style="{ width: item.pct + '%', background: 'var(--np-success)' }" />
                </div>
                <span class="dist-count mono">{{ item.count }}</span>
              </div>
            </div>
          </div>

          <!-- HTTP status -->
          <div class="stats-card" v-if="httpStatusDist.length">
            <h3 class="stats-title">{{ t('scanDetail.httpStatus') }}</h3>
            <div class="dist-list">
              <div class="dist-row" v-for="item in httpStatusDist" :key="item.label">
                <span class="dist-label mono">{{ item.label }}</span>
                <div class="dist-bar-wrap">
                  <div class="dist-bar" :style="{ width: item.pct + '%', background: statusColor(item.label) }" />
                </div>
                <span class="dist-count mono">{{ item.count }}</span>
              </div>
            </div>
          </div>

          <!-- Host list -->
          <div class="stats-card">
            <h3 class="stats-title">{{ t('scanDetail.hostList') }}</h3>
            <div class="host-list">
              <div class="host-row" v-for="(host, i) in result.hosts" :key="i">
                <div class="host-meta">
                  <span class="host-name">{{ host.hostname || host.ip }}</span>
                  <span class="mono host-ip" v-if="host.hostname && host.ip">{{ host.ip }}</span>
                </div>
                <div class="host-ports mono" v-if="host.ports?.length">
                  {{ host.ports.map(p => p.port).join(', ') }}
                </div>
                <span class="host-ports mono empty" v-else>{{ t('scanDetail.noPorts') }}</span>
              </div>
            </div>
          </div>
        </aside>

        <!-- RIGHT: Web site cards -->
        <main class="sites-panel">
          <div v-if="!allWebInfo.length" class="np-empty">
            <el-icon :size="36" color="var(--np-text-disabled)"><Monitor /></el-icon>
            <p>{{ t('scanDetail.noWebSites') }}</p>
          </div>

          <div v-for="(site, idx) in allWebInfo" :key="idx" class="site-card">
            <!-- URL + status -->
            <div class="site-header">
              <a :href="site.url" target="_blank" rel="noopener" class="site-url">{{ site.url }}</a>
              <el-tag v-if="site.status" :type="statusTagType(site.status)" size="small" effect="dark">
                {{ site.status }}
              </el-tag>
            </div>

            <!-- Title -->
            <div class="site-title" v-if="site.title">{{ site.title }}</div>

            <!-- Meta row: port, SSL, redirect -->
            <div class="site-meta">
              <span class="meta-item" v-if="site.port">
                <el-icon :size="13"><Connection /></el-icon>
                {{ site.port }}
              </span>
              <span class="meta-item" v-if="site.ssl">
                <el-icon :size="13"><Lock /></el-icon>
                {{ site.ssl.protocol || 'SSL' }}
                <el-tag v-if="site.ssl.expired" type="danger" size="small">{{ t('table.expired') || 'expired' }}</el-tag>
              </span>
              <span class="meta-item redirect" v-if="site.redirect">
                <el-icon :size="13"><Right /></el-icon>
                {{ site.redirect }}
              </span>
            </div>

            <!-- Tech fingerprints -->
            <div class="site-section" v-if="site.tech?.length">
              <div class="section-label">{{ t('table.tech') }}</div>
              <div class="tech-tags">
                <el-tag v-for="tech in site.tech" :key="tech.name" size="small" type="info" class="tech-tag">
                  {{ tech.name }}{{ tech.version ? ' ' + tech.version : '' }}
                </el-tag>
              </div>
            </div>

            <!-- Ports & services (from same host) -->
            <div class="site-section" v-if="site._hostPorts?.length">
              <div class="section-label">{{ t('scanDetail.portsServices') }}</div>
              <div class="mini-table">
                <div class="mini-row" v-for="p in site._hostPorts" :key="p.port">
                  <span class="mono">{{ p.port }}/{{ p.proto }}</span>
                  <span>{{ p.service }}</span>
                  <span class="mono version">{{ p.product }} {{ p.version }}</span>
                </div>
              </div>
            </div>

            <!-- Vulnerabilities (nuclei) -->
            <div class="site-section" v-if="site._vulns?.length">
              <div class="section-label danger">
                {{ t('scanDetail.vulnerabilities') }}
                <span class="section-badge danger">{{ site._vulns.length }}</span>
              </div>
              <div class="mini-table">
                <div class="mini-row vulnerable" v-for="(v, i) in site._vulns" :key="i">
                  <el-tag :type="vulnSeverityType(v.severity)" size="small" effect="dark">{{ v.severity }}</el-tag>
                  <span class="vuln-name">{{ v.name }}</span>
                  <a v-if="v.cve" :href="`https://nvd.nist.gov/vuln/detail/${v.cve}`" target="_blank" class="mono vuln-cve">{{ v.cve }}</a>
                  <span class="mono cvss" v-if="v.cvss_score">CVSS {{ v.cvss_score }}</span>
                </div>
              </div>
            </div>

            <!-- Sensitive paths -->
            <div class="site-section" v-if="site._sensitive?.length">
              <div class="section-label warn">
                {{ t('scanDetail.sensitivePaths') }}
                <span class="section-badge">{{ site._sensitive.length }}</span>
              </div>
              <div class="mini-table">
                <div class="mini-row sensitive" v-for="s in site._sensitive" :key="s.path">
                  <span class="mono path">{{ s.path }}</span>
                  <el-tag :type="severityType(s.severity)" size="small">{{ s.severity }}</el-tag>
                  <span class="mono" v-if="s.status_code">{{ s.status_code }}</span>
                </div>
              </div>
            </div>

            <!-- JS findings -->
            <div class="site-section" v-if="site._jsFindings?.length">
              <div class="section-label">{{ t('scanDetail.jsAnalysis') }}</div>
              <div class="mini-table">
                <div class="mini-row" v-for="j in site._jsFindings" :key="j.js_url">
                  <span class="mono js-file">{{ j.js_url }}</span>
                  <span class="mono" v-if="j.api_endpoints?.length">{{ j.api_endpoints.length }} {{ t('scanDetail.apis') }}</span>
                  <el-tag v-if="j.secrets?.length" type="danger" size="small">{{ j.secrets.length }} {{ t('scanDetail.secrets') }}</el-tag>
                </div>
              </div>
            </div>

            <!-- Banners -->
            <div class="site-section" v-if="site._banners?.length">
              <div class="section-label">{{ t('scanResult.banners') }}</div>
              <div class="mini-table">
                <div class="mini-row" v-for="b in site._banners" :key="b.port">
                  <span class="mono">{{ b.port }}</span>
                  <span>{{ b.service }}</span>
                  <span class="mono banner-text">{{ b.banner }}</span>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { getResult, getHistoryDetail, getDownloadUrl } from '../api/scan'
import type { ScanResult, Host, WebInfo } from '../types'

const { t } = useI18n()
const route = useRoute()
const loading = ref(true)
const result = ref<ScanResult | null>(null)
const detail = ref<any>(null)

// ── Aggregated stats ──────────────────────────────────────

const totalPorts = computed(() =>
  result.value?.hosts.reduce((s, h) => s + (h.ports?.length || 0), 0) || 0
)
const totalWeb = computed(() =>
  result.value?.hosts.reduce((s, h) => s + (h.web_info?.length || 0), 0) || 0
)
const totalSensitive = computed(() =>
  result.value?.hosts.reduce((s, h) => s + (h.sensitive?.length || 0), 0) || 0
)

interface DistItem { label: string; count: number; pct: number }

function makeDist(hosts: Host[], extract: (h: Host) => string[]): DistItem[] {
  const counts: Record<string, number> = {}
  for (const h of hosts) {
    for (const label of extract(h)) {
      counts[label] = (counts[label] || 0) + 1
    }
  }
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1])
  const max = sorted.length ? sorted[0][1] : 1
  return sorted.map(([label, count]) => ({ label, count, pct: (count / max) * 100 }))
}

const portDist = computed(() => {
  if (!result.value) return []
  return makeDist(result.value.hosts, h =>
    (h.ports || []).filter(p => p.state === 'open').map(p => `${p.port}/${p.proto}`)
  )
})

const serviceDist = computed(() => {
  if (!result.value) return []
  return makeDist(result.value.hosts, h =>
    (h.ports || []).filter(p => p.state === 'open' && p.service).map(p => p.service)
  )
})

const httpStatusDist = computed(() => {
  if (!result.value) return []
  return makeDist(result.value.hosts, h =>
    (h.web_info || []).filter(w => w.status).map(w => String(w.status))
  )
})

// ── Web info with host context ────────────────────────────

interface SiteInfo extends WebInfo {
  _hostPorts: Host['ports']
  _sensitive: Host['sensitive']
  _jsFindings: Host['js_findings']
  _banners: Host['banners']
  _vulns: Host['vulnerabilities']
}

const allWebInfo = computed<SiteInfo[]>(() => {
  if (!result.value) return []
  const sites: SiteInfo[] = []
  for (const host of result.value.hosts) {
    for (const web of (host.web_info || [])) {
      sites.push({
        ...web,
        _hostPorts: host.ports || [],
        _sensitive: host.sensitive || [],
        _jsFindings: host.js_findings || [],
        _banners: host.banners || [],
        _vulns: host.vulnerabilities || [],
      })
    }
  }
  return sites
})

// ── Helpers ───────────────────────────────────────────────

function statusTagType(status: number) {
  if (status >= 200 && status < 300) return 'success'
  if (status >= 300 && status < 400) return 'warning'
  return 'danger'
}

function statusColor(statusStr: string) {
  const code = parseInt(statusStr, 10)
  if (code >= 200 && code < 300) return 'var(--np-success)'
  if (code >= 300 && code < 400) return 'var(--np-warning, #e6a23c)'
  return 'var(--np-danger, #f56c6c)'
}

function severityType(sev: string) {
  if (sev === 'high' || sev === 'critical') return 'danger'
  if (sev === 'medium') return 'warning'
  return 'info'
}

function vulnSeverityType(sev: string) {
  if (sev === 'critical') return 'danger'
  if (sev === 'high') return 'danger'
  if (sev === 'medium') return 'warning'
  return 'info'
}

function handleDownload(fmt: string) {
  window.open(getDownloadUrl(route.params.id as string, fmt), '_blank')
}

onMounted(async () => {
  const id = route.params.id as string
  try {
    const [r, d] = await Promise.all([getResult(id), getHistoryDetail(id)])
    result.value = r
    detail.value = d
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.scan-detail {
  
  
}

/* ── Layout ──────────────────────────────────────────── */
.detail-layout {
  display: flex;
  gap: var(--np-space-5);
  align-items: flex-start;
}

/* ── LEFT: Stats Panel ───────────────────────────────── */
.stats-panel {
  width: 300px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  gap: var(--np-space-3);
  position: sticky;
  top: 0;
  max-height: calc(100vh - 120px);
  overflow-y: auto;
}

.stats-card {
  background: var(--np-bg-surface);
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-lg);
  padding: var(--np-space-4);
}

.stats-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--np-text-secondary);
  margin: 0 0 var(--np-space-3);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

/* Overview grid */
.overview-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--np-space-3);
}

.overview-item {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.overview-value {
  font-size: 22px;
  font-weight: 700;
  color: var(--np-text-primary);
  font-family: var(--np-font-mono);
  line-height: 1.2;
}

.overview-label {
  font-size: 11px;
  color: var(--np-text-muted);
}

/* Distribution bars */
.dist-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.dist-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.dist-label {
  font-size: 12px;
  color: var(--np-text-secondary);
  min-width: 70px;
  flex-shrink: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.dist-bar-wrap {
  flex: 1;
  height: 6px;
  background: var(--np-bg-app);
  border-radius: 3px;
  overflow: hidden;
}

.dist-bar {
  height: 100%;
  background: var(--np-blue-500);
  border-radius: 3px;
  min-width: 2px;
  transition: width 300ms ease;
}

.dist-count {
  font-size: 12px;
  color: var(--np-text-muted);
  min-width: 24px;
  text-align: right;
}

/* Host list */
.host-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.host-row {
  padding: 8px 0;
  border-top: 1px solid var(--np-border);
}

.host-row:first-child {
  border-top: none;
  padding-top: 0;
}

.host-meta {
  display: flex;
  align-items: center;
  gap: 8px;
}

.host-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--np-text-primary);
}

.host-ip {
  font-size: 11px;
  color: var(--np-text-muted);
}

.host-ports {
  font-size: 11px;
  color: var(--np-text-secondary);
  margin-top: 2px;
}

.host-ports.empty {
  color: var(--np-text-disabled);
  font-style: italic;
}

/* ── RIGHT: Sites Panel ──────────────────────────────── */
.sites-panel {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: var(--np-space-3);
}

.site-card {
  background: var(--np-bg-surface);
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-lg);
  padding: var(--np-space-4) var(--np-space-5);
}

.site-header {
  display: flex;
  align-items: center;
  gap: var(--np-space-3);
  margin-bottom: 6px;
}

.site-url {
  font-size: 14px;
  font-weight: 600;
  color: var(--np-blue-400);
  text-decoration: none;
  word-break: break-all;
}

.site-url:hover {
  color: var(--np-blue-300);
}

.site-title {
  font-size: 13px;
  color: var(--np-text-secondary);
  margin-bottom: 8px;
}

.site-meta {
  display: flex;
  align-items: center;
  gap: var(--np-space-3);
  flex-wrap: wrap;
  margin-bottom: 10px;
}

.meta-item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
  color: var(--np-text-muted);
}

.meta-item.redirect {
  color: var(--np-warning, #e6a23c);
  font-size: 11px;
  max-width: 300px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Site sections */
.site-section {
  margin-top: 10px;
  padding-top: 10px;
  border-top: 1px solid var(--np-border);
}

.section-label {
  font-size: 11px;
  font-weight: 600;
  color: var(--np-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  margin-bottom: 6px;
  display: flex;
  align-items: center;
  gap: 6px;
}

.section-label.warn {
  color: var(--np-warning, #e6a23c);
}

.section-label.danger {
  color: var(--np-danger, #f53f3f);
}

.section-badge.danger {
  background: var(--np-danger-bg, rgba(245,63,63,0.12));
  color: var(--np-danger, #f53f3f);
}

.section-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 18px;
  height: 18px;
  padding: 0 5px;
  border-radius: 9px;
  background: rgba(230, 162, 60, 0.15);
  font-size: 10px;
  font-weight: 700;
}

/* Tech tags */
.tech-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.tech-tag {
  font-size: 12px;
}

/* Mini table */
.mini-table {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.mini-row {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 12px;
  color: var(--np-text-secondary);
  padding: 3px 0;
}

.mini-row .version {
  color: var(--np-text-muted);
  margin-left: auto;
}

.mini-row .path {
  color: var(--np-blue-400);
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mini-row .js-file {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mini-row .banner-text {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--np-text-muted);
}

.mini-row.sensitive {
  padding: 4px 0;
}

.mini-row.vulnerable {
  padding: 5px 0;
  border-bottom: 1px solid var(--np-border, #e5e6eb);
  gap: var(--np-space-2, 8px);
}
.mini-row.vulnerable:last-child {
  border-bottom: none;
}
.vuln-name {
  flex: 1;
  font-size: 13px;
  color: var(--np-text-primary);
}
.vuln-cve {
  font-size: 12px;
  color: var(--np-blue-500, #165dff);
  text-decoration: none;
}
.vuln-cve:hover {
  text-decoration: underline;
}
.cvss {
  font-size: 11px;
  color: var(--np-text-muted, #86909c);
  background: var(--np-bg-elevated, #f0f2f5);
  padding: 1px 6px;
  border-radius: 3px;
}

/* ═══ Responsive ═══════════════════════════════════════ */
@media (max-width: 1024px) {
  .detail-layout {
    flex-direction: column;
  }

  .stats-panel {
    width: 100%;
    position: static;
    max-height: none;
    flex-direction: row;
    flex-wrap: wrap;
  }

  .stats-card {
    flex: 1;
    min-width: 200px;
  }
}

@media (max-width: 640px) {
  .stats-panel {
    flex-direction: column;
  }

  .stats-card {
    min-width: 0;
  }
}
</style>
