<template>
  <div class="stats-page">
    <div class="np-page-header">
      <div>
        <h2 class="np-page-title">{{ t('stats.title') }}</h2>
        <span class="np-page-desc">{{ t('stats.desc') }}</span>
      </div>
    </div>

    <div v-if="loading" class="task-loading">
      <div class="np-skeleton" style="height: 300px" />
    </div>

    <template v-else>
      <!-- 概览数字 -->
      <div class="np-stat-grid">
        <div class="np-stat-card">
          <div class="np-stat-num">{{ statsData.asset_count || assets.length }}</div>
          <div class="np-stat-label">{{ t('stats.totalAssets') }}</div>
        </div>
        <div class="np-stat-card">
          <div class="np-stat-num">{{ totalPorts }}</div>
          <div class="np-stat-label">{{ t('stats.totalPorts') }}</div>
        </div>
        <div class="np-stat-card">
          <div class="np-stat-num">{{ totalWeb }}</div>
          <div class="np-stat-label">{{ t('stats.totalWeb') }}</div>
        </div>
        <div class="np-stat-card">
          <div class="np-stat-num">{{ highRisk }}</div>
          <div class="np-stat-label">{{ t('stats.highRisk') }}</div>
        </div>
      </div>

      <!-- 图表网格 -->
      <div class="chart-grid">
        <el-card class="chart-card">
          <template #header>{{ t('stats.riskDist') }}</template>
          <v-chart class="chart" :option="riskChartOption" autoresize />
        </el-card>
        <el-card class="chart-card">
          <template #header>{{ t('stats.portDist') }}</template>
          <v-chart class="chart" :option="portDistChartOption" autoresize />
        </el-card>
        <el-card class="chart-card">
          <template #header>{{ t('stats.topAssets') }}</template>
          <v-chart class="chart" :option="topAssetsOption" autoresize />
        </el-card>
      </div>

      <!-- 系统指纹库统计 -->
      <el-card class="fp-stats-card" v-if="fpStats">
        <template #header>系统指纹库统计</template>
        <!-- 总览数字 -->
        <div class="fp-overview">
          <div class="fp-overview-item">
            <span class="fp-overview-num">{{ fpStats.fingerprints?.total || 0 }}</span>
            <span class="fp-overview-label">Web 指纹</span>
          </div>
          <div class="fp-overview-item">
            <span class="fp-overview-num">{{ fpStats.sensitive_paths?.total || 0 }}</span>
            <span class="fp-overview-label">敏感路径</span>
          </div>
          <div class="fp-overview-item">
            <span class="fp-overview-num">{{ fpStats.takeover?.total || 0 }}</span>
            <span class="fp-overview-label">接管指纹</span>
          </div>
          <div class="fp-overview-item">
            <span class="fp-overview-num">{{ fpStats.ports?.common || 0 }}</span>
            <span class="fp-overview-label">常用端口</span>
          </div>
          <div class="fp-overview-item">
            <span class="fp-overview-num">{{ fpStats.fingerprints?.with_version || 0 }}</span>
            <span class="fp-overview-label">版本提取</span>
          </div>
        </div>
        <!-- 图表网格 -->
        <div class="fp-chart-grid">
          <div class="fp-chart-item">
            <div class="fp-chart-title">Web 指纹分类</div>
            <v-chart class="fp-chart" :option="fpChartOption" autoresize />
          </div>
          <div class="fp-chart-item">
            <div class="fp-chart-title">敏感路径严重度</div>
            <v-chart class="fp-chart" :option="spChartOption" autoresize />
          </div>
        </div>
      </el-card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import api from '../api/index'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart, BarChart } from 'echarts/charts'
import { TitleComponent, TooltipComponent, LegendComponent, GridComponent } from 'echarts/components'
import { getAssets } from '../api/scan'
import { getStats } from '../api/scan'
import type { AssetSummary } from '../types'

use([CanvasRenderer, PieChart, BarChart, TitleComponent, TooltipComponent, LegendComponent, GridComponent])

const { t } = useI18n()
const assets = ref<AssetSummary[]>([])
const statsData = ref<any>({})
const loading = ref(true)

// 概览数字用后端去重数据（不用前端累加）
const totalPorts = computed(() => statsData.value?.port_count || 0)
const totalWeb = computed(() => statsData.value?.web_count || 0)
const highRisk = computed(() => {
  const sev = statsData.value?.vuln_by_severity || {}
  return (sev.critical || 0) + (sev.high || 0)
})

// 风险分布饼图
const riskChartOption = computed(() => {
  const high = assets.value.filter(a => (a.risk_score || 0) >= 70).length
  const medium = assets.value.filter(a => (a.risk_score || 0) >= 40 && (a.risk_score || 0) < 70).length
  const low = assets.value.filter(a => (a.risk_score || 0) < 40).length
  return {
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0 },
    series: [{
      type: 'pie', radius: ['40%', '70%'],
      data: [
        { value: high, name: t('stats.riskHigh'), itemStyle: { color: '#f53f3f' } },
        { value: medium, name: t('stats.riskMedium'), itemStyle: { color: '#ff9a2e' } },
        { value: low, name: t('stats.riskLow'), itemStyle: { color: '#00b42a' } },
      ],
    }],
  }
})

// 端口数分布柱状图（按端口数分桶）
/** 端口分布 Top 20（从高到低，超过 10 个滚动） */
const portDistChartOption = computed(() => {
  const dist = statsData.value?.port_dist || []
  // 反转让最多的在上面
  const data = [...dist].reverse()
  return {
    tooltip: { trigger: 'axis', formatter: (p: any) => `${p[0].name}<br/>出现次数: ${p[0].value}` },
    grid: { left: '3%', right: '6%', bottom: '3%', top: '3%', containLabel: true },
    xAxis: { type: 'value', minInterval: 1 },
    yAxis: {
      type: 'category',
      data: data.map((d: any) => `${d.port}/${d.proto}`),
      axisLabel: { fontSize: 12 },
    },
    dataZoom: dist.length > 10 ? [{ type: 'slider', yAxisIndex: 0, start: 0, end: 50, width: 12, right: 0 }] : [],
    series: [{
      type: 'bar',
      data: data.map((d: any) => d.count),
      itemStyle: { color: '#3b82f6', borderRadius: [0, 4, 4, 0] },
      label: { show: true, position: 'right', fontSize: 11 },
    }],
  }
})

// 端口最多的 Top 10 资产（过滤掉 0 端口的）
const topAssetsOption = computed(() => {
  const sorted = [...assets.value]
    .filter(a => (a.port_count || 0) > 0)
    .sort((a, b) => (b.port_count || 0) - (a.port_count || 0))
    .slice(0, 10)
  return {
    tooltip: { trigger: 'axis' },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: { type: 'value', minInterval: 1 },
    yAxis: { type: 'category', data: sorted.map(a => a.hostname || a.ip).reverse(), axisLabel: { width: 120, overflow: 'truncate' } },
    series: [{ type: 'bar', data: sorted.map(a => a.port_count || 0).reverse(), itemStyle: { color: '#10b981', borderRadius: [0, 4, 4, 0] } }],
  }
})

async function loadData() {
  loading.value = true
  try {
    const [res, stats] = await Promise.all([getAssets('', 'port_count'), getStats()])
    assets.value = res.items
    statsData.value = stats
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

/** 指纹库统计 */
const fpStats = ref<any>(null)

/** Web 指纹分类环形图 */
const fpChartOption = computed(() => {
  const cats = fpStats.value?.fingerprints?.categories || {}
  const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#14b8a6', '#f97316', '#6366f1', '#84cc16']
  const data = Object.entries(cats)
    .sort((a: any, b: any) => b[1] - a[1])
    .slice(0, 12)
    .map(([name, value]: any, i: number) => ({ name, value, itemStyle: { color: colors[i % colors.length] } }))
  return {
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { type: 'scroll', orient: 'vertical', right: 0, top: 'middle', textStyle: { fontSize: 11 } },
    series: [{
      type: 'pie', radius: ['40%', '70%'], center: ['35%', '50%'],
      data, label: { show: false },
      emphasis: { label: { show: true, fontSize: 13, fontWeight: 600 } },
    }],
  }
})

/** 敏感路径严重度环形图 */
const spChartOption = computed(() => {
  const cats = fpStats.value?.sensitive_paths?.categories || {}
  const sevColors: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#10b981', info: '#3b82f6' }
  const data = Object.entries(cats).map(([name, value]: any) => ({
    name, value, itemStyle: { color: sevColors[name] || '#94a3b8' },
  }))
  return {
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0, textStyle: { fontSize: 11 } },
    series: [{
      type: 'pie', radius: ['40%', '70%'], center: ['50%', '45%'],
      data, label: { show: false },
      emphasis: { label: { show: true, fontSize: 13, fontWeight: 600 } },
    }],
  }
})

async function loadFpStats() {
  try {
    const res: any = await api.get('/stats/fingerprints')
    fpStats.value = res
  } catch { /* 不阻塞 */ }
}

onMounted(async () => {
  await Promise.all([loadData(), loadFpStats()])
})
</script>

<style scoped>
.stats-page {  }
.chart-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 14px; }
.chart-card { min-height: 360px; }
.chart { height: 300px; }

/* 指纹库统计 */
.fp-stats-card { margin-top: 14px; }
.fp-overview {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 12px; margin-bottom: 20px;
}
.fp-overview-item {
  text-align: center; padding: 14px 8px;
  background: var(--np-bg-elevated); border-radius: var(--np-radius-md);
}
.fp-overview-num {
  display: block; font-size: 28px; font-weight: 800;
  color: var(--np-blue-500); font-family: var(--np-font-mono);
}
.fp-overview-label { font-size: 12px; color: var(--np-text-muted); }

.fp-chart-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 14px;
}
.fp-chart-item {
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-md);
  padding: 12px;
}
.fp-chart-title {
  font-size: 13px; font-weight: 600; color: var(--np-text-secondary);
  margin-bottom: 8px;
}
.fp-chart { height: 280px; }

@media (max-width: 768px) {
  .fp-chart-grid { grid-template-columns: 1fr; }
}
</style>
