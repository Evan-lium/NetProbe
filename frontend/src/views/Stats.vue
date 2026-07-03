<template>
  <div class="stats-page">
    <div class="tasks-header">
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
      <div class="overview-grid">
        <div class="overview-item">
          <div class="overview-num">{{ assets.length }}</div>
          <div class="overview-label">{{ t('stats.totalAssets') }}</div>
        </div>
        <div class="overview-item">
          <div class="overview-num">{{ totalPorts }}</div>
          <div class="overview-label">{{ t('stats.totalPorts') }}</div>
        </div>
        <div class="overview-item">
          <div class="overview-num">{{ totalWeb }}</div>
          <div class="overview-label">{{ t('stats.totalWeb') }}</div>
        </div>
        <div class="overview-item">
          <div class="overview-num">{{ highRisk }}</div>
          <div class="overview-label">{{ t('stats.highRisk') }}</div>
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
          <v-chart class="chart" :option="portChartOption" autoresize />
        </el-card>
        <el-card class="chart-card">
          <template #header>{{ t('stats.topAssets') }}</template>
          <v-chart class="chart" :option="topAssetsOption" autoresize />
        </el-card>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart, BarChart } from 'echarts/charts'
import { TitleComponent, TooltipComponent, LegendComponent, GridComponent } from 'echarts/components'
import { getAssets } from '../api/scan'
import type { AssetSummary } from '../types'

use([CanvasRenderer, PieChart, BarChart, TitleComponent, TooltipComponent, LegendComponent, GridComponent])

const { t } = useI18n()
const assets = ref<AssetSummary[]>([])
const loading = ref(true)

const totalPorts = computed(() => assets.value.reduce((s, a) => s + (a.port_count || 0), 0))
const totalWeb = computed(() => assets.value.reduce((s, a) => s + (a.web_count || 0), 0))
const highRisk = computed(() => assets.value.filter(a => (a.risk_score || 0) >= 70).length)

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
        { value: high, name: t('stats.riskHigh'), itemStyle: { color: '#f56c6c' } },
        { value: medium, name: t('stats.riskMedium'), itemStyle: { color: '#e6a23c' } },
        { value: low, name: t('stats.riskLow'), itemStyle: { color: '#67c23a' } },
      ],
    }],
  }
})

// 端口数分布柱状图（按端口数分桶）
const portChartOption = computed(() => {
  const buckets: Record<string, number> = {}
  const labels: Record<string, string> = {
    '0': t('stats.bucket_0'),
    '1-2': t('stats.bucket_1_2'),
    '3-5': t('stats.bucket_3_5'),
    '6-10': t('stats.bucket_6_10'),
    '10+': t('stats.bucket_10_plus'),
  }
  for (const a of assets.value) {
    const pc = a.port_count || 0
    const bucket = pc === 0 ? '0' : pc <= 2 ? '1-2' : pc <= 5 ? '3-5' : pc <= 10 ? '6-10' : '10+'
    buckets[bucket] = (buckets[bucket] || 0) + 1
  }
  const order = ['0', '1-2', '3-5', '6-10', '10+']
  return {
    tooltip: { trigger: 'axis' },
    xAxis: { type: 'category', data: order.map(k => labels[k]) },
    yAxis: { type: 'value', minInterval: 1 },
    series: [{ type: 'bar', data: order.map(k => buckets[k] || 0), itemStyle: { color: '#409eff' } }],
  }
})

// 端口最多的 Top 10 资产
const topAssetsOption = computed(() => {
  const sorted = [...assets.value].sort((a, b) => (b.port_count || 0) - (a.port_count || 0)).slice(0, 10)
  return {
    tooltip: { trigger: 'axis' },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: { type: 'value', minInterval: 1 },
    yAxis: { type: 'category', data: sorted.map(a => a.hostname || a.ip).reverse(), axisLabel: { width: 120, overflow: 'truncate' } },
    series: [{ type: 'bar', data: sorted.map(a => a.port_count || 0).reverse(), itemStyle: { color: '#67c23a' } }],
  }
})

async function loadData() {
  loading.value = true
  try {
    const res = await getAssets('', 'port_count')
    assets.value = res.items
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

onMounted(loadData)
</script>

<style scoped>
.stats-page { max-width: 1400px; margin: 0 auto; }
.tasks-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }
.overview-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
.overview-item { padding: 16px; border-radius: 8px; text-align: center; background: var(--el-fill-color-light); }
.overview-num { font-size: 28px; font-weight: 600; line-height: 1.2; }
.overview-label { font-size: 12px; color: var(--el-text-color-secondary); margin-top: 4px; }
.chart-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 14px; }
.chart-card { min-height: 360px; }
.chart { height: 300px; }
</style>
