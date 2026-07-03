<template>
  <div class="timeline-page">
    <div class="np-page-header">
      <div>
        <h2 class="np-page-title">{{ t('timeline.title') }}</h2>
        <span class="np-page-desc">{{ t('timeline.desc') }}</span>
      </div>
    </div>

    <el-card class="select-card">
      <div class="select-bar">
        <el-select v-model="target" filterable :placeholder="t('timeline.selectTarget')" style="width: 320px" @change="loadData">
          <el-option v-for="s in targets" :key="s.base_domain" :label="s.base_domain || s.target_raw" :value="s.base_domain || s.target_raw" />
        </el-select>
      </div>
    </el-card>

    <div v-if="loading" class="task-loading">
      <div class="np-skeleton" style="height: 400px" />
    </div>

    <template v-else-if="timelineData && timelineData.points.length">
      <!-- 概览统计 -->
      <div class="np-stat-grid">
        <div class="np-stat-card"><div class="np-stat-num">{{ timelineData.summary.total_scans }}</div><div class="np-stat-label">{{ t('stats.totalAssets') }}</div></div>
        <div class="np-stat-card np-stat-card--success"><div class="np-stat-num">{{ timelineData.summary.total_added }}</div><div class="np-stat-label">{{ t('timeline.added') }}</div></div>
        <div class="np-stat-card np-stat-card--danger"><div class="np-stat-num">{{ timelineData.summary.total_removed }}</div><div class="np-stat-label">{{ t('timeline.removed') }}</div></div>
        <div class="np-stat-card np-stat-card--warning"><div class="np-stat-num">{{ timelineData.summary.total_changed }}</div><div class="np-stat-label">{{ t('timeline.changed') }}</div></div>
      </div>

      <el-card>
        <template #header>{{ t('timeline.assetTrend') }}</template>
        <v-chart class="trend-chart" :option="trendOption" autoresize />
      </el-card>
    </template>

    <el-card v-else-if="target">
      <el-empty :description="t('timeline.empty')" />
    </el-card>
    <el-card v-else>
      <el-empty :description="t('timeline.empty')" />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { LineChart } from 'echarts/charts'
import { TitleComponent, TooltipComponent, LegendComponent, GridComponent } from 'echarts/components'
import { getHistory, getTimeline } from '../api/scan'

use([CanvasRenderer, LineChart, TitleComponent, TooltipComponent, LegendComponent, GridComponent])

const { t } = useI18n()
const targets = ref<any[]>([])
const target = ref('')
const timelineData = ref<any>(null)
const loading = ref(false)

const trendOption = computed(() => {
  if (!timelineData.value?.points) return {}
  const points = timelineData.value.points
  const dates = points.map((p: any) => {
    const d = new Date(p.started_at)
    return `${d.getMonth() + 1}/${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`
  })
  return {
    tooltip: { trigger: 'axis' },
    legend: { bottom: 0, data: [t('timeline.added'), t('timeline.removed'), t('timeline.changed')] },
    grid: { left: '3%', right: '4%', bottom: '12%', containLabel: true },
    xAxis: { type: 'category', data: dates, boundaryGap: false },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      { name: t('timeline.added'), type: 'line', smooth: true, data: points.map((p: any) => p.added), itemStyle: { color: '#67c23a' }, areaStyle: { opacity: 0.1 } },
      { name: t('timeline.removed'), type: 'line', smooth: true, data: points.map((p: any) => p.removed), itemStyle: { color: '#f56c6c' }, areaStyle: { opacity: 0.1 } },
      { name: t('timeline.changed'), type: 'line', smooth: true, data: points.map((p: any) => p.changed), itemStyle: { color: '#e6a23c' }, areaStyle: { opacity: 0.1 } },
    ],
  }
})

async function loadTargets() {
  try {
    const res = await getHistory({ per_page: 100, status: 'done' })
    // 去重 base_domain
    const seen = new Set<string>()
    targets.value = res.items.filter((s: any) => {
      const key = s.base_domain || s.target_raw
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
    if (targets.value.length) {
      target.value = targets.value[0].base_domain || targets.value[0].target_raw
      loadData()
    }
  } catch (e: any) {
    ElMessage.error(e.message)
  }
}

async function loadData() {
  if (!target.value) return
  loading.value = true
  timelineData.value = null
  try {
    timelineData.value = await getTimeline(target.value)
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

onMounted(loadTargets)
</script>

<style scoped>
.timeline-page { max-width: 1400px; margin: 0 auto; }
.select-card { margin-bottom: 16px; }
.trend-chart { height: 400px; }
</style>
