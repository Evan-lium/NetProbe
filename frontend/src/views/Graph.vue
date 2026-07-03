<template>
  <div class="graph-page">
    <div class="tasks-header">
      <div>
        <h2 class="np-page-title">{{ t('graph.title') }}</h2>
        <span class="np-page-desc">{{ t('graph.desc') }}</span>
      </div>
      <div class="graph-meta" v-if="graphData">
        <el-tag size="small">{{ graphData.nodes.length }} {{ t('graph.nodes') }}</el-tag>
        <el-tag size="small" type="info">{{ graphData.links.length }} {{ t('graph.edges') }}</el-tag>
      </div>
    </div>

    <el-card>
      <div v-if="loading" class="task-loading">
        <div class="np-skeleton" style="height: 500px" />
      </div>
      <v-chart
        v-else-if="graphData && graphData.nodes.length"
        class="graph-chart"
        :option="chartOption"
        autoresize
      />
      <el-empty v-else :description="t('graph.empty')" />
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
import { GraphChart } from 'echarts/charts'
import { TooltipComponent, LegendComponent } from 'echarts/components'
import { getCorrelationGraph } from '../api/scan'

use([CanvasRenderer, GraphChart, TooltipComponent, LegendComponent])

const { t } = useI18n()
const graphData = ref<{ nodes: any[]; links: any[]; categories: any[] } | null>(null)
const loading = ref(true)

const chartOption = computed(() => {
  if (!graphData.value) return {}
  return {
    tooltip: {
      formatter: (p: any) => p.dataType === 'node' ? p.data.name : `${p.data.source} → ${p.data.target}`,
    },
    legend: [{
      data: (graphData.value.categories || []).map(c => c.name),
      bottom: 0,
    }],
    series: [{
      type: 'graph',
      layout: 'force',
      roam: true,
      draggable: true,
      label: { show: true, position: 'right', fontSize: 11 },
      force: { repulsion: 120, edgeLength: 80, gravity: 0.1 },
      categories: graphData.value.categories,
      data: graphData.value.nodes,
      links: graphData.value.links,
      lineStyle: { color: 'source', opacity: 0.4, curveness: 0.1 },
      emphasis: { focus: 'adjacency', lineStyle: { width: 3 } },
    }],
  }
})

async function loadData() {
  loading.value = true
  try {
    graphData.value = await getCorrelationGraph()
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

onMounted(loadData)
</script>

<style scoped>
.graph-page { max-width: 1400px; margin: 0 auto; }
.tasks-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }
.graph-meta { display: flex; gap: 8px; }
.graph-chart { height: 600px; }
</style>
