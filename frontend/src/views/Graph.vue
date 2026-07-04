<template>
  <div class="graph-page">
    <div class="np-page-header">
      <div>
        <h2 class="np-page-title">{{ t('graph.title') }}</h2>
        <span class="np-page-desc">{{ t('graph.desc') }}</span>
      </div>
      <div class="graph-controls">
        <el-tag size="small" v-if="graphData">{{ graphData.nodes.length }} {{ t('graph.nodes') }}</el-tag>
        <el-tag size="small" type="info" v-if="graphData">{{ graphData.links.length }} {{ t('graph.edges') }}</el-tag>
        <el-radio-group v-model="layout" size="small">
          <el-radio-button value="tree">{{ t('graph.layoutTree') }}</el-radio-button>
          <el-radio-button value="force">{{ t('graph.layoutForce') }}</el-radio-button>
        </el-radio-group>
      </div>
    </div>

    <el-card>
      <div v-if="loading" class="task-loading">
        <div class="np-skeleton" style="height: 560px" />
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
import { GraphChart, TreeChart } from 'echarts/charts'
import { TooltipComponent, LegendComponent, TitleComponent } from 'echarts/components'
import { getCorrelationGraph } from '../api/scan'

use([CanvasRenderer, GraphChart, TreeChart, TooltipComponent, LegendComponent, TitleComponent])

const { t } = useI18n()
const graphData = ref<{ nodes: any[]; links: any[]; categories: any[] } | null>(null)
const loading = ref(true)
const layout = ref<'tree' | 'force'>('tree')

// 节点颜色（按 category）
const NODE_COLORS = ['#165dff', '#00b42a', '#ff7d00', '#722ed1', '#f53f3f']
const CATEGORY_NAMES = ['host', 'ip', 'cert', 'tech', 'favicon']

/**
 * 把扁平 nodes+links 转成树形结构。
 * 以 IP 节点为根，host 为子节点，关联维度(cert/tech/favicon)为叶子。
 */
function buildTreeData(nodes: any[], links: any[]) {
  // 找根节点（IP 节点优先，否则取第一个非 host 节点）
  const ipNodes = nodes.filter(n => CATEGORY_NAMES[n.category] === 'ip')
  const rootNodes = ipNodes.length ? ipNodes : nodes.filter(n => CATEGORY_NAMES[n.category] !== 'host')
  if (!rootNodes.length) {
    // 如果只有 host 节点，取第一个做根
    if (nodes.length) rootNodes.push(nodes[0])
    else return { name: 'empty', children: [] }
  }

  // 构建邻接表
  const adj: Record<string, string[]> = {}
  for (const link of links) {
    if (!adj[link.source]) adj[link.source] = []
    if (!adj[link.target]) adj[link.target] = []
    adj[link.source].push(link.target)
    adj[link.target].push(link.source)
  }

  const nodeMap: Record<string, any> = {}
  for (const n of nodes) nodeMap[n.id] = n

  const visited = new Set<string>()

  function buildNode(nodeId: string): any {
    if (visited.has(nodeId)) return null
    visited.add(nodeId)
    const node = nodeMap[nodeId]
    if (!node) return null

    const catName = CATEGORY_NAMES[node.category] || 'host'
    const result: any = {
      name: node.name,
      itemStyle: { color: NODE_COLORS[node.category] || NODE_COLORS[0] },
      symbolSize: node.symbolSize || 20,
      _category: catName,
    }

    const children = (adj[nodeId] || [])
      .map(childId => buildNode(childId))
      .filter(Boolean)

    if (children.length) result.children = children
    return result
  }

  // 如果有多个根，用一个虚拟根
  if (rootNodes.length === 1) {
    return buildNode(rootNodes[0].id)
  }
  return {
    name: 'Assets',
    itemStyle: { color: '#86909c' },
    symbolSize: 30,
    children: rootNodes.map(r => buildNode(r.id)).filter(Boolean),
  }
}

const chartOption = computed(() => {
  if (!graphData.value) return {}

  if (layout.value === 'tree') {
    // ── 树形布局（清晰层级）──
    const treeData = buildTreeData(graphData.value.nodes, graphData.value.links)
    return {
      tooltip: { trigger: 'item', formatter: (p: any) => p.data.name },
      series: [{
        type: 'tree',
        data: [treeData],
        top: '5%',
        left: '10%',
        bottom: '5%',
        right: '20%',
        symbolSize: 12,
        orient: 'LR',          // 左右展开（横向树）
        label: {
          position: 'left',
          verticalAlign: 'middle',
          align: 'right',
          fontSize: 12,
          color: '#1d2129',
        },
        leaves: {
          label: {
            position: 'right',
            verticalAlign: 'middle',
            align: 'left',
          },
        },
        emphasis: { focus: 'descendant' },
        expandAndCollapse: true,
        animationDuration: 300,
        animationDurationUpdate: 300,
        lineStyle: { color: '#c9cdd4', width: 1 },
        itemStyle: { borderColor: '#fff', borderWidth: 1 },
      }],
    }
  }

  // ── 力导向布局（优化参数，大间距防重叠）──
  const nodeColors = graphData.value.nodes.map(n => NODE_COLORS[n.category] || NODE_COLORS[0])
  return {
    tooltip: {
      formatter: (p: any) => p.dataType === 'node' ? p.data.name : `${p.data.source} → ${p.data.target}`,
    },
    legend: [{
      data: (graphData.value.categories || []).map(c => c.name),
      bottom: 0,
      textStyle: { color: '#4e5969' },
    }],
    series: [{
      type: 'graph',
      layout: 'force',
      roam: true,
      draggable: true,
      label: {
        show: true,
        position: 'right',
        fontSize: 11,
        color: '#1d2129',
        formatter: (p: any) => {
          const name = p.data.name || ''
          return name.length > 20 ? name.slice(0, 18) + '..' : name
        },
      },
      force: {
        repulsion: 400,         // 大间距防重叠（原 120 太小）
        edgeLength: [60, 160],   // 边长度范围（弹性）
        gravity: 0.05,          // 小引力让节点散开
        layoutAnimation: true,
      },
      scaleLimit: { min: 0.3, max: 3 },  // 缩放限制
      categories: graphData.value.categories,
      data: graphData.value.nodes.map((n, i) => ({
        ...n,
        itemStyle: { color: nodeColors[i], borderColor: '#fff', borderWidth: 1 },
        label: { show: n.symbolSize >= 15 },  // 小节点不显示标签防重叠
      })),
      links: graphData.value.links,
      lineStyle: { color: '#c9cdd4', opacity: 0.5, curveness: 0.15, width: 1 },
      emphasis: {
        focus: 'adjacency',
        lineStyle: { width: 3, color: '#165dff', opacity: 1 },
        label: { show: true, fontSize: 13, fontWeight: 600 },
      },
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
.graph-page {  }
.graph-controls { display: flex; gap: 8px; align-items: center; }
.graph-chart { height: 600px; }
</style>
