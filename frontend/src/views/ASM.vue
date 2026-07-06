<template>
  <div class="asm-page">
    <div class="np-page-header">
      <div>
        <span class="np-page-title">攻击面管理</span>
        <span class="np-page-desc">持续监控 · 自动发现 · 变更追踪</span>
      </div>
      <div class="np-page-actions">
        <router-link to="/schedules">
          <el-button size="small"><el-icon><Setting /></el-icon> 定时任务</el-button>
        </router-link>
        <router-link to="/alerts">
          <el-button size="small"><el-icon><Bell /></el-icon> 告警规则</el-button>
        </router-link>
      </div>
    </div>

    <div v-if="loading" class="task-loading">
      <div class="np-skeleton" style="height: 300px" />
    </div>

    <template v-else-if="data">
      <!-- 监控状态卡片 -->
      <div class="np-stat-grid">
        <div class="np-stat-card">
          <div class="np-stat-num">{{ data.total_assets }}</div>
          <div class="np-stat-label">监控资产</div>
        </div>
        <div class="np-stat-card">
          <div class="np-stat-num">{{ data.total_ports }}</div>
          <div class="np-stat-label">暴露端口</div>
        </div>
        <div class="np-stat-card">
          <div class="np-stat-num">{{ data.monitor_status?.schedule_count || 0 }}</div>
          <div class="np-stat-label">定时任务</div>
        </div>
        <div class="np-stat-card">
          <div class="np-stat-num">{{ data.recent_alerts?.length || 0 }}</div>
          <div class="np-stat-label">最近告警</div>
        </div>
      </div>

      <!-- 监控能力状态 -->
      <el-card class="asm-section">
        <template #header>持续监控状态</template>
        <div class="monitor-grid">
          <div class="monitor-item">
            <el-tag type="success" size="small" effect="dark">运行中</el-tag>
            <span class="monitor-name">CT 证书监控</span>
            <span class="monitor-desc">每天 6:00 拉取 crt.sh 发现新子域</span>
          </div>
          <div class="monitor-item">
            <el-tag type="success" size="small" effect="dark">运行中</el-tag>
            <span class="monitor-name">DNS 变更监控</span>
            <span class="monitor-desc">每天 6:30 对比 A/CNAME 快照</span>
          </div>
          <div class="monitor-item">
            <el-tag :type="data.targets.length ? 'success' : 'info'" size="small" effect="dark">
              {{ data.targets.length ? '运行中' : '未配置' }}
            </el-tag>
            <span class="monitor-name">定时扫描</span>
            <span class="monitor-desc">周期扫描 + 扫描后自动 diff 告警</span>
          </div>
        </div>
      </el-card>

      <div class="asm-chart-grid">
        <!-- 扫描趋势 -->
        <el-card class="asm-chart-card">
          <template #header>扫描趋势（最近 {{ data.scan_trend.length }} 次）</template>
          <v-chart v-if="data.scan_trend.length" class="asm-chart" :option="trendChartOption" autoresize />
          <div v-else class="asm-empty">暂无扫描记录</div>
        </el-card>

        <!-- 资产标签分布 -->
        <el-card class="asm-chart-card">
          <template #header>资产标签分布</template>
          <v-chart v-if="tagChartReady" class="asm-chart" :option="tagChartOption" autoresize />
          <div v-else class="asm-empty">暂无标签数据</div>
        </el-card>
      </div>

      <!-- 监控目标列表 -->
      <el-card class="asm-section">
        <template #header>监控目标</template>
        <el-table v-if="data.targets.length" :data="data.targets" size="small" stripe>
          <el-table-column prop="name" label="任务名" min-width="140" show-overflow-tooltip />
          <el-table-column prop="target" label="目标" min-width="160" show-overflow-tooltip />
          <el-table-column prop="cron" label="Cron" min-width="120" show-overflow-tooltip />
          <el-table-column label="状态" min-width="80" align="center">
            <template #default="{ row }">
              <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="上次执行" min-width="160">
            <template #default="{ row }">{{ formatTime(row.last_run) }}</template>
          </el-table-column>
        </el-table>
        <div v-else class="asm-empty">
          <router-link to="/schedules"><el-button type="primary" size="small">去创建定时扫描</el-button></router-link>
        </div>
      </el-card>

      <!-- 最近告警 -->
      <el-card class="asm-section">
        <template #header>最近告警事件</template>
        <el-timeline v-if="data.recent_alerts.length">
          <el-timeline-item v-for="a in data.recent_alerts" :key="a.id" :timestamp="formatTime(a.triggered_at)" type="danger">
            {{ a.summary }}
          </el-timeline-item>
        </el-timeline>
        <div v-else class="asm-empty">暂无告警</div>
      </el-card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import api from '../api/index'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { LineChart, PieChart } from 'echarts/charts'
import { TooltipComponent, GridComponent, LegendComponent } from 'echarts/components'

use([CanvasRenderer, LineChart, PieChart, TooltipComponent, GridComponent, LegendComponent])

const loading = ref(true)
const data = ref<any>(null)

const tagChartReady = computed(() => {
  const stats = data.value?.tag_stats || {}
  return Object.keys(stats).length > 0
})

const trendChartOption = computed(() => {
  const trend = data.value?.scan_trend || []
  return {
    tooltip: { trigger: 'axis' },
    legend: { bottom: 0, data: ['主机', '端口', '网站'] },
    grid: { left: '3%', right: '4%', bottom: '12%', containLabel: true },
    xAxis: { type: 'category', data: trend.map((s: any) => s.started_at?.slice(5, 16) || ''), axisLabel: { fontSize: 10, rotate: 30 } },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      { name: '主机', type: 'line', smooth: true, data: trend.map((s: any) => s.host_count), itemStyle: { color: '#3b82f6' } },
      { name: '端口', type: 'line', smooth: true, data: trend.map((s: any) => s.port_count), itemStyle: { color: '#10b981' } },
      { name: '网站', type: 'line', smooth: true, data: trend.map((s: any) => s.web_count), itemStyle: { color: '#f59e0b' } },
    ],
  }
})

const tagChartOption = computed(() => {
  const stats = data.value?.tag_stats || {}
  const colors = ['#ef4444', '#f59e0b', '#94a3b8', '#10b981', '#3b82f6', '#8b5cf6', '#ec4899']
  const tagData = Object.entries(stats).map(([name, value]: any, i: number) => ({
    name, value, itemStyle: { color: colors[i % colors.length] },
  }))
  return {
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0, textStyle: { fontSize: 11 } },
    series: [{ type: 'pie', radius: ['40%', '70%'], center: ['50%', '45%'], data: tagData, label: { show: false } }],
  }
})

function formatTime(iso: string) {
  if (!iso) return '—'
  const d = new Date(iso)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

async function loadData() {
  loading.value = true
  try {
    const res: any = await api.get('/asm/overview')
    data.value = res
  } finally {
    loading.value = false
  }
}

onMounted(loadData)
</script>

<style scoped>
.asm-section { margin-top: 14px; }
.monitor-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }
.monitor-item { display: flex; flex-direction: column; gap: 4px; padding: 14px; background: var(--np-bg-elevated); border-radius: var(--np-radius-md); }
.monitor-name { font-size: 14px; font-weight: 600; color: var(--np-text-primary); }
.monitor-desc { font-size: 12px; color: var(--np-text-muted); }
.asm-chart-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; margin-top: 14px; }
.asm-chart-card { min-height: 340px; }
.asm-chart { height: 280px; }
.asm-empty { padding: 32px; text-align: center; color: var(--np-text-muted); font-size: 13px; }
@media (max-width: 768px) { .monitor-grid { grid-template-columns: 1fr; } .asm-chart-grid { grid-template-columns: 1fr; } }
</style>
