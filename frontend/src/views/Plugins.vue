<template>
  <div class="plugins-page">
    <div class="np-page-header">
      <div>
        <h2 class="np-page-title">插件管理</h2>
        <span class="np-page-desc">{{ plugins.length }} 个已注册插件</span>
      </div>
    </div>

    <el-card v-loading="loading">
      <!-- 按分类分组 -->
      <div v-for="cat in categories" :key="cat.key" class="plugin-category">
        <div class="category-header">
          <span class="category-icon">{{ cat.icon }}</span>
          <span class="category-name">{{ cat.label }}</span>
          <el-tag size="small" type="info">{{ getPluginsByCategory(cat.key).length }}</el-tag>
        </div>
        <div class="plugin-grid">
          <div
            v-for="p in getPluginsByCategory(cat.key)"
            :key="p.name"
            class="plugin-card"
            :class="{ disabled: !p.enabled }"
          >
            <div class="plugin-head">
              <span class="plugin-icon">{{ p.icon }}</span>
              <div class="plugin-info">
                <div class="plugin-name">
                  {{ p.display_name }}
                  <el-tag v-if="p.is_builtin" size="small" type="info" effect="plain">内置</el-tag>
                </div>
                <div class="plugin-desc">{{ p.description }}</div>
              </div>
              <el-switch
                v-model="p.enabled"
                :disabled="!p.is_available || p.stage === '_engine_managed'"
                @change="togglePlugin(p)"
                size="small"
              />
            </div>
            <div class="plugin-meta">
              <el-tag size="small" effect="plain">{{ stageLabel(p.stage) }}</el-tag>
              <el-tag v-if="!p.is_available" size="small" type="danger" effect="plain">未就绪</el-tag>
              <el-tag v-if="p.stage === '_engine_managed'" size="small" type="warning" effect="plain">引擎管理</el-tag>
            </div>
          </div>
        </div>
      </div>

      <el-empty v-if="!plugins.length && !loading" description="无插件" />
    </el-card>

    <!-- 插件开发说明 -->
    <el-card class="dev-info-card">
      <template #header>
        <div class="np-card-header">
          <el-icon :size="16"><InfoFilled /></el-icon>
          插件开发指南
        </div>
      </template>
      <div class="dev-info">
        <p>将 <code>.py</code> 文件放入 <code>data/plugins/</code> 目录，继承 <code>Plugin</code> 基类即可自动注册：</p>
        <pre class="code-block">from netprobe.plugins.base import Plugin

class MyPlugin(Plugin):
    name = 'my_plugin'
    display_name = '我的检测插件'
    description = '自定义安全检测'
    category = 'vuln'
    stage = 'vuln'
    icon = '🔬'
    is_builtin = False

    def run(self, hosts, options, emit=None):
        # 检测逻辑...
        return findings_count</pre>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../api/index'

interface PluginInfo {
  name: string
  display_name: string
  description: string
  category: string
  stage: string
  icon: string
  is_builtin: boolean
  is_available: boolean
  enabled: boolean
}

const plugins = ref<PluginInfo[]>([])
const loading = ref(false)

const categories = [
  { key: 'vuln', label: '漏洞检测', icon: '🔴' },
  { key: 'recon', label: '信息收集', icon: '🔍' },
  { key: 'info', label: '信息识别', icon: 'ℹ️' },
]

function getPluginsByCategory(cat: string) {
  return plugins.value.filter(p => p.category === cat)
}

function stageLabel(stage: string): string {
  const labels: Record<string, string> = {
    vuln: '漏洞阶段',
    web: 'Web阶段',
    sensitive: '敏感路径阶段',
    takeover: '接管检测阶段',
    dir_brute: '目录爆破',
    _engine_managed: '引擎管理',
  }
  return labels[stage] || stage
}

async function loadPlugins() {
  loading.value = true
  try {
    const res: any = await api.get('/plugins')
    plugins.value = res.items || []
  } catch (e: any) {
    ElMessage.error('加载失败: ' + (e.message || e))
  } finally {
    loading.value = false
  }
}

async function togglePlugin(p: PluginInfo) {
  try {
    await api.patch(`/plugins/${p.name}/toggle`, { enabled: p.enabled })
    ElMessage.success(`${p.display_name} 已${p.enabled ? '启用' : '禁用'}`)
  } catch (e: any) {
    p.enabled = !p.enabled  // 回滚
    ElMessage.error('操作失败: ' + (e.message || e))
  }
}

onMounted(loadPlugins)
</script>

<style scoped>
.plugins-page {}

.plugin-category {
  margin-bottom: var(--np-space-5);
}

.category-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: var(--np-space-3);
  font-size: 15px;
  font-weight: 600;
  color: var(--np-text-primary);
}

.category-icon {
  font-size: 18px;
}

.plugin-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
  gap: var(--np-space-3);
}

.plugin-card {
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-md);
  padding: var(--np-space-3);
  background: var(--np-bg-elevated);
  transition: border-color var(--np-transition), opacity var(--np-transition);
}

.plugin-card:hover {
  border-color: var(--np-blue-400);
}

.plugin-card.disabled {
  opacity: 0.55;
}

.plugin-head {
  display: flex;
  align-items: flex-start;
  gap: 10px;
}

.plugin-icon {
  font-size: 24px;
  flex-shrink: 0;
  margin-top: 2px;
}

.plugin-info {
  flex: 1;
  min-width: 0;
}

.plugin-name {
  font-size: 14px;
  font-weight: 600;
  color: var(--np-text-primary);
  display: flex;
  align-items: center;
  gap: 6px;
}

.plugin-desc {
  font-size: 12px;
  color: var(--np-text-muted);
  margin-top: 2px;
  line-height: 1.4;
}

.plugin-meta {
  display: flex;
  gap: 4px;
  margin-top: 8px;
}

.dev-info-card {
  margin-top: var(--np-space-4);
}

.dev-info {
  font-size: 13px;
  color: var(--np-text-secondary);
  line-height: 1.6;
}

.code-block {
  background: var(--np-bg-app);
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-md);
  padding: 12px 16px;
  font-family: var(--np-font-mono);
  font-size: 12px;
  overflow-x: auto;
  margin-top: 8px;
}
</style>
