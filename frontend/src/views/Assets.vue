<template>
  <div class="assets">
    <div class="np-page-header">
      <div>
        <span class="np-page-title">{{ t('assets.title') }}</span>
        <span class="np-page-desc" v-if="items.length">{{ t('assets.assets', { n: items.length }) }}</span>
      </div>
    </div>

    <el-card>
      <div class="np-filter-bar">
        <el-input v-model="query" :placeholder="t('assets.searchPlaceholder')" clearable style="width: 260px" @keyup.enter="loadData">
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <el-select v-model="sortBy" style="width: 160px" @change="loadData">
          <el-option :label="t('assets.sortHostname')" value="hostname" />
          <el-option :label="t('assets.sortPortCount')" value="port_count" />
          <el-option :label="t('assets.sortScanCount')" value="scan_count" />
        </el-select>
        <el-button type="primary" @click="loadData">{{ t('common.search') }}</el-button>
      </div>

      <div class="np-table-wrapper">
        <el-table :data="items" v-loading="loading">
          <el-table-column prop="hostname" :label="t('assets.hostname')" min-width="200">
            <template #default="{ row }"><span style="font-weight:500">{{ row.hostname }}</span></template>
          </el-table-column>
          <el-table-column prop="ip" :label="t('assets.ip')" width="140">
            <template #default="{ row }"><span class="mono">{{ row.ip }}</span></template>
          </el-table-column>
          <el-table-column prop="scan_count" :label="t('assets.scans')" width="80">
            <template #default="{ row }"><span class="mono">{{ row.scan_count }}</span></template>
          </el-table-column>
          <el-table-column prop="port_count" :label="t('assets.ports')" width="80">
            <template #default="{ row }"><span class="mono">{{ row.port_count }}</span></template>
          </el-table-column>
          <el-table-column prop="web_count" :label="t('assets.web')" width="80">
            <template #default="{ row }"><span class="mono">{{ row.web_count }}</span></template>
          </el-table-column>
        </el-table>
      </div>

      <div v-if="!loading && items.length === 0" class="np-empty">
        <el-icon :size="36" color="var(--np-text-disabled)"><Grid /></el-icon>
        <p>{{ t('assets.empty') }}</p>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { getAssets } from '../api/scan'
import type { AssetSummary } from '../types'

const { t } = useI18n()
const items = ref<AssetSummary[]>([])
const loading = ref(false)
const query = ref('')
const sortBy = ref('hostname')

async function loadData() {
  loading.value = true
  try {
    const res = await getAssets(query.value, sortBy.value)
    items.value = res.items
  } finally {
    loading.value = false
  }
}

onMounted(loadData)
</script>

<style scoped>
.assets {
  max-width: 1400px;
  margin: 0 auto;
}
</style>
