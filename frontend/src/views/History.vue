<template>
  <div class="history">
    <div class="np-page-header">
      <div>
        <span class="np-page-title">{{ t('history.title') }}</span>
        <span class="np-page-desc" v-if="total">{{ t('history.scans', { n: total }) }}</span>
      </div>
    </div>

    <el-card>
      <div class="np-filter-bar">
        <el-input v-model="query" :placeholder="t('history.searchPlaceholder')" clearable style="width: 260px" @clear="loadData" @keyup.enter="loadData">
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <el-select v-model="statusFilter" :placeholder="t('history.status')" clearable style="width: 120px" @change="loadData">
          <el-option :label="t('history.statusDone')" value="done" />
          <el-option :label="t('history.statusError')" value="error" />
          <el-option :label="t('history.statusRunning')" value="running" />
        </el-select>
        <el-button type="primary" @click="loadData">{{ t('common.search') }}</el-button>
      </div>

      <div class="np-table-wrapper">
        <el-table :data="items" v-loading="loading" style="width: 100%">
          <el-table-column :label="t('history.target')" min-width="200" show-overflow-tooltip>
            <template #default="{ row }">
              <router-link :to="`/history/${row.scan_id}`" class="link">
                {{ row.base_domain || row.target_raw }}
              </router-link>
              <div class="row-sub mono" v-if="row.target_raw !== row.base_domain">{{ row.target_raw }}</div>
            </template>
          </el-table-column>
          <el-table-column prop="status" :label="t('history.status')" width="100">
            <template #default="{ row }">
              <el-tag :type="statusType(row.status)" size="small">{{ row.status }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="host_count" :label="t('history.hosts')" width="70">
            <template #default="{ row }"><span class="mono">{{ row.host_count }}</span></template>
          </el-table-column>
          <el-table-column prop="port_count" :label="t('history.ports')" width="70">
            <template #default="{ row }"><span class="mono">{{ row.port_count }}</span></template>
          </el-table-column>
          <el-table-column prop="web_count" :label="t('history.web')" width="60">
            <template #default="{ row }"><span class="mono">{{ row.web_count }}</span></template>
          </el-table-column>
          <el-table-column prop="duration_secs" :label="t('history.duration')" width="90">
            <template #default="{ row }">
              <span class="mono">{{ row.duration_secs != null ? `${row.duration_secs}s` : '-' }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('history.date')" width="170">
            <template #default="{ row }">{{ formatDate(row.started_at) }}</template>
          </el-table-column>
          <el-table-column label="" width="60" fixed="right">
            <template #default="{ row }">
              <el-popconfirm :title="t('history.deleteConfirm')" @confirm="handleDelete(row.scan_id)">
                <template #reference>
                  <el-button type="danger" text size="small">{{ t('common.delete') }}</el-button>
                </template>
              </el-popconfirm>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <div class="pagination" v-if="total > 0">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="perPage"
          :total="total"
          :page-sizes="[5, 10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next, jumper"
         
          background
          @current-change="loadData"
          @size-change="onSizeChange"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { getHistory, deleteHistory } from '../api/scan'
import { usePageSize } from '../composables/usePageSetting'
import type { HistoryItem } from '../types'

const { t } = useI18n()
const items = ref<HistoryItem[]>([])
const total = ref(0)
const page = ref(1)
const perPage = usePageSize('history')
function onSizeChange() { page.value = 1; loadData() }
const query = ref('')
const statusFilter = ref('')
const loading = ref(false)

function statusType(status: string) {
  if (status === 'done') return 'success'
  if (status === 'error') return 'danger'
  return 'warning'
}

function formatDate(d: string) {
  return new Date(d).toLocaleString('zh-CN')
}

async function loadData() {
  loading.value = true
  try {
    const res = await getHistory({ page: page.value, per_page: perPage.value, q: query.value, status: statusFilter.value })
    items.value = res.items
    total.value = res.total
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

async function handleDelete(scanId: string) {
  try {
    await deleteHistory(scanId)
    ElMessage.success(t('history.deleted'))
    loadData()
  } catch (e: any) {
    ElMessage.error(e.message)
  }
}

onMounted(loadData)
</script>

<style scoped>
.history {
  
  
}

.link {
  color: var(--np-blue-400);
  font-weight: 500;
  text-decoration: none;
  transition: color var(--np-transition);
}

.link:hover {
  color: var(--np-blue-500);
  text-decoration: none;
}

.row-sub {
  font-size: 11px;
  color: var(--np-text-muted);
  margin-top: 2px;
  max-width: 400px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.pagination {
  margin-top: var(--np-space-4);
  display: flex;
  justify-content: flex-end;
}
</style>
