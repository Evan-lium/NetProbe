<template>
  <div class="settings">
    <div class="np-page-header">
      <span class="np-page-title">{{ t('settings.title') }}</span>
    </div>

    <div class="settings-grid">
      <!-- Layout -->
      <el-card>
        <template #header>
          <div class="np-card-header">
            <el-icon :size="16"><Monitor /></el-icon>
            <span>{{ t('settings.layout') }}</span>
          </div>
        </template>
        <el-radio-group v-model="layout" @change="handleLayoutChange">
          <el-radio-button value="sidebar">{{ t('settings.layoutSidebar') }}</el-radio-button>
          <el-radio-button value="topnav">{{ t('settings.layoutTopNav') }}</el-radio-button>
        </el-radio-group>
        <p class="helper">{{ t('settings.layoutHelp') }}</p>
      </el-card>

      <!-- External Tools -->
      <el-card>
        <template #header>
          <div class="np-card-header">
            <el-icon :size="16"><SetUp /></el-icon>
            <span>{{ t('settings.externalTools') }}</span>
          </div>
        </template>
        <div class="np-table-wrapper">
          <el-table :data="toolList" v-loading="toolsLoading" size="small">
            <el-table-column prop="label" :label="t('settings.tool')" min-width="120" show-overflow-tooltip />
            <el-table-column prop="name" :label="t('settings.command')" min-width="120" show-overflow-tooltip>
              <template #default="{ row }"><span class="mono">{{ row.name }}</span></template>
            </el-table-column>
            <el-table-column :label="t('settings.status')" min-width="100" align="center">
              <template #default="{ row }">
                <el-tag :type="row.available ? 'success' : 'danger'" size="small">{{ row.available ? t('common.available') : t('common.missing') }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column :label="t('settings.capabilities')">
              <template #default="{ row }">
                <el-tag v-for="cap in row.caps" :key="cap" size="small" type="info" style="margin-right:4px">{{ cap }}</el-tag>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-card>

      <!-- API Keys -->
      <el-card class="full-width">
        <template #header>
          <div class="np-card-header">
            <el-icon :size="16"><Key /></el-icon>
            <span>{{ t('settings.apiKeys') }}</span>
          </div>
        </template>
        <el-form label-width="140px">
          <el-form-item :label="t('settings.shodanKey')">
            <el-input v-model="apiKeys.shodan" :placeholder="t('settings.enterKey')" show-password style="max-width:400px" />
          </el-form-item>
          <el-form-item :label="t('settings.fofaEmail')">
            <el-input v-model="apiKeys.fofa_email" :placeholder="t('settings.email')" style="max-width:400px" />
          </el-form-item>
          <el-form-item :label="t('settings.fofaKey')">
            <el-input v-model="apiKeys.fofa_key" :placeholder="t('settings.enterKey')" show-password style="max-width:400px" />
          </el-form-item>
        </el-form>
        <div class="form-actions">
          <el-button type="primary" :loading="saving" @click="saveSettings">
            <el-icon v-if="!saving"><Check /></el-icon>
            <span>{{ saving ? t('common.saving') : t('common.save') }}</span>
          </el-button>
        </div>
      </el-card>

      <!-- 通知渠道 -->
      <el-card class="full-width">
        <template #header>
          <div class="np-card-header">
            <el-icon :size="16"><Bell /></el-icon>
            <span>通知渠道</span>
            <span class="np-card-subtitle">告警消息推送（扫描后自动触发，留空则不启用该渠道）</span>
          </div>
        </template>
        <el-tabs v-model="notifyTab">
          <!-- Webhook -->
          <el-tab-pane label="Webhook" name="webhook">
            <el-form label-width="120px">
              <el-form-item label="Webhook URL">
                <el-input v-model="notify.webhook.url" placeholder="https://your-webhook.com/endpoint" style="max-width:500px" />
              </el-form-item>
            </el-form>
          </el-tab-pane>

          <!-- 钉钉 -->
          <el-tab-pane label="钉钉" name="dingtalk">
            <el-form label-width="120px">
              <el-form-item label="Access Token">
                <el-input v-model="notify.dingtalk.access_token" placeholder="钉钉群机器人的 access_token" style="max-width:500px" />
              </el-form-item>
              <el-form-item label="加签密钥">
                <el-input v-model="notify.dingtalk.secret" placeholder="（可选）启用加签校验" show-password style="max-width:500px" />
              </el-form-item>
              <p class="helper">安全设置需含关键词"NetProbe"或启用加签</p>
            </el-form>
          </el-tab-pane>

          <!-- 企业微信 -->
          <el-tab-pane label="企业微信" name="wecom">
            <el-form label-width="120px">
              <el-form-item label="机器人 Key">
                <el-input v-model="notify.wecom.key" placeholder="企业微信群机器人 webhook 的 key 参数" style="max-width:500px" />
              </el-form-item>
            </el-form>
          </el-tab-pane>

          <!-- 飞书 -->
          <el-tab-pane label="飞书" name="feishu">
            <el-form label-width="120px">
              <el-form-item label="Webhook">
                <el-input v-model="notify.feishu.webhook" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..." style="max-width:500px" />
              </el-form-item>
              <el-form-item label="加签密钥">
                <el-input v-model="notify.feishu.secret" placeholder="（可选）启用签名校验" show-password style="max-width:500px" />
              </el-form-item>
            </el-form>
          </el-tab-pane>

          <!-- Telegram -->
          <el-tab-pane label="Telegram" name="telegram">
            <el-form label-width="120px">
              <el-form-item label="Bot Token">
                <el-input v-model="notify.telegram.bot_token" placeholder="123456:ABC-DEF..." show-password style="max-width:500px" />
              </el-form-item>
              <el-form-item label="Chat ID">
                <el-input v-model="notify.telegram.chat_id" placeholder="目标群/频道/用户 ID" style="max-width:500px" />
              </el-form-item>
            </el-form>
          </el-tab-pane>

          <!-- 邮件 -->
          <el-tab-pane label="邮件" name="email">
            <el-form label-width="120px">
              <el-form-item label="SMTP 主机">
                <el-input v-model="notify.email.smtp_host" placeholder="smtp.qq.com / smtp.gmail.com" style="max-width:300px" />
              </el-form-item>
              <el-form-item label="端口">
                <el-input-number v-model="notify.email.smtp_port" :min="1" :max="65535" style="width:140px" />
                <el-checkbox v-model="notify.email.use_ssl" style="margin-left:16px">SSL（465）</el-checkbox>
              </el-form-item>
              <el-form-item label="账号">
                <el-input v-model="notify.email.username" placeholder="发件邮箱账号" style="max-width:300px" />
              </el-form-item>
              <el-form-item label="密码/授权码">
                <el-input v-model="notify.email.password" placeholder="邮箱密码或授权码" show-password style="max-width:300px" />
              </el-form-item>
              <el-form-item label="收件人">
                <el-input v-model="emailToText" placeholder="多个用逗号分隔" style="max-width:400px" />
              </el-form-item>
            </el-form>
          </el-tab-pane>
        </el-tabs>

        <div class="form-actions">
          <el-button @click="testNotification" :loading="testing">
            <el-icon v-if="!testing"><Promotion /></el-icon>
            <span>{{ testing ? '发送中...' : '发送测试通知' }}</span>
          </el-button>
          <el-button type="primary" :loading="saving" @click="saveNotify">
            <el-icon v-if="!saving"><Check /></el-icon>
            <span>{{ saving ? t('common.saving') : t('common.save') }}</span>
          </el-button>
        </div>
      </el-card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { useAppStore } from '../stores/app'
import { getTools, getSettings, updateSettings } from '../api/scan'
import api from '../api/index'
import type { ToolStatus } from '../types'

const { t } = useI18n()
const appStore = useAppStore()
const layout = ref(appStore.layout)
const toolsLoading = ref(false)
const toolList = ref<(ToolStatus & { name: string })[]>([])
const saving = ref(false)
const testing = ref(false)
const apiKeys = reactive({ shodan: '', fofa_email: '', fofa_key: '' })

/** 通知渠道配置（与后端 settings.json notifications 结构一致） */
const notifyTab = ref('webhook')
const notify = reactive({
  webhook: { url: '', headers: {} },
  dingtalk: { access_token: '', secret: '' },
  wecom: { key: '' },
  feishu: { webhook: '', secret: '' },
  telegram: { bot_token: '', chat_id: '' },
  email: { smtp_host: '', smtp_port: 465, username: '', password: '', from_addr: '', to_addrs: [] as string[], use_ssl: true },
})
/** 收件人输入框（逗号分隔 → 数组） */
const emailToText = ref('')
function syncEmailTo() {
  notify.email.to_addrs = emailToText.value.split(',').map(s => s.trim()).filter(Boolean)
}

function handleLayoutChange(val: any) {
  appStore.setLayout(val as 'sidebar' | 'topnav')
}

async function saveSettings() {
  saving.value = true
  try {
    await updateSettings({ api_keys: { ...apiKeys } })
    ElMessage.success(t('settings.saved'))
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    saving.value = false
  }
}

async function saveNotify() {
  saving.value = true
  try {
    syncEmailTo()
    await updateSettings({ notifications: JSON.parse(JSON.stringify(notify)) })
    ElMessage.success('通知渠道配置已保存')
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    saving.value = false
  }
}

async function testNotification() {
  testing.value = true
  try {
    // 先保存再测试，确保用最新配置
    syncEmailTo()
    await updateSettings({ notifications: JSON.parse(JSON.stringify(notify)) })
    const res: any = await api.post('/settings/test-notification')
    if (res.success) {
      ElMessage.success(`测试通知发送成功（渠道：${res.channel}）`)
    } else {
      ElMessage.error(`发送失败：${res.error || '未知错误'}`)
    }
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail || e.message)
  } finally {
    testing.value = false
  }
}

onMounted(async () => {
  toolsLoading.value = true
  try {
    const [tools, settings] = await Promise.all([getTools(), getSettings()])
    toolList.value = Object.values(tools)
    if (settings.api_keys) Object.assign(apiKeys, settings.api_keys)
    if (settings.notifications) {
      // 合并后端配置到 notify（保留默认结构，覆盖已有值）
      for (const ch of Object.keys(notify)) {
        if (settings.notifications[ch]) {
          Object.assign(notify[ch as keyof typeof notify], settings.notifications[ch])
        }
      }
      emailToText.value = (notify.email.to_addrs || []).join(', ')
    }
  } finally {
    toolsLoading.value = false
  }
})
</script>

<style scoped>
.settings {
  
  
}

.settings-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--np-space-4);
}

.settings-grid .full-width {
  grid-column: 1 / -1;
}

.helper {
  margin-top: var(--np-space-3);
  font-size: 13px;
  color: var(--np-text-muted);
}

.np-card-subtitle {
  margin-left: var(--np-space-2);
  font-size: 12px;
  font-weight: normal;
  color: var(--np-text-muted);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  padding-top: var(--np-space-2);
}

.form-actions .el-button {
  display: flex;
  align-items: center;
  gap: var(--np-space-2);
}

@media (max-width: 768px) {
  .settings-grid {
    grid-template-columns: 1fr;
  }
}
</style>
