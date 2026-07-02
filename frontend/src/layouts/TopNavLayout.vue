<template>
  <el-container class="admin-layout" direction="vertical">
    <!-- Top header bar -->
    <header class="admin-header">
      <div class="header-left">
        <div class="brand-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 2L2 7l10 5 10-5-10-5z"/>
            <path d="M2 17l10 5 10-5"/>
            <path d="M2 12l10 5 10-5"/>
          </svg>
        </div>
        <span class="brand-text">{{ t('brand') }}</span>
        <div class="header-divider" />
        <nav class="top-nav">
          <router-link
            v-for="item in navItems"
            :key="item.path"
            :to="item.path"
            class="nav-item"
            :class="{ active: isActive(item.path) }"
          >
            <el-icon :size="16"><component :is="item.icon" /></el-icon>
            <span>{{ t(item.labelKey) }}</span>
          </router-link>
        </nav>
      </div>
      <div class="header-right">
        <button class="lang-toggle" @click="toggleLang">
          <el-icon :size="14"><Switch /></el-icon>
          <span>{{ locale === 'zh-CN' ? t('lang.en') : t('lang.zh') }}</span>
        </button>
        <div class="header-badge">
          <span class="status-dot" />
          <span class="status-text">v3.0</span>
        </div>
      </div>
    </header>

    <!-- Breadcrumb bar -->
    <div class="breadcrumb-bar">
      <div class="breadcrumb">
        <span class="breadcrumb-item" v-for="(crumb, i) in breadcrumbs" :key="i">
          <router-link v-if="crumb.path && i < breadcrumbs.length - 1" :to="crumb.path">{{ crumb.label }}</router-link>
          <span v-else>{{ crumb.label }}</span>
          <el-icon v-if="i < breadcrumbs.length - 1" :size="12" class="breadcrumb-sep"><ArrowRight /></el-icon>
        </span>
      </div>
    </div>

    <!-- Content -->
    <el-main class="admin-content">
      <router-view />
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'

const { t, locale } = useI18n()
const route = useRoute()

const navItems = [
  { path: '/', icon: 'Odometer', labelKey: 'nav.dashboard' },
  { path: '/tasks', icon: 'List', labelKey: 'nav.tasks' },
  { path: '/assets', icon: 'Grid', labelKey: 'nav.assets' },
  { path: '/settings', icon: 'Setting', labelKey: 'nav.settings' },
]

function isActive(path: string) {
  if (path === '/') return route.path === '/'
  return route.path.startsWith(path)
}

function toggleLang() {
  locale.value = locale.value === 'zh-CN' ? 'en' : 'zh-CN'
  localStorage.setItem('netprobe_lang', locale.value)
}

const breadcrumbs = computed(() => {
  const crumbs: { label: string; path?: string }[] = [{ label: t('brand'), path: '/' }]
  if (route.path === '/') {
    crumbs.push({ label: t('breadcrumb.dashboard') })
  } else if (route.path === '/tasks') {
    crumbs.push({ label: t('breadcrumb.tasks') })
  } else if (route.path.startsWith('/tasks/')) {
    crumbs.push({ label: t('breadcrumb.tasks'), path: '/tasks' })
    crumbs.push({ label: t('breadcrumb.detail') })
  } else if (route.path.startsWith('/scan/')) {
    crumbs.push({ label: t('breadcrumb.dashboard'), path: '/' })
    crumbs.push({ label: t('breadcrumb.liveScan') })
  } else if (route.path === '/assets') {
    crumbs.push({ label: t('breadcrumb.assets') })
  } else if (route.path === '/settings') {
    crumbs.push({ label: t('breadcrumb.settings') })
  }
  return crumbs
})
</script>

<style scoped>
.admin-layout {
  height: 100vh;
  overflow: hidden;
}

/* ── Top Header ────────────────────────────────────────────── */
.admin-header {
  height: var(--np-header-height);
  background: var(--np-bg-layout);
  border-bottom: 1px solid var(--np-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
  flex-shrink: 0;
  z-index: var(--np-z-header);
}

.header-left {
  display: flex;
  align-items: center;
  gap: 16px;
  min-width: 0;
}

.brand-icon {
  width: 32px;
  height: 32px;
  background: var(--np-blue-600);
  color: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--np-radius-md);
  flex-shrink: 0;
}

.brand-text {
  font-size: 16px;
  font-weight: 700;
  color: var(--np-text-primary);
  letter-spacing: -0.02em;
  white-space: nowrap;
}

.header-divider {
  width: 1px;
  height: 24px;
  background: var(--np-border);
  flex-shrink: 0;
}

.top-nav {
  display: flex;
  gap: 4px;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 14px;
  border-radius: var(--np-radius-md);
  color: var(--np-text-secondary);
  text-decoration: none;
  font-size: 13px;
  font-weight: 500;
  transition: all var(--np-transition);
  white-space: nowrap;
}

.nav-item:hover {
  background: var(--np-bg-surface);
  color: var(--np-text-primary);
  text-decoration: none;
}

.nav-item.active {
  background: rgba(37, 99, 235, 0.1);
  color: var(--np-blue-400);
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.lang-toggle {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 4px 10px;
  background: transparent;
  border: none;
  color: var(--np-text-muted);
  cursor: pointer;
  border-radius: var(--np-radius-md);
  font-size: 12px;
  font-weight: 500;
  transition: all var(--np-transition);
}

.lang-toggle:hover {
  background: var(--np-bg-surface);
  color: var(--np-text-primary);
}

.header-badge {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  background: var(--np-bg-surface);
  border-radius: 20px;
  font-size: 12px;
  color: var(--np-text-muted);
}

.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--np-success);
}

.status-text {
  font-family: var(--np-font-mono);
  font-size: 11px;
}

/* ── Breadcrumb Bar ────────────────────────────────────────── */
.breadcrumb-bar {
  background: var(--np-bg-layout);
  border-bottom: 1px solid var(--np-border);
  padding: 0 24px;
  height: 36px;
  display: flex;
  align-items: center;
  flex-shrink: 0;
}

.breadcrumb {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
}

.breadcrumb-item {
  display: flex;
  align-items: center;
  gap: 6px;
}

.breadcrumb-item a {
  color: var(--np-text-muted);
  text-decoration: none;
  transition: color var(--np-transition);
}

.breadcrumb-item a:hover {
  color: var(--np-blue-400);
}

.breadcrumb-item > span {
  color: var(--np-text-secondary);
  font-weight: 500;
}

.breadcrumb-sep {
  color: var(--np-text-disabled);
}

/* ── Content ───────────────────────────────────────────────── */
.admin-content {
  background: var(--np-bg-app);
  overflow-y: auto;
  padding: 20px 24px;
  flex: 1;
}

/* ═══ Responsive ═════════════════════════════════════════════ */
@media (max-width: 768px) {
  .admin-header {
    padding: 0 16px;
  }

  .header-divider,
  .brand-text {
    display: none;
  }

  .nav-item span {
    display: none;
  }

  .nav-item {
    padding: 8px;
  }

  .lang-toggle span {
    display: none;
  }

  .breadcrumb-bar {
    padding: 0 16px;
  }

  .admin-content {
    padding: 16px;
  }
}
</style>
