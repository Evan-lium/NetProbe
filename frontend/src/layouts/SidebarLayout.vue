<template>
  <el-container class="admin-layout">
    <!-- Mobile overlay -->
    <div
      v-if="drawerOpen"
      class="sidebar-overlay"
      @click="drawerOpen = false"
    />

    <!-- Sidebar -->
    <aside
      class="admin-sidebar"
      :class="{ collapsed, 'drawer-open': drawerOpen }"
      :style="{ width: sidebarWidth }"
    >
      <div class="sidebar-brand">
        <div class="brand-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 2L2 7l10 5 10-5-10-5z"/>
            <path d="M2 17l10 5 10-5"/>
            <path d="M2 12l10 5 10-5"/>
          </svg>
        </div>
        <transition name="fade">
          <span v-if="!collapsed" class="brand-text">{{ t('brand') }}</span>
        </transition>
      </div>

      <nav class="sidebar-nav">
        <router-link
          v-for="item in visibleNavItems"
          :key="item.path"
          :to="item.path"
          class="nav-item"
          :class="{ active: isActive(item.path) }"
          @click="drawerOpen = false"
        >
          <el-icon :size="18"><component :is="item.icon" /></el-icon>
          <transition name="fade">
            <span v-if="!collapsed" class="nav-label">{{ t(item.labelKey) }}</span>
          </transition>
        </router-link>
      </nav>

      <div class="sidebar-footer" :class="{ 'footer-collapsed': collapsed }">
        <button
          class="lang-toggle"
          @click="toggleLang"
          :title="locale === 'zh-CN' ? 'Switch to English' : '切换到中文'"
        >
          <el-icon :size="14"><Switch /></el-icon>
          <transition name="fade">
            <span v-if="!collapsed">{{ locale === 'zh-CN' ? t('lang.en') : t('lang.zh') }}</span>
          </transition>
        </button>
        <button
          class="collapse-toggle"
          @click="toggleCollapse"
          :aria-label="collapsed ? t('common.expand') : t('common.collapse')"
        >
          <el-icon :size="16">
            <DArrowLeft v-if="!collapsed" />
            <DArrowRight v-else />
          </el-icon>
        </button>
      </div>
    </aside>

    <!-- Main area -->
    <el-container class="admin-main-wrapper">
      <!-- Top header bar -->
      <header class="admin-header">
        <div class="header-left">
          <button class="mobile-toggle" @click="drawerOpen = !drawerOpen" :aria-label="t('common.menu')">
            <el-icon :size="20"><Fold v-if="drawerOpen" /><Expand v-else /></el-icon>
          </button>
          <div class="breadcrumb">
            <span class="breadcrumb-item" v-for="(crumb, i) in breadcrumbs" :key="i">
              <router-link v-if="crumb.path && i < breadcrumbs.length - 1" :to="crumb.path">{{ crumb.label }}</router-link>
              <span v-else>{{ crumb.label }}</span>
              <el-icon v-if="i < breadcrumbs.length - 1" :size="12" class="breadcrumb-sep"><ArrowRight /></el-icon>
            </span>
          </div>
        </div>
        <div class="header-right">
          <div class="header-badge">
            <span class="status-dot" />
            <span class="status-text">v3.0</span>
          </div>
          <el-dropdown @command="onUserCommand" trigger="click">
            <span class="user-info">
              <el-icon><UserFilled /></el-icon>
              {{ authStore.user?.username || 'admin' }}
              <el-icon :size="12"><ArrowDown /></el-icon>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="changePwd">修改密码</el-dropdown-item>
                <el-dropdown-item command="logout" divided>退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </header>

      <!-- Content area -->
      <el-main class="admin-content">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessageBox, ElMessage } from 'element-plus'
import { useAuthStore } from '../stores/auth'

const { t, locale } = useI18n()
const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()
const collapsed = ref(false)
const drawerOpen = ref(false)

const navItems = [
  { path: '/', icon: 'Odometer', labelKey: 'nav.dashboard' },
  { path: '/tasks', icon: 'List', labelKey: 'nav.tasks' },
  { path: '/schedules', icon: 'Timer', labelKey: 'nav.schedules' },
  { path: '/assets', icon: 'Grid', labelKey: 'nav.assets' },
  { path: '/correlations', icon: 'Share', labelKey: 'nav.correlations' },
  { path: '/stats', icon: 'DataLine', labelKey: 'nav.stats' },
  { path: '/graph', icon: 'Connection', labelKey: 'nav.graph' },
  { path: '/alerts', icon: 'Bell', labelKey: 'nav.alerts' },
  { path: '/asm', icon: 'Aim', labelKey: 'nav.asm' },
  { path: '/users', icon: 'UserFilled', labelKey: 'nav.users', adminOnly: true },
  { path: '/settings', icon: 'Setting', labelKey: 'nav.settings' },
]

/** 菜单过滤：非管理员不显示 adminOnly 项 */
const visibleNavItems = computed(() =>
  navItems.filter(item => !item.adminOnly || authStore.user?.is_admin)
)

const sidebarWidth = computed(() => collapsed.value ? 'var(--np-sidebar-collapsed)' : 'var(--np-sidebar-width)')

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
  } else if (route.path === '/schedules') {
    crumbs.push({ label: t('breadcrumb.schedules') })
  } else if (route.path === '/diff') {
    crumbs.push({ label: t('breadcrumb.diff') })
  } else if (route.path === '/correlations') {
    crumbs.push({ label: t('breadcrumb.correlations') })
  } else if (route.path === '/stats') {
    crumbs.push({ label: t('breadcrumb.stats') })
  } else if (route.path === '/graph') {
    crumbs.push({ label: t('breadcrumb.graph') })
  } else if (route.path === '/alerts') {
    crumbs.push({ label: t('breadcrumb.alerts') })
  } else if (route.path === '/assets') {
    crumbs.push({ label: t('breadcrumb.assets') })
  } else if (route.path === '/settings') {
    crumbs.push({ label: t('breadcrumb.settings') })
  }
  return crumbs
})

async function onUserCommand(cmd: string) {
  if (cmd === 'logout') {
    authStore.logout()
    router.push('/login')
  } else if (cmd === 'changePwd') {
    let newPwd: string
    let oldPwd: string
    try {
      const res1 = await ElMessageBox.prompt('请输入新密码', '修改密码', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        inputType: 'password',
        inputPlaceholder: '新密码（至少 6 位）',
      })
      newPwd = res1.value
      if (!newPwd || newPwd.length < 6) {
        ElMessage.warning('密码至少 6 位')
        return
      }
      const res2 = await ElMessageBox.prompt('请输入当前密码', '验证身份', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        inputType: 'password',
      })
      oldPwd = res2.value
    } catch {
      // 用户点了取消/关闭，不做任何提示
      return
    }
    try {
      await authStore.changePassword(oldPwd!, newPwd!)
      ElMessage.success('密码修改成功')
    } catch (e: any) {
      ElMessage.error(e.message || '修改失败')
    }
  }
}

function toggleCollapse() {
  collapsed.value = !collapsed.value
}

// Close drawer on route change (mobile)
watch(() => route.path, () => {
  drawerOpen.value = false
})
</script>

<style scoped>
.admin-layout {
  height: 100vh;
  overflow: hidden;
}

/* ── Sidebar Overlay (mobile) ──────────────────────────────── */
.sidebar-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  z-index: var(--np-z-drawer);
  backdrop-filter: blur(4px);
}

/* ── Sidebar ───────────────────────────────────────────────── */
.admin-sidebar {
  height: 100vh;
  background: var(--np-bg-layout);
  border-right: 1px solid var(--np-border);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  z-index: var(--np-z-sidebar);
  transition: width 200ms ease;
  overflow: hidden;
}

.sidebar-brand {
  height: var(--np-header-height);
  display: flex;
  align-items: center;
  padding: 0 16px;
  gap: 10px;
  border-bottom: 1px solid var(--np-border);
  flex-shrink: 0;
  background: var(--np-gradient-sidebar);
}

.admin-sidebar.collapsed .sidebar-brand {
  justify-content: center;
  padding: 0;
}

.brand-icon {
  width: 32px;
  height: 32px;
  background: rgba(255, 255, 255, 0.2);
  backdrop-filter: blur(8px);
  color: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--np-radius-md);
  flex-shrink: 0;
  border: 1px solid rgba(255, 255, 255, 0.3);
}

.brand-text {
  font-size: 16px;
  font-weight: 700;
  color: #fff;
  letter-spacing: -0.02em;
  white-space: nowrap;
}

.sidebar-nav {
  flex: 1;
  padding: 8px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 12px;
  height: 40px;
  border-radius: var(--np-radius-md);
  color: var(--np-text-secondary);
  text-decoration: none;
  font-size: 14px;
  font-weight: 500;
  transition: all var(--np-transition);
  white-space: nowrap;
  flex-shrink: 0;
  overflow: hidden;
}

.admin-sidebar.collapsed .nav-item {
  justify-content: center;
  padding: 0;
}

.nav-item:hover {
  background: rgba(99, 102, 241, 0.08);
  color: var(--np-blue-600);
  text-decoration: none;
}

.nav-item.active {
  background: var(--np-gradient-brand);
  color: #fff;
  font-weight: 600;
  box-shadow: 0 2px 8px rgba(79, 70, 229, 0.3);
}

.nav-item.active .el-icon {
  color: #fff;
}

.nav-label {
  overflow: hidden;
  text-overflow: ellipsis;
}

.sidebar-footer {
  border-top: 1px solid var(--np-border);
  padding: 8px;
  flex-shrink: 0;
  display: flex;
  gap: 4px;
}

.sidebar-footer.footer-collapsed {
  flex-direction: column;
  align-items: center;
  gap: 4px;
}

.sidebar-footer.footer-collapsed .lang-toggle {
  width: 100%;
}

.lang-toggle {
  flex: 1;
  height: 36px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 4px;
  background: transparent;
  border: none;
  color: var(--np-text-muted);
  cursor: pointer;
  border-radius: var(--np-radius-md);
  font-size: 12px;
  font-weight: 500;
  transition: all var(--np-transition);
  white-space: nowrap;
  overflow: hidden;
}

.lang-toggle:hover {
  background: var(--np-bg-surface);
  color: var(--np-text-primary);
}

.collapse-toggle {
  width: 36px;
  height: 36px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: none;
  color: var(--np-text-muted);
  cursor: pointer;
  border-radius: var(--np-radius-md);
  transition: all var(--np-transition);
  flex-shrink: 0;
}

.collapse-toggle:hover {
  background: var(--np-bg-surface);
  color: var(--np-text-primary);
}

/* ── Main Wrapper ──────────────────────────────────────────── */
.admin-main-wrapper {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
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

.mobile-toggle {
  display: none;
  background: none;
  border: none;
  color: var(--np-text-secondary);
  cursor: pointer;
  padding: 4px;
  border-radius: var(--np-radius-sm);
  transition: all var(--np-transition);
}

.mobile-toggle:hover {
  color: var(--np-text-primary);
  background: var(--np-bg-surface);
}

.breadcrumb {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  min-width: 0;
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
  color: var(--np-text-primary);
  font-weight: 500;
}

.breadcrumb-sep {
  color: var(--np-text-disabled);
}

.header-right {
  display: flex;
  align-items: center;
  gap: 16px;
}
.user-info {
  display: flex;
  align-items: center;
  gap: 4px;
  cursor: pointer;
  font-size: 13px;
  color: var(--np-text-secondary);
  padding: 4px 8px;
  border-radius: var(--np-radius-md);
  transition: all var(--np-transition);
}
.user-info:hover {
  background: var(--np-bg-elevated);
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

/* ── Content ───────────────────────────────────────────────── */
.admin-content {
  background: var(--np-bg-app);
  overflow-y: auto;
  padding: 20px 24px;
  flex: 1;
}

/* ── Transitions ───────────────────────────────────────────── */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 150ms ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

/* ═══ Responsive ═════════════════════════════════════════════ */

/* Mobile: ≤ 640px */
@media (max-width: 640px) {
  .admin-sidebar {
    position: fixed;
    left: 0;
    top: 0;
    width: var(--np-sidebar-width) !important;
    transform: translateX(-100%);
    transition: transform 250ms ease;
    z-index: var(--np-z-drawer);
  }

  .admin-sidebar.drawer-open {
    transform: translateX(0);
  }

  .admin-sidebar.collapsed {
    width: var(--np-sidebar-width) !important;
  }

  .admin-sidebar .collapse-toggle {
    display: none;
  }

  .mobile-toggle {
    display: flex;
  }

  .admin-content {
    padding: 16px;
  }

  .admin-header {
    padding: 0 16px;
  }
}

/* Tablet: 641–1024px — auto-collapse sidebar */
@media (min-width: 641px) and (max-width: 1024px) {
  .admin-content {
    padding: 20px;
  }
}
</style>
