import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('../views/Login.vue'),
      meta: { public: true },
    },
    {
      path: '/',
      name: 'dashboard',
      component: () => import('../views/Dashboard.vue'),
      meta: { title: 'Dashboard', icon: 'Odometer' },
    },
    {
      path: '/tasks',
      name: 'tasks',
      component: () => import('../views/Tasks.vue'),
      meta: { title: 'Tasks', icon: 'List' },
    },
    {
      path: '/tasks/:id',
      name: 'task-detail',
      component: () => import('../views/TaskDetail.vue'),
      meta: { title: 'Task Detail' },
    },
    {
      path: '/scan/:id',
      name: 'scan-result',
      component: () => import('../views/ScanResult.vue'),
      meta: { title: 'Scan Result' },
    },
    {
      path: '/schedules',
      name: 'schedules',
      component: () => import('../views/Schedules.vue'),
      meta: { title: 'Scheduled Scans', icon: 'Timer' },
    },
    {
      path: '/diff',
      name: 'scan-diff',
      component: () => import('../views/ScanDiff.vue'),
      meta: { title: 'Compare Scans', icon: 'DataExchange' },
    },
    {
      path: '/correlations',
      name: 'correlations',
      component: () => import('../views/Correlations.vue'),
      meta: { title: 'Correlations', icon: 'Share' },
    },
    {
      path: '/stats',
      name: 'stats',
      component: () => import('../views/Stats.vue'),
      meta: { title: 'Statistics', icon: 'DataLine' },
    },
    {
      path: '/graph',
      name: 'graph',
      component: () => import('../views/Graph.vue'),
      meta: { title: 'Graph', icon: 'Connection' },
    },
    {
      path: '/alerts',
      name: 'alerts',
      component: () => import('../views/Alerts.vue'),
      meta: { title: 'Alerts', icon: 'Bell' },
    },
    {
      path: '/assets',
      name: 'assets',
      component: () => import('../views/Assets.vue'),
      meta: { title: 'Asset Inventory', icon: 'Grid' },
    },
    {
      path: '/settings',
      name: 'settings',
      component: () => import('../views/Settings.vue'),
      meta: { title: 'Settings', icon: 'Setting' },
    },
    // Redirects from old /history routes
    {
      path: '/asm',
      name: 'asm',
      component: () => import('../views/ASM.vue'),
      meta: { title: 'ASM', icon: 'Aim' },
    },
    {
      path: '/users',
      name: 'users',
      component: () => import('../views/Users.vue'),
      meta: { title: 'Users', icon: 'UserFilled', requiresAdmin: true },
    },
    { path: '/history', redirect: '/tasks' },
    { path: '/history/:id', redirect: to => `/tasks/${to.params.id}` },
  ],
})

// 全局路由守卫 — 未登录跳 /login，非管理员访问管理页跳首页
router.beforeEach((to, _from, next) => {
  const token = localStorage.getItem('netprobe_token')
  if (to.meta.public || token) {
    if (to.path === '/login' && token) {
      next('/')
    } else if (to.meta.requiresAdmin) {
      // 检查是否管理员
      const user = JSON.parse(localStorage.getItem('netprobe_user') || '{}')
      if (user.is_admin) {
        next()
      } else {
        next('/')
      }
    } else {
      next()
    }
  } else {
    next('/login')
  }
})

export default router
