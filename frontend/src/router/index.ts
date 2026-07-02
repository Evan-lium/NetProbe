import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(),
  routes: [
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
      component: () => import('../views/ScanDetail.vue'),
      meta: { title: 'Scan Detail' },
    },
    {
      path: '/scan/:id',
      name: 'scan-result',
      component: () => import('../views/ScanResult.vue'),
      meta: { title: 'Scan Result' },
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
    { path: '/history', redirect: '/tasks' },
    { path: '/history/:id', redirect: to => `/tasks/${to.params.id}` },
  ],
})

export default router
