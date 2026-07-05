<template>
  <Login v-if="isLoginPage" />
  <SidebarLayout v-else-if="appStore.layout === 'sidebar'" />
  <TopNavLayout v-else />
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useAppStore } from './stores/app'
import SidebarLayout from './layouts/SidebarLayout.vue'
import TopNavLayout from './layouts/TopNavLayout.vue'
import Login from './views/Login.vue'

const appStore = useAppStore()
const route = useRoute()
const isLoginPage = computed(() => route.path === '/login')
</script>
