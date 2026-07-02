<template>
  <SidebarLayout v-if="appStore.layout === 'sidebar'" />
  <TopNavLayout v-else />
</template>

<script setup lang="ts">
import { useAppStore } from './stores/app'
import SidebarLayout from './layouts/SidebarLayout.vue'
import TopNavLayout from './layouts/TopNavLayout.vue'

const appStore = useAppStore()
</script>
