import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useAppStore = defineStore('app', () => {
  const layout = ref<'sidebar' | 'topnav'>(
    (localStorage.getItem('netprobe_layout') as 'sidebar' | 'topnav') || 'sidebar'
  )

  function setLayout(mode: 'sidebar' | 'topnav') {
    layout.value = mode
    localStorage.setItem('netprobe_layout', mode)
  }

  return { layout, setLayout }
})
