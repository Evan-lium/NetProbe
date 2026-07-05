import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import api from '../api/index'

export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem('netprobe_token') || '')
  const user = ref(JSON.parse(localStorage.getItem('netprobe_user') || 'null'))

  const isLoggedIn = computed(() => !!token.value)

  async function login(username: string, password: string) {
    const res: any = await api.post('/auth/login', { username, password })
    token.value = res.token
    user.value = res.user
    localStorage.setItem('netprobe_token', res.token)
    localStorage.setItem('netprobe_user', JSON.stringify(res.user))
    return res
  }

  function logout() {
    token.value = ''
    user.value = null
    localStorage.removeItem('netprobe_token')
    localStorage.removeItem('netprobe_user')
  }

  async function changePassword(oldPwd: string, newPwd: string) {
    return await api.post('/auth/change-password', { old_password: oldPwd, new_password: newPwd })
  }

  return { token, user, isLoggedIn, login, logout, changePassword }
})
