import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
})

// 请求拦截：自动携带 JWT token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('netprobe_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// 响应拦截：拆包 data + 401 跳登录
api.interceptors.response.use(
  (res) => res.data,
  (err) => {
    // 401 未授权 → 清 token 跳登录
    if (err.response?.status === 401) {
      localStorage.removeItem('netprobe_token')
      localStorage.removeItem('netprobe_user')
      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login'
      }
    }
    const msg = err.response?.data?.detail || err.message || 'Request failed'
    return Promise.reject(new Error(msg))
  }
)

export default api
