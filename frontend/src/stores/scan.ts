import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { Host, SSEEvent } from '../types'

export const useScanStore = defineStore('scan', () => {
  const scanId = ref('')
  const status = ref<'idle' | 'running' | 'done' | 'error'>('idle')
  const baseDomain = ref('')
  const hosts = ref<Host[]>([])
  const logs = ref<string[]>([])
  const eventSource = ref<EventSource | null>(null)

  function reset() {
    scanId.value = ''
    status.value = 'idle'
    baseDomain.value = ''
    hosts.value = []
    logs.value = []
    disconnect()
  }

  function connect(taskId: string) {
    disconnect()
    scanId.value = taskId
    status.value = 'running'
    logs.value = []

    const es = new EventSource(`/api/stream/${taskId}`)
    eventSource.value = es

    es.onmessage = (e) => {
      try {
        const data: SSEEvent = JSON.parse(e.data)
        handleEvent(data)
      } catch {
        logs.value.push(e.data)
      }
    }

    es.onerror = () => {
      status.value = 'error'
      logs.value.push('[error] SSE connection lost')
      es.close()
    }
  }

  function handleEvent(data: SSEEvent) {
    switch (data.event) {
      case 'log':
        logs.value.push(data.text || '')
        break
      case 'progress':
        logs.value.push(data.text || '')
        break
      case 'host_found':
        if (data.host) {
          hosts.value.push(data.host)
        }
        break
      case 'done':
        status.value = 'done'
        if (data.hosts) hosts.value = data.hosts
        if (data.base_domain) baseDomain.value = data.base_domain
        logs.value.push('[done] scan completed')
        disconnect()
        break
      case 'error':
        status.value = 'error'
        logs.value.push(`[error] ${data.text || 'unknown error'}`)
        disconnect()
        break
      default:
        if (data.text) logs.value.push(data.text)
    }
  }

  function disconnect() {
    if (eventSource.value) {
      eventSource.value.close()
      eventSource.value = null
    }
  }

  return {
    scanId, status, baseDomain, hosts, logs,
    reset, connect, disconnect,
  }
})
