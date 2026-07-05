import { ref, watch } from 'vue'

const STORAGE_PREFIX = 'netprobe_page_size_'
const DEFAULT_SIZE = 20

/** 每页条数（按页面 key 独立持久化，互不影响）。
 *
 * 用法：
 *   const perPage = usePageSize('assets')  // 资产页独立
 *   const perPage = usePageSize('tasks')   // 任务页独立
 *   // 改 perPage.value 只影响当前页面 key
 */
export function usePageSize(pageKey: string = 'default') {
  const storageKey = STORAGE_PREFIX + pageKey
  let initial = DEFAULT_SIZE
  try {
    const saved = localStorage.getItem(storageKey)
    if (saved) initial = Number(saved) || DEFAULT_SIZE
  } catch {
    /* localStorage 不可用时用默认值 */
  }

  const pageSize = ref(initial)

  // 监听变化，自动持久化
  watch(pageSize, (val) => {
    try {
      localStorage.setItem(storageKey, String(val))
    } catch {
      /* 忽略写入失败 */
    }
  })

  return pageSize
}
