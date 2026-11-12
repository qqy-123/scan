import { useRouter } from 'vue-router'

// 返回上一级：优先走浏览器历史（保留来源页状态），无历史时回退到指定页面
export function useBack(fallback = '/') {
  const router = useRouter()
  return () => {
    if (window.history.state?.back) return router.back()
    router.push(fallback)
  }
}
