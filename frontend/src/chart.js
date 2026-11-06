import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'

// Minimal echarts wrapper: chartRef -> div, optionRef -> echarts option
export function useChart(getOption) {
  const el = ref(null)
  let chart = null

  const render = () => {
    if (chart) chart.setOption(getOption(), true)
  }

  onMounted(() => {
    chart = echarts.init(el.value)
    render()
    window.addEventListener('resize', resize)
  })
  onBeforeUnmount(() => {
    window.removeEventListener('resize', resize)
    chart?.dispose()
  })
  const resize = () => chart?.resize()
  watch(getOption, render)
  return el
}
