<template>
  <div class="page">
    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 16px">
      <a-button size="small" @click="goBack">
        <template #icon><ArrowLeftOutlined /></template>返回
      </a-button>
      <a-breadcrumb style="margin: 0">
        <a-breadcrumb-item><router-link to="/projects">项目</router-link></a-breadcrumb-item>
        <a-breadcrumb-item>
          <router-link :to="`/projects/${pid}?tab=scans`">扫描记录</router-link>
        </a-breadcrumb-item>
        <a-breadcrumb-item>轮次 #{{ sid }}</a-breadcrumb-item>
      </a-breadcrumb>
    </div>

    <a-card :bordered="false">
      <div class="result-head">
        <span class="result-title">
          扫描结果 · 轮次 #{{ sid }}
          <a-tag v-if="scan" :color="scan.kind === 'rescan' ? 'purple' : 'blue'"
                 style="margin-left: 8px">
            {{ scan.kind === 'rescan' ? '二次扫描' : '全量扫描' }}
          </a-tag>
          <a-tag v-if="scan" color="default">存活 {{ scan.alive }}/{{ scan.total }}</a-tag>
        </span>
        <a-checkbox v-model:checked="onlyAlive" style="margin: 0 10px">只看存活</a-checkbox>
        <a-input v-model:value="resCodeFilter" placeholder="状态码：200 / 200-399 / 4xx"
                 size="small" style="width: 180px; margin-right: 10px" allow-clear />
        <a-input-search v-model:value="scanKw" placeholder="过滤 URL / 标题 / 指纹"
                        style="width: 240px" size="small" allow-clear />
        <a-popover trigger="click" placement="bottomRight">
          <a-button size="small" style="margin-left: 10px">列设置</a-button>
          <template #content>
            <a-checkbox-group v-model:value="visibleCols" style="display: grid; gap: 6px">
              <a-checkbox v-for="c in resultCols.filter(x => !FIXED_COLS.includes(x.key))"
                          :key="c.key" :value="c.key">{{ c.title }}</a-checkbox>
            </a-checkbox-group>
          </template>
        </a-popover>
      </div>
      <div v-if="scan" class="result-meta">
        开始 {{ fmtTime(scan.started_at) }}<template v-if="scan.finished_at"> · 结束 {{ fmtTime(scan.finished_at) }}</template>
        <template v-if="scan.options?.screenshot === false"> · 未截图</template>
        <template v-if="scan.options?.fingerprint === false"> · 未指纹识别</template>
      </div>
      <a-table
        :data-source="filteredResults"
        :columns="shownResultCols"
        row-key="id"
        size="small"
        :pagination="{ defaultPageSize: 20, showSizeChanger: true, showQuickJumper: true,
                      showTotal: (t) => `共 ${t} 条` }"
        :loading="scan === null"
      >
        <template #bodyCell="{ column, record: r }">
          <template v-if="column.key === 'alive'">
            <a-badge :status="r.alive ? 'success' : 'error'"
                     :text="r.alive ? '存活' : '失活'" />
            <a-tag v-if="r.protection" color="volcano" style="margin-left: 4px">防护</a-tag>
          </template>
          <template v-else-if="column.key === 'fps'">
            <FpTags :raw="r.fingerprints" />
          </template>
          <template v-else-if="column.key === 'shot'">
            <router-link v-if="r.screenshot" :to="`/results/${r.id}`">
              <img class="shot-thumb" :src="`/screenshots/${r.screenshot}`" />
            </router-link>
            <span v-else>-</span>
          </template>
          <template v-else-if="column.key === 'detail'">
            <a-button size="small" @click="router.push(`/results/${r.id}`)">详情</a-button>
          </template>
          <template v-else-if="column.key === 'final_url'">
            <a :href="r.final_url" target="_blank" rel="noopener" class="mono"
               style="word-break: break-all">{{ r.final_url }}</a>
          </template>
        </template>
      </a-table>
      <a-empty v-if="scan && !scan.results.length" description="该轮没有结果" />
    </a-card>
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeftOutlined } from '@ant-design/icons-vue'
import api from '../api'
import FpTags from '../components/FpTags.vue'
import { useBack } from '../back'
import { fmtTime } from '../fmt'

const route = useRoute()
const router = useRouter()
const pid = Number(route.params.pid)
const sid = Number(route.params.sid)

const scan = ref(null)
const scanKw = ref('')
const onlyAlive = ref(false)
const resCodeFilter = ref('')

const goBack = useBack(`/projects/${pid}?tab=scans`)

const resultCols = [
  { title: '状态', key: 'alive', width: 100 },
  { title: 'URL', key: 'final_url', ellipsis: true },
  { title: 'HTTP', key: 'status_code', dataIndex: 'status_code', width: 70 },
  { title: '标题', key: 'title', dataIndex: 'title', ellipsis: true },
  { title: '指纹', key: 'fps' },
  { title: '截图', key: 'shot', width: 130 },
  { title: '操作', key: 'detail', width: 70 },
]

const COL_STORE_KEY = 'scan_result_cols'
const FIXED_COLS = ['detail']
const visibleCols = ref(
  JSON.parse(localStorage.getItem(COL_STORE_KEY) || 'null') ||
  resultCols.map((c) => c.key)
)
watch(visibleCols, (v) => localStorage.setItem(COL_STORE_KEY, JSON.stringify(v)),
      { deep: true })
const shownResultCols = computed(() =>
  resultCols.filter((c) => FIXED_COLS.includes(c.key) || visibleCols.value.includes(c.key))
)

function parseCodeRange(v) {
  const s = (v || '').trim()
  if (!s) return null
  if (/^\d{3}$/.test(s)) return { lo: +s, hi: +s }
  const m = s.match(/^(\d)(xx|\d{2})$/)
  if (m) { const lo = +m[1] * 100; return { lo, hi: lo + 99 } }
  const r = s.match(/^(\d{3})\s*-\s*(\d{3})$/)
  if (r) return { lo: +r[1], hi: +r[2] }
  return null
}
const inCodeRange = (code, range) => code >= range.lo && code <= range.hi

const filteredResults = computed(() => {
  const rows = scan.value?.results || []
  const kw = scanKw.value.trim().toLowerCase()
  const range = parseCodeRange(resCodeFilter.value)
  return rows.filter((r) => {
    if (onlyAlive.value && !r.alive) return false
    if (range && !inCodeRange(r.status_code, range)) return false
    if (!kw) return true
    return [r.final_url, r.url, r.title, r.fingerprints, r.protection]
      .filter(Boolean).join(' ').toLowerCase().includes(kw)
  })
})

onMounted(async () => {
  const { data } = await api.getScan(sid)
  scan.value = data
})
</script>

<style scoped>
.result-head { display: flex; align-items: center; flex-wrap: wrap; gap: 4px 0; }
.result-title { font-weight: 600; margin-right: 10px; }
.result-meta { color: #999; font-size: 12px; margin: 4px 0 12px; }
.shot-thumb { width: 110px; height: 62px; object-fit: cover; border-radius: 4px;
              border: 1px solid #eee; display: block; }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
</style>
