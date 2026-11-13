<template>
  <div class="texp">
    <div class="texp-head">
      <span class="texp-meta">
        测绘结果 <b>{{ rows.length }}</b> 条
        <template v-if="surfaceCount">（攻击面 <b style="color:#f5222d">{{ surfaceCount }}</b>）</template>
        <template v-if="lastRun"> · 最近测绘 {{ fmtTime(lastRun) }}</template>
        <a-tag v-if="runningNow" color="processing" style="margin-left:8px">测绘中…</a-tag>
      </span>
      <a-space>
        <a-button size="small" @click="load">刷新</a-button>
        <a-popover trigger="click" placement="bottomRight">
          <a-button size="small">列设置</a-button>
          <template #content>
            <a-checkbox-group v-model:value="visible" style="display:grid;gap:6px">
              <a-checkbox v-for="c in cols.filter(x => !FIXED.includes(x.key))"
                          :key="c.key" :value="c.key">{{ c.title }}</a-checkbox>
            </a-checkbox-group>
          </template>
        </a-popover>
        <a-button size="small" type="primary" :disabled="running"
                  @click="$emit('scan', target)">测绘本目标</a-button>
      </a-space>
    </div>
    <a-table :data-source="rows" :columns="shown" row-key="id" size="small"
             :loading="loading" :pagination="{ defaultPageSize: 10, showSizeChanger: true, showTotal: (t) => `共 ${t} 条` }">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'kind'">
          <a-tag :color="kindColor(record.kind)">{{ kindLabel(record.kind) }}</a-tag>
        </template>
        <template v-else-if="column.key === 'url'">
          <a :href="record.url" target="_blank" rel="noopener" class="mono"
             style="word-break: break-all">{{ record.url }}</a>
          <div v-if="record.title" class="sub-line">{{ record.title }}</div>
        </template>
        <template v-else-if="column.key === 'status'">
          <a-tag v-if="record.status_code" :color="statusColor(record.status_code)">
            {{ record.status_code }}</a-tag>
          <a-tag v-else-if="record.alive === 0" color="default">失活</a-tag>
          <span v-else>-</span>
        </template>
        <template v-else-if="column.key === 'level'">
          <a-tag :color="record.surface ? 'red' : 'default'">
            {{ record.surface ? '攻击面' : '信息' }}</a-tag>
        </template>
        <template v-else-if="column.key === 'hint'">
          <a-tag v-if="record.hint && record.hint !== 'other'"
                 :color="hintColor(record.hint)">{{ record.hint }}</a-tag>
          <span v-else style="color:#bfbfbf">-</span>
        </template>
        <template v-else-if="column.key === 'fingerprints'">
          <FpTags v-if="record.status_code || record.alive" :raw="record.fingerprints" />
          <span v-else style="color:#bfbfbf">-</span>
          <span v-if="record.protection" style="font-size:11px;color:#fa541c">🛡 {{ record.protection }}</span>
        </template>
        <template v-else-if="column.key === 'screenshot'">
          <a v-if="record.screenshot" :href="`/screenshots/${record.screenshot}`"
             target="_blank" rel="noopener">
            <img :src="`/screenshots/${record.screenshot}`" loading="lazy"
                 style="width:72px;border:1px solid #f0f0f0;border-radius:4px;display:block" />
          </a>
          <span v-else style="color:#bfbfbf">-</span>
        </template>
        <template v-else-if="column.key === 'pkt'">
          <a v-if="record.has_response" @click.stop="openPkt(record)">查看</a>
          <span v-else style="color:#d9d9d9">-</span>
        </template>
        <template v-else-if="column.key === 'source'">
          <span class="mono" style="font-size:11px;color:#8c8c8c;word-break:break-all">
            {{ record.source || '-' }}</span>
        </template>
        <template v-else-if="column.key === 'run'">
          <span class="mono" style="font-size:12px">#{{ record.run_id }}</span>
        </template>
        <template v-else-if="column.key === 'time'">
          <span style="font-size:12px">{{ fmtTime(record.created_at) }}</span>
        </template>
      </template>
      <template #emptyText>
        <a-empty description="该目标还没有测绘结果，点击右上角「测绘本目标」" />
      </template>
    </a-table>

    <a-modal v-model:open="pkt.open" title="回显数据包" width="880px" :footer="null">
      <div class="mono" style="font-size:12px;color:#8c8c8c;word-break:break-all">{{ pkt.url }}</div>
      <div v-if="pkt.loading" style="text-align:center;padding:24px"><a-spin /></div>
      <pre v-else class="pkt-pre">{{ pkt.response || '(空)' }}</pre>
    </a-modal>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import api from '../api'
import FpTags from './FpTags.vue'
import { fmtTime } from '../fmt'
import { loadColPrefs, saveColPrefs } from '../colprefs'

const props = defineProps({
  target: Object,
  running: Boolean,   // any exposure run active in the project
})
const emit = defineEmits(['scan'])

const rows = ref([])
const runs = ref([])
const loading = ref(false)
let timer = null

const surfaceCount = computed(() => rows.value.filter((r) => r.surface).length)
const lastRun = computed(() => {
  const ts = [
    ...runs.value.map((r) => r.started_at),
    ...rows.value.map((r) => r.run_started),
  ].filter(Boolean).sort()
  return ts.length ? ts[ts.length - 1] : null
})
const runningNow = computed(() =>
  props.running || runs.value.some((r) => r.status === 'running'))

async function load() {
  loading.value = true
  try {
    const { data } = await api.targetExposure(props.target.id)
    rows.value = data.results || []
    runs.value = data.runs || []
  } finally {
    loading.value = false
  }
}

watch(runningNow, (v) => {
  clearInterval(timer)
  if (v) timer = setInterval(load, 5000)
})

onMounted(() => {
  load()
  if (runningNow.value) timer = setInterval(load, 5000)
})
onBeforeUnmount(() => clearInterval(timer))

// ---- columns + prefs ----
const FIXED = ['url']
const STORE_KEY = 'target_exposure_cols'
const cols = [
  { title: '方式', key: 'kind', width: 78 },
  { title: 'URL / 标题', key: 'url' },
  { title: '状态', key: 'status', width: 74 },
  { title: '分类', key: 'hint', width: 100 },
  { title: '级别', key: 'level', width: 76 },
  { title: '指纹', key: 'fingerprints', width: 230 },
  { title: '截图', key: 'screenshot', width: 92 },
  { title: '详情', key: 'pkt', width: 56 },
  { title: '来源', key: 'source', width: 140, ellipsis: true },
  { title: '轮次', key: 'run', width: 64 },
  { title: '发现时间', key: 'time', width: 120 },
]
const visible = ref(
  loadColPrefs(STORE_KEY, cols.map((c) => c.key), 1))
watch(visible,
  (v) => saveColPrefs(STORE_KEY, v, cols.map((c) => c.key), 1))
const shown = computed(() =>
  cols.filter((c) => FIXED.includes(c.key) || visible.value.includes(c.key)))

// ---- response packet viewer ----
const pkt = reactive({ open: false, loading: false, url: '', response: '' })
async function openPkt(r) {
  pkt.open = true
  pkt.loading = true
  pkt.url = r.url
  try {
    const { data } = await api.exposureRowResponse(r.id)
    pkt.response = data.response || ''
  } finally {
    pkt.loading = false
  }
}

const kindColor = (k) =>
  ({ js: 'cyan', dir: 'blue', leak: 'magenta', vuln: 'red', point: 'volcano',
     sub: 'purple', host: 'volcano', cdn: 'red', net: 'green',
     url: 'geekblue', port: 'orange' })[k] || 'default'
const kindLabel = (k) =>
  ({ js: 'JS', dir: 'DIR', leak: '泄露', vuln: '漏洞', point: '攻击点',
     sub: '子域', host: 'Host碰撞', cdn: '源站', net: '测绘',
     url: '历史URL', port: '端口' })[k] || k
const statusColor = (s) =>
  s < 300 ? 'green' : s < 400 ? 'geekblue' : s === 401 || s === 403 ? 'orange' : 'red'
const hintColor = (h) =>
  ({ admin: 'red', api: 'geekblue', upload: 'orange', auth: 'purple',
     config: 'gold', debug: 'cyan', vuln: 'red', leak: 'magenta',
     point: 'volcano', origin: 'red', host: 'volcano', entry: 'purple',
     takeover: 'red', critical: 'red', port: 'orange' })[String(h).split(':')[0]] || 'default'
</script>

<style scoped>
.texp { padding: 8px 4px; }
.texp-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.texp-meta { font-size: 13px; color: #595959; }
.sub-line { font-size: 11px; color: #8c8c8c; }
.pkt-pre {
  max-height: 60vh; overflow: auto; background: #0d0d0d; color: #d4d4d4;
  padding: 12px; border-radius: 6px; font-size: 12px; white-space: pre-wrap;
  word-break: break-all;
}
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
</style>
