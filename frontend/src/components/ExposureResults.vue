<template>
  <div class="result-toolbar">
    <a-checkable-tag v-for="o in SEV_OPTS" :key="o.value"
                     :checked="sevSel.includes(o.value)"
                     :style="sevSel.includes(o.value)
                             ? `background:${SEV[o.value].hex};border-color:${SEV[o.value].hex}` : ''"
                     class="filter-chip"
                     @change="toggle(sevSel, o.value)">{{ o.label }}</a-checkable-tag>
    <span class="toolbar-sep" />
    <a-checkable-tag v-for="o in tagOpts" :key="o.value"
                     :checked="tagSel.includes(o.value)"
                     class="filter-chip"
                     @change="toggle(tagSel, o.value)">{{ o.label }}</a-checkable-tag>
    <a-input v-model:value="kw" placeholder="搜索 URL / 标题 / 指纹 / 标签" allow-clear
             size="small" style="width: 220px; margin-left: auto" />
    <span class="toolbar-count">
      {{ flat.length }} 条结果<template v-if="dupTotal">（合并 {{ dupTotal }} 条相同）</template>
    </span>
  </div>
  <a-table :data-source="flat" :columns="cols" row-key="key" size="small"
           :pagination="pager" :loading="loading" @change="onTableChange"
           :expanded-row-keys="expandedKeys" @update:expandedRowKeys="expandedKeys = $event"
           :scroll="{ y: 560 }">
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'num'">
        <span :class="record.isAlike ? 'num-sub' : 'num'">{{ record.num }}</span>
      </template>
      <template v-else-if="column.key === 'url'">
        <template v-if="record.isAlike">
          <span class="alike-url mono">└ {{ record.url }}</span>
          <div v-if="record.title" class="sub-line">{{ record.title }}</div>
        </template>
        <template v-else>
          <a :href="record.url" target="_blank" rel="noopener" class="mono"
             style="word-break: break-all">{{ record.url }}</a>
          <a-tag v-if="record._alike?.length" color="default" style="margin-left: 6px">
            ×{{ record._alike.length + 1 }} 相同
          </a-tag>
          <div class="sub-line">
            <template v-if="record.title">{{ record.title }}</template>
            <template v-if="record.title && record.target_url"> · </template>
            <template v-if="record.target_url">{{ record.target_url }}</template>
          </div>
        </template>
      </template>
      <template v-else-if="column.key === 'sev'">
        <a-tag v-if="!record.isAlike" :color="SEV[record.sev].color">{{ SEV[record.sev].label }}</a-tag>
      </template>
      <template v-else-if="column.key === 'level'">
        <a-tag :color="record.surface ? 'red' : 'default'">
          {{ record.surface ? '攻击面' : '信息' }}
        </a-tag>
      </template>
      <template v-else-if="column.key === 'kind'">
        <a-tag :color="kindColor(record.kind)">{{ kindLabel(record.kind) }}</a-tag>
      </template>
      <template v-else-if="column.key === 'status'">
        <a-tag v-if="record.status_code" :color="statusColor(record.status_code)">
          {{ record.status_code }}
        </a-tag>
        <a-tag v-else-if="record.alive === 0" color="default">失活</a-tag>
        <span v-else>-</span>
      </template>
      <template v-else-if="column.key === 'hint'">
        <a-tag v-if="record.hint && record.hint !== 'other'" :color="hintColor(record.hint)">
          {{ record.hint }}
        </a-tag>
        <span v-else style="color: #bfbfbf">-</span>
      </template>
      <template v-else-if="column.key === 'fingerprints'">
        <template v-if="!record.isAlike">
          <FpTags v-if="record.status_code || record.alive" :raw="record.fingerprints" />
          <span v-else style="color: #bfbfbf" title="未深扫">-</span>
          <span v-if="record.protection" class="prot-tag">🛡 {{ record.protection }}</span>
        </template>
      </template>
      <template v-else-if="column.key === 'screenshot'">
        <a v-if="!record.isAlike && record.screenshot"
           :href="`/screenshots/${record.screenshot}`" target="_blank" rel="noopener">
          <img :src="`/screenshots/${record.screenshot}`" loading="lazy"
               style="width: 72px; border: 1px solid #f0f0f0; border-radius: 4px; display: block" />
        </a>
        <span v-else-if="!record.isAlike" style="color: #bfbfbf"
              title="未进深扫 / 与首页相同(非攻击面) / 截图失败">-</span>
      </template>
      <template v-else-if="column.key === 'source'">
        <span class="mono" style="font-size: 11px; color: #8c8c8c; word-break: break-all">
          {{ record.source || '-' }}
        </span>
      </template>
    </template>
  </a-table>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import api from '../api'
import FpTags from './FpTags.vue'

const props = defineProps({ runId: Number, filter: { type: String, default: '' } })
const results = ref([])
const loading = ref(false)
const expandedKeys = ref([])
const kw = ref('')
const sevSel = ref([])     // multi-select: [] = all levels
const tagSel = ref([])     // multi-select tag filter

const SEV_OPTS = [
  { value: 0, label: '高危' }, { value: 1, label: '中危' },
  { value: 2, label: '信息' }, { value: 3, label: '噪声' },
]

function toggle(list, v) {
  const i = list.value.indexOf(v)
  if (i < 0) list.value.push(v)
  else list.value.splice(i, 1)
}

const TAG_LABEL = {
  entry: '入口', entryq: '疑似入口', api: 'API', upload: '上传', auth: '认证',
  config: '配置', debug: '调试', leak: '泄露', vuln: '漏洞',
  point: '攻击点', takeover: '接管', origin: '源站', host: 'Host碰撞',
  port: '端口', sub: '子域', url: '历史URL', net: '测绘',
  surface: '攻击面', shot: '已截图',
}

const ENTRY_RE = /\/(admin|manage|console|backend|backstage|login|signin|portal|sso|dashboard|phpmyadmin|wp-admin)(\/|\.|\?|$)/i
const API_RE = /\/api[\/_.-]|\.api\.|^api\.|\/v\d+(\/|$)/i

function tagsOf(r) {
  const t = []
  const h = r.hint || ''
  const u = (r.url || '').toLowerCase()
  const h0 = h.split(':')[0]
  if (h0 === 'admin' || h === 'entry' || h === 'point:admin' ||
      h === 'point:login' || ENTRY_RE.test(u)) t.push('entry')
  // 疑似入口: served a real page (status<400 with rendered evidence)
  if (r.status_code != null && r.status_code < 400 && r.status_code !== 204 &&
      (r.title || r.screenshot || r.surface)) t.push('entryq')
  if (h0 === 'api' || h === 'point:api' || API_RE.test(u)) t.push('api')
  if (h0 === 'upload') t.push('upload')
  if (h0 === 'auth') t.push('auth')
  if (h0 === 'config') t.push('config')
  if (h0 === 'debug') t.push('debug')
  if (h.startsWith('leak:')) t.push('leak')
  if (h.startsWith('vuln:')) t.push('vuln')
  if (h.startsWith('point:')) t.push('point')
  if (h === 'takeover') t.push('takeover')
  if (h === 'origin' || r.kind === 'cdn') t.push('origin')
  if (r.kind === 'host') t.push('host')
  if (r.kind === 'port') t.push('port')
  if (r.kind === 'sub') t.push('sub')
  if (r.kind === 'url') t.push('url')
  if (r.kind === 'net') t.push('net')
  if (r.surface) t.push('surface')
  if (r.screenshot) t.push('shot')
  return t
}

const tagOpts = computed(() => {
  const present = new Set()
  for (const r of results.value) for (const t of tagsOf(r)) present.add(t)
  return Object.entries(TAG_LABEL)
    .filter(([k]) => present.has(k))
    .map(([value, label]) => ({ value, label }))
})

const page = ref(1)
const pageSize = ref(20)
const pager = computed(() => ({
  current: page.value,
  pageSize: pageSize.value,
  total: flat.value.length,
  showSizeChanger: true,
  pageSizeOptions: ['10', '20', '30', '50'],
  showQuickJumper: true,
  showTotal: (t) => `共 ${t} 条`,
}))
function onTableChange(p) {
  page.value = p.current
  pageSize.value = p.pageSize
}
watch([kw, sevSel, tagSel], () => { page.value = 1 })

const cols = [
  { title: '#', key: 'num', width: 76 },
  { title: 'URL / 标题', key: 'url' },
  { title: '危害', key: 'sev', width: 66 },
  { title: '级别', key: 'level', width: 70 },
  { title: '方式', key: 'kind', width: 66 },
  { title: '状态', key: 'status', width: 74 },
  { title: '分类', key: 'hint', width: 104 },
  { title: '指纹', key: 'fingerprints', width: 240 },
  { title: '截图', key: 'screenshot', width: 92 },
  { title: '来源', key: 'source', width: 140, ellipsis: true },
]

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

// 0 高危 1 中危 2 信息 3 噪声
const HIGH_LEAK = /rsa|private|aws|github|gitlab|token|jwt|secret|password|passwd|jdbc|oss|s3|shiro|cloud|aliyun|tencent|apikey|aksk|webhook/i
const ADMIN_URL = /(^|[\/_\-.])(admin|manager|manage|console|backend|backstage|druid|phpmyadmin|nacos|actuator|jolokia|jenkins|sonar|weblogic|grafana|kibana|harbor|rancher|zabbix|sentinel|xxl|apisix|portainer|minio|elasticsearch|swagger|dubbo|nexus|gitlab|gitea|jumpserver|waf)([\/_\-.?]|$)/i

function sevOf(r) {
  const h = r.hint || ''
  const u = (r.url || '').toLowerCase()
  if (h.startsWith('vuln:')) return 0
  if (h === 'point:admin') return 0
  if (h.startsWith('leak:') && HIGH_LEAK.test(h)) return 0
  if (r.surface && ADMIN_URL.test(u)) return 0
  if (h === 'takeover') return 0
  if (h === 'port:critical') return 0
  if (h === 'host:vhost') return 1
  if (h === 'origin') return 1
  if (h.startsWith('port:')) return 1
  if (h.startsWith('point:')) return 1
  if (h.startsWith('leak:')) return 1
  if (r.surface) return 1
  if (r.status_code != null || r.alive === 0) return 3
  return 2
}

const SEV = [
  { label: '高危', color: 'red', hex: '#f5222d' },
  { label: '中危', color: 'orange', hex: '#fa8c16' },
  { label: '信息', color: 'blue', hex: '#1677ff' },
  { label: '噪声', color: 'default', hex: '#8c8c8c' },
]

// 相同返回算一个结果: 状态码+标题+长度桶
const sigOf = (r) =>
  r.status_code != null
    ? `${r.status_code}|${(r.title || '').trim().toLowerCase()}|${Math.round((r.length || 0) / 300)}`
    : null

const INTEL_HINT_RANK = { 'sub:alive': 0, 'sub:dns': 1, 'sub:ct': 2, 'sub:echo': 3, 'sub:js': 4 }

const flat = computed(() => {
  const search = (kw.value || props.filter || '').trim().toLowerCase()
  const match = (r) => {
    if (sevSel.value.length && !sevSel.value.includes(sevOf(r))) return false
    if (tagSel.value.length && !tagsOf(r).some((t) => tagSel.value.includes(t)))
      return false
    if (!search) return true
    const hay = [
      r.url, r.title, r.hint, r.source, r.fingerprints, r.target_url,
      ...tagsOf(r).map((t) => TAG_LABEL[t]),
    ].filter(Boolean).join(' ').toLowerCase()
    return hay.includes(search)
  }
  const rows = results.value.filter(match)

  // pass 1: intel dedup — same asset from several sources
  const probed = []
  const intelGroups = new Map()
  for (const r of rows) {
    if (sigOf(r)) { probed.push(r); continue }
    const k = `intel|${r.url}`
    if (!intelGroups.has(k)) intelGroups.set(k, [])
    intelGroups.get(k).push(r)
  }
  const intelReps = []
  for (const [, rs] of intelGroups) {
    rs.sort((a, b) => (INTEL_HINT_RANK[a.hint] ?? 9) - (INTEL_HINT_RANK[b.hint] ?? 9))
    const [rep, ...rest] = rs
    rep._alike = rest
    intelReps.push(rep)
  }

  // pass 2: response-signature dedup among probed rows
  const bySig = new Map()
  for (const r of probed) {
    const k = sigOf(r)
    if (!bySig.has(k)) bySig.set(k, [])
    bySig.get(k).push(r)
  }
  const reps = []
  for (const [, rs] of bySig) {
    rs.sort((a, b) =>
      sevOf(a) - sevOf(b) || (b.surface || 0) - (a.surface || 0)
      || (b.screenshot ? 1 : 0) - (a.screenshot ? 1 : 0) || a.url.length - b.url.length)
    const [rep, ...rest] = rs
    rep._alike = rest
    reps.push(rep)
  }

  // pass 3: same-interface dedup — screenshots whose rendered DOM
  // structure is identical (shot_sig) collapse into one result even if
  // the raw response differs slightly (tokens/timestamps/hosts)
  reps.sort((a, b) => sevOf(a) - sevOf(b)
    || (b.screenshot ? 1 : 0) - (a.screenshot ? 1 : 0))
  const byShot = new Map()
  const merged = []
  for (const r of reps) {
    const s = r.shot_sig
    if (!s) { merged.push(r); continue }
    const keep = byShot.get(s)
    if (!keep) { byShot.set(s, r); merged.push(r); continue }
    keep._alike = [...(keep._alike || []), r, ...(r._alike || [])]
  }

  let all = [...merged, ...intelReps]
  all.sort((a, b) => sevOf(a) - sevOf(b)
    || (b.screenshot ? 1 : 0) - (a.screenshot ? 1 : 0)
    || (b.surface || 0) - (a.surface || 0) || a.url.localeCompare(b.url))
  return all.map((r, i) => ({
    ...r, key: `r-${r.id}`, sev: sevOf(r), num: i + 1,
    children: (r._alike || []).map((a, j) => ({
      ...a, isAlike: true, key: `a-${r.id}-${j}`, num: `${i + 1}.${j + 1}`,
    })),
  }))
})

const dupTotal = computed(() =>
  flat.value.reduce((s, r) => s + (r._alike?.length || 0), 0))

onMounted(async () => {
  loading.value = true
  try {
    const { data } = await api.getExposure(props.runId)
    results.value = data.results
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.result-toolbar {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 12px;
}
.filter-chip { margin-inline-end: 0; user-select: none; }
.toolbar-sep {
  width: 1px;
  height: 16px;
  background: #e0e0e0;
  margin: 0 6px;
}
.toolbar-count { font-size: 12px; color: #8c8c8c; margin-left: auto; }
.num { font-size: 12px; color: #595959; font-weight: 500; white-space: nowrap; }
.num-sub { font-size: 11px; color: #bfbfbf; white-space: nowrap; }
.alike-url { color: #8c8c8c; font-size: 12px; word-break: break-all; }
.sub-line { font-size: 11px; color: #a6a6a6; margin-top: 2px; word-break: break-all; }
.prot-tag { color: #fa8c16; font-size: 11px; margin-left: 4px; }
</style>
