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
    <a-input v-model:value="codeFilter" placeholder="码：200 / 200-399 / 4xx" allow-clear
             size="small" style="width: 160px; margin-left: auto" />
    <a-input v-model:value="kw" placeholder="搜索 URL / 标题 / 指纹 / 标签" allow-clear
             size="small" style="width: 220px; margin-left: 8px" />
    <span class="toolbar-count">
      {{ flat.length }} 条结果<template v-if="dupTotal">（合并 {{ dupTotal }} 条相同）</template>
    </span>
    <a-popover trigger="click" placement="bottomRight">
      <a-button size="small">列设置</a-button>
      <template #content>
        <a-checkbox-group v-model:value="visibleCols" style="display:grid;gap:6px">
          <a-checkbox v-for="c in cols.filter(x => !FIXED_COLS.includes(x.key))"
                      :key="c.key" :value="c.key">{{ c.title }}</a-checkbox>
        </a-checkbox-group>
      </template>
    </a-popover>
  </div>
  <a-table :data-source="flat" :columns="shownCols" row-key="key" size="small"
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
      <template v-else-if="column.key === 'pkt'">
        <a v-if="!record.isAlike && record.has_response" @click.stop="openPkt(record)">查看</a>
        <span v-else-if="!record.isAlike" style="color: #d9d9d9">-</span>
      </template>
      <template v-else-if="column.key === 'source'">
        <span class="mono" style="font-size: 11px; color: #8c8c8c; word-break: break-all">
          {{ record.source || '-' }}
        </span>
      </template>
    </template>
  </a-table>

  <a-modal v-model:open="pkt.open" title="回显数据包" width="880px" :footer="null">
    <div class="mono" style="font-size: 12px; color: #8c8c8c; word-break: break-all">
      {{ pkt.url }}
    </div>
    <div v-if="pkt.loading" style="text-align: center; padding: 24px"><a-spin /></div>
    <template v-else>
      <div class="fp-ev-list" v-if="pktFps.length">
        <div v-for="f in pktFps" :key="f.name" class="fp-ev">
          <a-tag :color="lvColor(level(f))" class="fp-ev-tag"
                 :style="activeFp === f.name ? 'outline:2px solid #1677ff' : ''"
                 @click="activeFp = activeFp === f.name ? null : f.name">
            {{ lvText(level(f)) }}·{{ f.name }}{{ f.version ? ' ' + f.version : '' }}
          </a-tag>
          <span v-for="(e, i) in f.evidence || []" :key="i" class="ev-line">
            {{ e.field }}{{ e.key ? '.' + e.key : '' }} ~ {{ shortPat(e.pattern) }}
          </span>
        </div>
        <div style="font-size: 11px; color: #bfbfbf">点击指纹可只看它的命中高亮</div>
      </div>
      <pre class="pkt-pre" v-html="pktHtml"></pre>
    </template>
  </a-modal>
</template>

<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import api from '../api'
import FpTags from './FpTags.vue'
import { loadColPrefs, saveColPrefs } from '../colprefs'

const props = defineProps({ runId: Number, filter: { type: String, default: '' } })
const results = ref([])
const loading = ref(false)
const expandedKeys = ref([])
const kw = ref('')
const codeFilter = ref('')
const sevSel = ref([])     // multi-select: [] = all levels
const tagSel = ref([])     // multi-select tag filter

// '200' | '200-399' | '4xx' -> [min,max] | null
function parseCodeRange(v) {
  v = (v || '').trim().toLowerCase()
  if (!v) return null
  let m = v.match(/^(\d)xx$/)
  if (m) return [m[1] * 100, m[1] * 100 + 99]
  m = v.match(/^(\d{3})\s*-\s*(\d{3})$/)
  if (m) return [+m[1], +m[2]]
  if (/^\d{3}$/.test(v)) return [+v, +v]
  return null
}

const SEV_OPTS = [
  { value: 0, label: '高危' }, { value: 1, label: '中危' },
  { value: 2, label: '信息' }, { value: 3, label: '噪声' },
]

function toggle(arr, v) {
  const i = arr.indexOf(v)
  if (i < 0) arr.push(v)
  else arr.splice(i, 1)
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
  const path = u.replace(/^[a-z]+:\/\/[^/]+/i, '')   // path only — never the host
  const isPage = r.status_code != null && r.status_code < 400 &&
    r.status_code !== 204 && (r.title || r.screenshot || r.surface)
  // 入口: entry evidence (content hint / admin keyword / entry-pattern
  // URL) AND an actually served page — dead rows, 403/404 blocks, intel
  // rows and unbypassed protection pages never count
  const blockedByProt = r.protection && !r.protection.includes('bypass')
  if (isPage && !blockedByProt &&
      (h === 'entry' || h === 'point:admin' || h === 'point:login'
       || h0 === 'admin' || h0 === 'auth' || ENTRY_RE.test(path)))
    t.push('entry')
  // 疑似入口: served a real page (status<400 with rendered evidence)
  if (isPage) t.push('entryq')
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
watch([kw, codeFilter, sevSel, tagSel], () => { page.value = 1 })

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
  { title: '详情', key: 'pkt', width: 56 },
  { title: '来源', key: 'source', width: 140, ellipsis: true },
]

// 列显示控制（#序号、URL、详情固定），与其余结果表同一套 colprefs
const FIXED_COLS = ['num', 'url', 'pkt']
const COL_STORE_KEY = 'exposure_result_cols'
const visibleCols = ref(
  loadColPrefs(COL_STORE_KEY, cols.map((c) => c.key), 1))
watch(visibleCols,
  (v) => saveColPrefs(COL_STORE_KEY, v, cols.map((c) => c.key), 1))
const shownCols = computed(() =>
  cols.filter((c) => FIXED_COLS.includes(c.key) || visibleCols.value.includes(c.key)))

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
  const codeRange = parseCodeRange(codeFilter.value)
  const match = (r) => {
    if (sevSel.value.length && !sevSel.value.includes(sevOf(r))) return false
    if (tagSel.value.length && !tagsOf(r).some((t) => tagSel.value.includes(t)))
      return false
    if (codeRange && (r.status_code == null
        || r.status_code < codeRange[0] || r.status_code > codeRange[1]))
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

// ---- response packet viewer with fingerprint-evidence highlights ----
const pkt = reactive({ open: false, loading: false, url: '', response: '', fingerprints: '' })
const activeFp = ref(null)

async function openPkt(r) {
  pkt.open = true
  pkt.loading = true
  pkt.url = r.url
  pkt.response = ''
  pkt.fingerprints = r.fingerprints || ''
  activeFp.value = null
  try {
    const { data } = await api.exposureRowResponse(r.id)
    pkt.response = data.response || ''
    pkt.fingerprints = data.fingerprints || pkt.fingerprints
  } finally {
    pkt.loading = false
  }
}

const pktFps = computed(() => {
  try { return JSON.parse(pkt.fingerprints || '[]') || [] }
  catch { return [] }
})

const LV = {
  confirmed: { text: '确认', color: 'green', hex: '#52c41a' },
  high: { text: '高可信', color: 'orange', hex: '#fa8c16' },
  low: { text: '低可信', color: 'default', hex: '#8c8c8c' },
}
const lvText = (l) => (LV[l] || LV.low).text
const lvColor = (l) => (LV[l] || LV.low).color
const lvHex = (l) => (LV[l] || LV.low).hex

function level(f) {
  if (f.level) return f.level
  if (f.confidence === 'implied') return 'low'
  const fields = new Set((f.evidence || []).map((e) => e.field))
  if (['probe', 'favicon', 'dom'].some((x) => fields.has(x))) return 'confirmed'
  return (f.score || 0) >= 100 ? 'high' : 'low'
}

const shortPat = (p) => String(p || '').split('\\;')[0].slice(0, 80)
const escHtml = (s) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
// evidence fields that exist as runtime data, not literal packet text
const SKIP_HL = new Set(['dom', 'favicon', 'implies', 'js', 'xhr'])

const pktHtml = computed(() => {
  const reqEnd = `GET ${pkt.url} HTTP/1.1\n`.length
  const text = `GET ${pkt.url} HTTP/1.1\n` + (pkt.response || '')
  const bodyStart = text.indexOf('\n\n') + 2 || text.length
  const spans = []
  // run a pattern inside a bounded region only — evidence is credited to
  // the exact place its field matched, not anywhere in the packet
  const addPat = (pat, region, color) => {
    try {
      const rx = new RegExp(pat, 'gi')
      const slice = text.slice(region[0], region[1])
      let m, n = 0
      while ((m = rx.exec(slice)) && n++ < 60) {
        if (!m[0]) { rx.lastIndex++; continue }
        spans.push({
          s: region[0] + m.index,
          e: region[0] + m.index + m[0].length, color,
        })
      }
    } catch { /* python-only regex syntax — listed but unlit */ }
  }
  for (const f of pktFps.value) {
    if (activeFp.value && f.name !== activeFp.value) continue
    const color = lvHex(level(f))
    for (const e of f.evidence || []) {
      if (!e.pattern || SKIP_HL.has(e.field)) continue
      const pat = String(e.pattern).split('\\;')[0]
      if (e.field === 'headers' || e.field === 'cookies') {
        // only inside that header's own line
        const keyRx = new RegExp(`^${escRe(e.key)}\\s*:.*$`, 'gim')
        const km = keyRx.exec(text)
        if (km) addPat(pat, [km.index, km.index + km[0].length], color)
      } else if (e.field === 'meta' && e.key) {
        const keyRx = new RegExp(
          `<meta[^>]*(?:name|property)=["']?${escRe(e.key)}["']?[^>]*>`, 'gi')
        const km = keyRx.exec(text)
        if (km) addPat(pat, [km.index, km.index + km[0].length], color)
      } else if (e.field === 'url' || e.field === 'probe') {
        addPat(e.field === 'probe' && e.key ? escRe(e.key) : pat,
               [0, reqEnd + 4], color)   // the request line only
      } else {
        // html / scripts / scriptSrc → body only, never headers
        if (bodyStart < text.length) addPat(pat, [bodyStart, text.length], color)
      }
    }
  }
  spans.sort((a, b) => a.s - b.s || b.e - a.e)
  let html = '', pos = 0
  for (const sp of spans) {
    if (sp.s < pos) continue
    html += escHtml(text.slice(pos, sp.s))
      + `<mark style="background:${sp.color}2e;outline:1px solid ${sp.color}">`
      + escHtml(text.slice(sp.s, sp.e)) + '</mark>'
    pos = sp.e
  }
  return html + escHtml(text.slice(pos))
})

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
.fp-ev-list { margin: 10px 0; max-height: 180px; overflow-y: auto; }
.fp-ev { margin-bottom: 5px; }
.fp-ev-tag { cursor: pointer; }
.ev-line {
  font-size: 11px;
  color: #8c8c8c;
  font-family: ui-monospace, monospace;
  margin-left: 8px;
  word-break: break-all;
}
.pkt-pre {
  max-height: 460px;
  overflow: auto;
  background: #f6f8fa;
  border: 1px solid #eaecef;
  border-radius: 6px;
  font-size: 11.5px;
  line-height: 1.55;
  padding: 10px;
  white-space: pre-wrap;
  word-break: break-all;
}
.pkt-pre mark { padding: 0 1px; border-radius: 2px; }
.toolbar-count { font-size: 12px; color: #8c8c8c; margin-left: auto; }
.num { font-size: 12px; color: #595959; font-weight: 500; white-space: nowrap; }
.num-sub { font-size: 11px; color: #bfbfbf; white-space: nowrap; }
.alike-url { color: #8c8c8c; font-size: 12px; word-break: break-all; }
.sub-line { font-size: 11px; color: #a6a6a6; margin-top: 2px; word-break: break-all; }
.prot-tag { color: #fa8c16; font-size: 11px; margin-left: 4px; }
</style>
