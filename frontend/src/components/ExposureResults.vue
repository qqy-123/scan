<template>
  <a-table :data-source="groups" :columns="cols" row-key="key" size="small"
           :pagination="false" :loading="loading"
           :expanded-row-keys="expandedKeys" @update:expandedRowKeys="expandedKeys = $event"
           :scroll="{ y: 560 }">
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'url'">
        <template v-if="record.isSev">
          <span class="sev-url">
            <a-tag :color="SEV[record.sev].color" class="sev-tag">{{ SEV[record.sev].label }}</a-tag>
            {{ record.count }} 条结果
            <a-tag v-if="record.dupCount" style="margin-left: 8px">合并了 {{ record.dupCount }} 条相同记录</a-tag>
            <a-tag v-for="k in record.kindSet" :key="k" :color="kindColor(k)" style="margin-left: 2px">
              {{ kindLabel(k) }}
            </a-tag>
          </span>
        </template>
        <template v-else-if="record.isAlike">
          <span class="alike-url mono">└ {{ record.url }}</span>
        </template>
        <template v-else>
          <a :href="record.url" target="_blank" rel="noopener" class="mono"
             style="word-break: break-all">{{ record.url }}</a>
          <a-tag v-if="record._alike?.length" color="default" style="margin-left: 6px">
            ×{{ record._alike.length + 1 }} 相同
          </a-tag>
        </template>
      </template>
      <template v-else-if="column.key === 'level'">
        <a-tag v-if="!record.isSev && !record.isAlike" :color="record.surface ? 'red' : 'default'">
          {{ record.surface ? '攻击面' : '信息' }}
        </a-tag>
      </template>
      <template v-else-if="column.key === 'kind'">
        <a-tag v-if="!record.isSev" :color="kindColor(record.kind)">
          {{ kindLabel(record.kind) }}
        </a-tag>
      </template>
      <template v-else-if="column.key === 'status'">
        <template v-if="!record.isSev">
          <a-tag v-if="record.status_code" :color="statusColor(record.status_code)">
            {{ record.status_code }}
          </a-tag>
          <a-tag v-else-if="record.alive === 0" color="default">失活</a-tag>
          <span v-else>-</span>
        </template>
      </template>
      <template v-else-if="column.key === 'hint'">
        <a-tag v-if="!record.isSev && record.hint && record.hint !== 'other'"
               :color="hintColor(record.hint)">
          {{ record.hint }}
        </a-tag>
        <span v-else-if="!record.isSev" style="color: #bfbfbf">-</span>
      </template>
      <template v-else-if="column.key === 'fingerprints'">
        <template v-if="!record.isSev && !record.isAlike">
          <FpTags v-if="record.status_code || record.alive" :raw="record.fingerprints" />
          <span v-else style="color: #bfbfbf" title="未深扫">-</span>
          <span v-if="record.protection" class="prot-tag">🛡 {{ record.protection }}</span>
        </template>
      </template>
      <template v-else-if="column.key === 'screenshot'">
        <a-image v-if="!record.isSev && !record.isAlike && record.screenshot"
                 :src="`/screenshots/${record.screenshot}`" :width="72"
                 style="border: 1px solid #f0f0f0; border-radius: 4px" />
        <span v-else-if="!record.isSev" style="color: #bfbfbf">-</span>
      </template>
      <template v-else-if="column.key === 'title'">
        <span v-if="!record.isSev">{{ record.title || '-' }}</span>
      </template>
      <template v-else-if="column.key === 'source'">
        <span v-if="!record.isSev" class="mono"
              style="font-size: 11px; color: #8c8c8c; word-break: break-all">
          {{ record.source || '-' }}
        </span>
      </template>
    </template>
  </a-table>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { LinkOutlined } from '@ant-design/icons-vue'
import api from '../api'
import FpTags from './FpTags.vue'

const props = defineProps({ runId: Number, filter: { type: String, default: '' } })
const results = ref([])
const loading = ref(false)
const expandedKeys = ref([])

const cols = [
  { title: 'URL / 攻击面', key: 'url' },
  { title: '级别', key: 'level', width: 76 },
  { title: '方式', key: 'kind', width: 70 },
  { title: '状态', key: 'status', width: 80 },
  { title: '分类', key: 'hint', width: 110 },
  { title: '指纹', key: 'fingerprints', width: 220 },
  { title: '截图', key: 'screenshot', width: 100 },
  { title: '标题', key: 'title', width: 160, ellipsis: true },
  { title: '来源', key: 'source', width: 200, ellipsis: true },
]

const kindColor = (k) =>
  ({ js: 'cyan', dir: 'blue', leak: 'magenta', vuln: 'red', point: 'volcano',
     sub: 'purple', host: 'volcano', net: 'green' })[k] || 'default'
const kindLabel = (k) =>
  ({ js: 'JS', dir: 'DIR', leak: '泄露', vuln: '漏洞', point: '攻击点',
     sub: '子域', host: 'Host碰撞', net: '测绘' })[k] || k
const statusColor = (s) =>
  s < 300 ? 'green' : s < 400 ? 'geekblue' : s === 401 || s === 403 ? 'orange' : 'red'
const hintColor = (h) =>
  ({ admin: 'red', api: 'geekblue', upload: 'orange', auth: 'purple',
     config: 'gold', debug: 'cyan', vuln: 'red', leak: 'magenta',
     point: 'volcano' })[String(h).split(':')[0]] || 'default'

// ---------- 危害分级 ----------
// 0 高危: 漏洞页/高可信泄露/管理后台面  1 中危: 攻击点/泄露/Host碰撞/已验证攻击面
// 2 信息: 未验证的资产情报            3 噪声: 已探活但回声页/死链
const HIGH_LEAK = /rsa|private|aws|github|gitlab|token|jwt|secret|password|passwd|jdbc|oss|s3|shiro|cloud|aliyun|tencent|apikey|aksk|webhook/i
const ADMIN_URL = /(^|[\/_\-.])(admin|manager|manage|console|backend|backstage|druid|phpmyadmin|nacos|actuator|jolokia|jenkins|sonar|weblogic|grafana|kibana|harbor|rancher|zabbix|sentinel|xxl|apisix|portainer|minio|elasticsearch|swagger|dubbo|nexus|gitlab|gitea|jumpserver|waf)([\/_\-.?]|$)/i

function sevOf(r) {
  const h = r.hint || ''
  const u = (r.url || '').toLowerCase()
  if (h.startsWith('vuln:')) return 0
  if (h === 'point:admin') return 0
  if (h.startsWith('leak:') && HIGH_LEAK.test(h)) return 0
  if (r.surface && ADMIN_URL.test(u)) return 0
  if (h === 'host:vhost') return 1
  if (h.startsWith('point:')) return 1
  if (h.startsWith('leak:')) return 1
  if (r.surface) return 1
  if (r.status_code != null || r.alive === 0) return 3   // probed but echo/dead
  return 2                                              // unverified intel
}

const SEV = [
  { label: '高危', color: 'red', open: true },
  { label: '中危', color: 'orange', open: true },
  { label: '信息', color: 'blue', open: true },
  { label: '噪声', color: 'default', open: false },   // collapsed by default
]

// 相同返回算一个结果: 状态码+标题+长度桶 相同的探活行合并为代表+同类项
const sigOf = (r) =>
  r.status_code != null
    ? `${r.status_code}|${(r.title || '').trim().toLowerCase()}|${Math.round((r.length || 0) / 300)}`
    : null

// 同域名从多个来源发现(如 crt.name+brute+js)合并为一条
const INTEL_HINT_RANK = { 'sub:alive': 0, 'sub:dns': 1, 'sub:ct': 2, 'sub:echo': 3, 'sub:js': 4 }

const groups = computed(() => {
  const kw = (props.filter || '').trim().toLowerCase()
  const match = (r) => {
    if (!kw) return true
    const hay = [r.url, r.title, r.hint, r.source, r.fingerprints]
      .filter(Boolean).join(' ').toLowerCase()
    return hay.includes(kw)
  }
  const rows = results.value.filter(match)

  // pass 1: intel dedup by url — same asset discovered via several sources
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

  // group by severity
  const buckets = [[], [], [], []]
  for (const r of [...reps, ...intelReps]) buckets[sevOf(r)].push(r)
  const out = []
  buckets.forEach((rs, i) => {
    if (!rs.length) return
    rs.sort((a, b) =>
      (b.screenshot ? 1 : 0) - (a.screenshot ? 1 : 0)
      || (a.status_code || 999) - (b.status_code || 999) || a.url.localeCompare(b.url))
    out.push({
      key: `sev-${i}`, isSev: true, sev: i, count: rs.length,
      dupCount: rs.reduce((s, x) => s + (x._alike?.length || 0), 0),
      kindSet: [...new Set(rs.map((x) => x.kind))],
      children: rs.map((r) => ({
        ...r, key: `r-${r.id}`,
        children: (r._alike || []).map((a, j) => ({ ...a, isAlike: true, key: `a-${r.id}-${j}` })),
      })),
    })
  })
  return out
})

onMounted(async () => {
  loading.value = true
  try {
    const { data } = await api.getExposure(props.runId)
    results.value = data.results
    // 高危/中危/信息默认展开, 噪声折叠
    expandedKeys.value = SEV.map((s, i) => `sev-${i}`).filter((_, i) => SEV[i].open)
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.sev-url { font-weight: 600; font-size: 13px; }
.sev-tag { font-weight: 600; margin-right: 6px; }
.alike-url { color: #8c8c8c; font-size: 12px; word-break: break-all; }
.prot-tag { color: #fa8c16; font-size: 11px; margin-left: 4px; }
</style>
