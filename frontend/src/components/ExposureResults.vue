<template>
  <a-table :data-source="groups" :columns="cols" row-key="key" size="small"
           :pagination="false" :loading="loading"
           :expanded-row-keys="expandedKeys" @update:expandedRowKeys="expandedKeys = $event"
           :scroll="{ y: 560 }">
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'url'">
        <template v-if="record.isGroup">
          <span class="group-url">
            <LinkOutlined /> {{ record.url }}
            <a-tag color="default" style="margin-left: 8px">{{ record.count }} 个攻击面</a-tag>
            <a-tag v-for="k in record.kindSet" :key="k" :color="kindColor(k)" style="margin-left: 2px">
              {{ kindLabel(k) }}
            </a-tag>
          </span>
        </template>
        <a v-else :href="record.url" target="_blank" rel="noopener" class="mono"
           style="word-break: break-all">{{ record.url }}</a>
      </template>
      <template v-else-if="column.key === 'kind'">
        <a-tag v-if="!record.isGroup" :color="kindColor(record.kind)">
          {{ kindLabel(record.kind) }}
        </a-tag>
      </template>
      <template v-else-if="column.key === 'status'">
        <template v-if="!record.isGroup">
          <a-tag v-if="record.status_code" :color="statusColor(record.status_code)">
            {{ record.status_code }}
          </a-tag>
          <a-tag v-else-if="record.alive === 0" color="default">失活</a-tag>
          <span v-else>-</span>
        </template>
      </template>
      <template v-else-if="column.key === 'hint'">
        <a-tag v-if="!record.isGroup && record.hint && record.hint !== 'other'"
               :color="hintColor(record.hint)">
          {{ record.hint }}
        </a-tag>
        <span v-else-if="!record.isGroup" style="color: #bfbfbf">-</span>
      </template>
      <template v-else-if="column.key === 'fingerprints'">
        <template v-if="!record.isGroup">
          <a-tag v-for="f in fpList(record.fingerprints)" :key="f.name"
                 :color="f.confirmed ? 'green' : 'orange'" style="margin-bottom: 2px">
            {{ f.name }}{{ f.version ? ' ' + f.version : '' }}
          </a-tag>
          <span v-if="record.protection" class="prot-tag">🛡 {{ record.protection }}</span>
        </template>
      </template>
      <template v-else-if="column.key === 'screenshot'">
        <a-image v-if="!record.isGroup && record.screenshot"
                 :src="`/screenshots/${record.screenshot}`" :width="72"
                 style="border: 1px solid #f0f0f0; border-radius: 4px" />
        <span v-else-if="!record.isGroup" style="color: #bfbfbf">-</span>
      </template>
      <template v-else-if="column.key === 'title'">
        <span v-if="!record.isGroup">{{ record.title || '-' }}</span>
      </template>
      <template v-else-if="column.key === 'source'">
        <span v-if="!record.isGroup" class="mono"
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

const props = defineProps({ runId: Number })
const results = ref([])
const loading = ref(false)
const expandedKeys = ref([])

const cols = [
  { title: 'URL / 攻击面', key: 'url' },
  { title: '方式', key: 'kind', width: 70 },
  { title: '状态', key: 'status', width: 80 },
  { title: '分类', key: 'hint', width: 110 },
  { title: '指纹', key: 'fingerprints', width: 220 },
  { title: '截图', key: 'screenshot', width: 100 },
  { title: '标题', key: 'title', width: 160, ellipsis: true },
  { title: '来源', key: 'source', width: 200, ellipsis: true },
]

const kindColor = (k) =>
  ({ js: 'cyan', dir: 'blue', leak: 'magenta', vuln: 'red', point: 'volcano' })[k] || 'default'
const kindLabel = (k) =>
  ({ js: 'JS', dir: 'DIR', leak: '泄露', vuln: '漏洞', point: '攻击点' })[k] || k
const statusColor = (s) =>
  s < 300 ? 'green' : s < 400 ? 'geekblue' : s === 401 || s === 403 ? 'orange' : 'red'
const hintColor = (h) =>
  ({ admin: 'red', api: 'geekblue', upload: 'orange', auth: 'purple',
     config: 'gold', debug: 'cyan', vuln: 'red', leak: 'magenta',
     point: 'volcano' })[String(h).split(':')[0]] || 'default'

const fpList = (raw) => {
  if (!raw) return []
  try {
    const arr = JSON.parse(raw)
    return arr.map(f => ({ name: f.name, version: f.version, confirmed: f.confirmed !== false }))
  } catch { return [] }
}

const groups = computed(() => {
  const m = new Map()
  for (const r of results.value) {
    const k = r.target_url || '未关联目标'
    if (!m.has(k)) m.set(k, [])
    m.get(k).push(r)
  }
  const out = []
  for (const [u, rs] of m.entries()) {
    out.push({
      key: 'g-' + u, url: u, isGroup: true, count: rs.length,
      kindSet: [...new Set(rs.map(x => x.kind))],
      children: rs.map(x => ({ ...x, key: 'r-' + x.id })),
    })
  }
  return out
})

onMounted(async () => {
  loading.value = true
  try {
    const { data } = await api.getExposure(props.runId)
    results.value = data.results
    expandedKeys.value = [...new Set(data.results.map(r => 'g-' + (r.target_url || '未关联目标')))]
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.group-url { font-weight: 600; font-size: 13px; }
.prot-tag { color: #fa8c16; font-size: 11px; margin-left: 4px; }
</style>
