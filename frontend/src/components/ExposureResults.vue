<template>
  <a-table :data-source="results" :columns="cols" row-key="id" size="small"
           :pagination="{ pageSize: 10 }" :loading="loading">
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'kind'">
        <a-tag :color="{ js: 'cyan', dir: 'blue', leak: 'magenta', vuln: 'red', point: 'volcano' }[record.kind] || 'default'">
          {{ { js: 'JS', dir: 'DIR', leak: '泄露', vuln: '漏洞', point: '攻击点' }[record.kind] || record.kind }}
        </a-tag>
      </template>
      <template v-else-if="column.key === 'url'">
        <a :href="record.url" target="_blank" rel="noopener" class="mono"
           style="word-break: break-all">{{ record.url }}</a>
      </template>
      <template v-else-if="column.key === 'status'">
        <a-tag v-if="record.status_code" :color="statusColor(record.status_code)">
          {{ record.status_code }}
        </a-tag>
        <span v-else>-</span>
      </template>
      <template v-else-if="column.key === 'hint'">
        <a-tag v-if="record.hint && record.hint !== 'other'" :color="hintColor(record.hint)">
          {{ record.hint }}
        </a-tag>
        <span v-else style="color: #bfbfbf">-</span>
      </template>
      <template v-else-if="column.key === 'source'">
        <span class="mono" style="font-size: 11px; color: #8c8c8c; word-break: break-all">
          {{ record.source || record.target_url }}
        </span>
      </template>
    </template>
  </a-table>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import api from '../api'

const props = defineProps({ runId: Number })
const results = ref([])
const loading = ref(false)

const cols = [
  { title: '方式', key: 'kind', width: 60 },
  { title: 'URL', key: 'url' },
  { title: '状态', key: 'status', width: 80 },
  { title: '分类', key: 'hint', width: 110 },
  { title: '标题', dataIndex: 'title', width: 180, ellipsis: true, customRender: ({ text }) => text || '-' },
  { title: '来源', key: 'source', width: 220, ellipsis: true },
]

const statusColor = (s) =>
  s < 300 ? 'green' : s < 400 ? 'geekblue' : s === 401 || s === 403 ? 'orange' : 'red'
const hintColor = (h) =>
  ({ admin: 'red', api: 'geekblue', upload: 'orange', auth: 'purple',
     config: 'gold', debug: 'cyan', vuln: 'red', leak: 'magenta',
     point: 'volcano' })[h.split(':')[0]] || 'default'

onMounted(async () => {
  loading.value = true
  try {
    results.value = (await api.getExposure(props.runId)).data.results
  } finally {
    loading.value = false
  }
})
</script>
