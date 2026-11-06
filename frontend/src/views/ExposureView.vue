<template>
  <div class="page">
    <div class="page-header">
      <div>
        <div class="page-title">暴露面测绘</div>
        <div class="page-sub">JS 接口提取 · 目录爆破 · 扩大存活资产攻击面</div>
      </div>
    </div>

    <a-card :bordered="false">
      <a-table :data-source="runs" :columns="runCols" row-key="id" size="small"
               :pagination="{ pageSize: 15 }" :loading="loading">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'project'">
            <router-link :to="`/projects/${record.project_id}`">{{ record.project_name }}</router-link>
          </template>
          <template v-else-if="column.key === 'kinds'">
            <a-tag v-for="k in parseKinds(record)" :key="k" :color="k === 'js' ? 'cyan' : 'blue'">
              {{ k === 'js' ? 'JS接口' : '目录爆破' }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'status'">
            <a-badge :status="{ running: 'processing', done: 'success' }[record.status] || 'error'"
                     :text="record.status === 'running' ? `${record.done}/${record.total}` : record.status" />
          </template>
          <template v-else-if="column.key === 'found'">
            <span :style="{ color: record.found ? 'var(--red)' : 'inherit', fontWeight: record.found ? 600 : 400 }">
              {{ record.found }}
            </span>
          </template>
          <template v-else-if="column.key === 'op'">
            <a-popconfirm title="删除该次测绘及结果？" @confirm="del(record.id)">
              <a style="color: #cf1322">删除</a>
            </a-popconfirm>
          </template>
        </template>

        <template #expandedRowRender="{ record }">
          <ExposureResults :run-id="record.id" />
        </template>
        <template #expandColumnTitle><span /></template>
      </a-table>
      <a-empty v-if="!loading && !runs.length" description="暂无测绘记录，到项目详情发起「暴露面扫描」" />
    </a-card>
  </div>
</template>

<script setup>
import { onBeforeUnmount, onMounted, ref } from 'vue'
import api from '../api'
import ExposureResults from '../components/ExposureResults.vue'

const runs = ref([])
const loading = ref(false)
let timer = null

const runCols = [
  { title: '#', dataIndex: 'id', width: 60 },
  { title: '项目', key: 'project' },
  { title: '方式', key: 'kinds', width: 160 },
  { title: '状态', key: 'status', width: 130 },
  { title: '发现', key: 'found', width: 80 },
  { title: '开始时间', dataIndex: 'started_at', width: 190 },
  { title: '结束时间', dataIndex: 'finished_at', width: 190, customRender: ({ text }) => text || '-' },
  { title: '操作', key: 'op', width: 70 },
]

const parseKinds = (r) => {
  try {
    return JSON.parse(r.options || '{}').kinds || []
  } catch {
    return []
  }
}

async function del(id) {
  await api.deleteExposure(id)
  load()
}

async function load() {
  loading.value = true
  try {
    runs.value = (await api.listExposureAll()).data
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  load()
  timer = setInterval(() => {
    if (runs.value.some((r) => r.status === 'running')) load()
  }, 3000)
})
onBeforeUnmount(() => timer && clearInterval(timer))
</script>
