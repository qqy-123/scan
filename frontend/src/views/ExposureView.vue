<template>
  <div class="page">
    <div class="page-header">
      <div>
        <div class="page-title">暴露面测绘</div>
        <div class="page-sub">JS 接口提取 · 目录爆破 · 敏感信息/攻击点/源码泄露检测 · 攻击面深扫</div>
      </div>
    </div>

    <a-card :bordered="false" title="测绘记录" style="margin-bottom: 16px">
      <a-table :data-source="runs" :columns="runCols" row-key="id" size="small"
               :pagination="{ pageSize: 8 }" :loading="loading"
               :custom-row="rowClick" :row-class-name="rowClass">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'project'">
            <router-link :to="`/projects/${record.project_id}`" @click.stop>{{ record.project_name }}</router-link>
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
          <template v-else-if="column.key === 'deep'">
            <a-badge v-if="record.deep_status === 'running'" status="processing"
                     :text="`深扫中 ${record.deep_done}/${record.deep_total}`" />
            <a-tag v-else-if="record.deep_status === 'done'" color="green">已深扫</a-tag>
            <a-tag v-else-if="record.deep_status === 'failed'" color="red">深扫失败</a-tag>
            <span v-else style="color: #bfbfbf">-</span>
          </template>
          <template v-else-if="column.key === 'op'">
            <a v-if="record.status === 'done' && record.deep_status !== 'running'"
               style="margin-right: 10px" @click.stop="deepScan(record.id)">
              {{ record.deep_status === 'done' ? '重新深扫' : '深扫' }}
            </a>
            <a-popconfirm title="删除该次测绘及结果？" @confirm="del(record.id)">
              <a style="color: #cf1322" @click.stop>删除</a>
            </a-popconfirm>
          </template>
        </template>
      </a-table>
      <a-empty v-if="!loading && !runs.length" description="暂无测绘记录，到项目详情发起「暴露面扫描」" />
    </a-card>

    <a-card v-if="selected" :bordered="false" :key="selected.id">
      <template #title>
        <span style="font-size: 14px">
          攻击面结果 · 测绘 #{{ selected.id }}
          <a-tag color="default" style="margin-left: 8px">{{ selected.project_name }}</a-tag>
          <a-tag :color="selected.found ? 'red' : 'default'">{{ selected.found }} 条发现</a-tag>
        </span>
      </template>
      <template #extra>
        <a-input-search v-model:value="kw" placeholder="过滤 URL / 标题 / 指纹"
                        style="width: 260px" size="small" allow-clear />
      </template>
      <ExposureResults :run-id="selected.id" :filter="kw" />
    </a-card>
  </div>
</template>

<script setup>
import { onBeforeUnmount, onMounted, ref } from 'vue'
import api from '../api'
import ExposureResults from '../components/ExposureResults.vue'

const runs = ref([])
const loading = ref(false)
const selected = ref(null)
const kw = ref('')
let timer = null

const runCols = [
  { title: '#', dataIndex: 'id', width: 60 },
  { title: '项目', key: 'project' },
  { title: '方式', key: 'kinds', width: 160 },
  { title: '状态', key: 'status', width: 130 },
  { title: '发现', key: 'found', width: 80 },
  { title: '深扫', key: 'deep', width: 140 },
  { title: '开始时间', dataIndex: 'started_at', width: 170 },
  { title: '结束时间', dataIndex: 'finished_at', width: 170, customRender: ({ text }) => text || '-' },
  { title: '操作', key: 'op', width: 120 },
]

const parseKinds = (r) => {
  try {
    return JSON.parse(r.options || '{}').kinds || []
  } catch {
    return []
  }
}

const rowClick = (record) => ({
  onClick: () => {
    selected.value = record
    kw.value = ''
  },
})
const rowClass = (record) => (selected.value?.id === record.id ? 'row-selected' : '')

async function deepScan(id) {
  try {
    await api.deepScanExposure(id, 120)
    load()
  } catch (e) {
    // silent
  }
}

async function del(id) {
  await api.deleteExposure(id)
  if (selected.value?.id === id) selected.value = null
  load()
}

async function load() {
  loading.value = true
  try {
    runs.value = (await api.listExposureAll()).data
    if (!selected.value && runs.value.length) {
      selected.value = runs.value.find((r) => r.status === 'done') || runs.value[0]
    } else if (selected.value) {
      // refresh selected run object (deep progress etc.)
      selected.value = runs.value.find((r) => r.id === selected.value.id) || selected.value
    }
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  load()
  timer = setInterval(() => {
    if (runs.value.some((r) => r.status === 'running' || r.deep_status === 'running')) load()
  }, 3000)
})
onBeforeUnmount(() => timer && clearInterval(timer))
</script>

<style>
.row-selected > td { background: #f0f5ff !important; }
</style>
