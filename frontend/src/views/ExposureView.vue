<template>
  <div class="page">
    <div class="page-header">
      <div>
        <div class="page-title">暴露面测绘</div>
        <div class="page-sub">JS 接口提取 · 目录爆破 · 敏感信息/攻击点/源码泄露检测 · 攻击面深扫</div>
      </div>
    </div>

    <a-row :gutter="16" style="margin-bottom: 4px">
      <a-col :span="6">
        <a-card :bordered="false" class="stat-card">
          <div class="stat-label"><RadarChartOutlined /> 测绘轮次</div>
          <div class="stat-num">{{ stats.runs ?? '-' }}</div>
          <div class="stat-sub">覆盖 {{ stats.projects ?? '-' }} 个项目</div>
        </a-card>
      </a-col>
      <a-col :span="6">
        <a-card :bordered="false" class="stat-card">
          <div class="stat-label"><AimOutlined /> 攻击面</div>
          <div class="stat-num" style="color: var(--red)">{{ stats.surfaces ?? '-' }}</div>
          <div class="stat-sub">已验证与首页不同的页面</div>
        </a-card>
      </a-col>
      <a-col :span="6">
        <a-card :bordered="false" class="stat-card">
          <div class="stat-label"><InfoCircleOutlined /> 信息</div>
          <div class="stat-num">{{ stats.infos ?? '-' }}</div>
          <div class="stat-sub">JS/泄露/攻击点等待验证线索</div>
        </a-card>
      </a-col>
      <a-col :span="6">
        <a-card :bordered="false" class="stat-card">
          <div class="stat-label"><DatabaseOutlined /> 发现总数</div>
          <div class="stat-num">{{ stats.findings ?? '-' }}</div>
          <div class="stat-sub">JS接口 · 目录 · 子域 · 测绘资产</div>
        </a-card>
      </a-col>
    </a-row>

    <a-card :bordered="false" title="测绘记录" style="margin-bottom: 16px">
      <template #extra>
        <a-button type="primary" size="small" @click="showScan = true">
          <template #icon><RadarChartOutlined /></template>发起测绘
        </a-button>
      </template>
      <a-table :data-source="runs" :columns="runCols" row-key="id" size="small"
               :pagination="{ defaultPageSize: 8, showSizeChanger: true, showQuickJumper: true,
                             showTotal: (t) => `共 ${t} 条` }" :loading="loading"
               :custom-row="rowClick" :row-class-name="rowClass">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'project'">
            {{ record.project_name }}
          </template>
          <template v-else-if="column.key === 'kinds'">
            <a-tag v-for="k in parseKinds(record)" :key="k" :color="kindColor(k)">
              {{ kindLabel(k) }}
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
            <a-space :size="6" wrap>
              <a-button size="small" @click.stop="viewRun(record)">查看</a-button>
              <a-button v-if="record.status === 'done' && record.deep_status !== 'running'"
                        size="small" @click.stop="deepScan(record.id)">
                {{ record.deep_status === 'done' ? '重新深扫' : '深扫' }}
              </a-button>
              <a-button v-if="record.status === 'done'" size="small"
                        @click.stop="showDiff(record)">对比</a-button>
              <a-dropdown v-if="record.status === 'done'">
                <a-button size="small" @click.stop>导出</a-button>
                <template #overlay>
                  <a-menu @click="({ key }) => download(record.id, key)">
                    <a-menu-item key="csv">CSV</a-menu-item>
                    <a-menu-item key="xlsx">Excel</a-menu-item>
                  </a-menu>
                </template>
              </a-dropdown>
              <a-popconfirm title="删除该次测绘及结果？" @confirm="del(record.id)">
                <a-button size="small" danger @click.stop>删除</a-button>
              </a-popconfirm>
            </a-space>
          </template>
        </template>
      </a-table>
      <a-empty v-if="!loading && !runs.length">
        <template #description>
          还没有测绘记录
          <a-button type="primary" size="small" @click="showScan = true">立即发起测绘</a-button>
        </template>
      </a-empty>
    </a-card>

    <a-modal v-model:open="diff.open" title="与上一轮对比" width="760px" :footer="null">
      <div v-if="diff.loading" style="text-align: center; padding: 32px"><a-spin /></div>
      <template v-else-if="diff.data">
        <a-empty v-if="!diff.data.prev" description="该项目第一轮已完成的测绘，无可对比对象" />
        <template v-else>
          <div style="margin-bottom: 12px">
            vs 测绘 #{{ diff.data.prev }}（{{ diff.data.prev_time || '-' }}）
            <a-tag color="green">+{{ diff.data.new_count }} 新增</a-tag>
            <a-tag>-{{ diff.data.gone_count }} 消失</a-tag>
            <a-tag color="orange">~{{ diff.data.changed_count }} 变化</a-tag>
          </div>
          <a-tabs size="small">
            <a-tab-pane key="new" :tab="`新增 ${diff.data.new_count}`">
              <a-table :data-source="diff.data.new" :columns="diffCols"
                       size="small" :pagination="{ defaultPageSize: 10 }" row-key="url" />
            </a-tab-pane>
            <a-tab-pane key="gone" :tab="`消失 ${diff.data.gone_count}`">
              <a-table :data-source="diff.data.gone" :columns="diffCols"
                       size="small" :pagination="{ defaultPageSize: 10 }" row-key="url" />
            </a-tab-pane>
            <a-tab-pane key="changed" :tab="`变化 ${diff.data.changed_count}`">
              <a-table :data-source="diff.data.changed" :columns="diffChangedCols"
                       size="small" :pagination="{ defaultPageSize: 10 }" row-key="url" />
            </a-tab-pane>
          </a-tabs>
        </template>
      </template>
    </a-modal>

    <ExposureScanModal v-model:open="showScan" @started="load" />

    <a-card v-if="selected" :bordered="false" :key="selected.id" id="exp-result-card">
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
import { nextTick, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { AimOutlined, DatabaseOutlined, InfoCircleOutlined, RadarChartOutlined } from '@ant-design/icons-vue'
import api from '../api'
import ExposureResults from '../components/ExposureResults.vue'
import ExposureScanModal from '../components/ExposureScanModal.vue'

const runs = ref([])
const stats = ref({})
const loading = ref(false)
const selected = ref(null)
const showScan = ref(false)
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
  { title: '操作', key: 'op', width: 240 },
]

const parseKinds = (r) => {
  try {
    return JSON.parse(r.options || '{}').kinds || []
  } catch {
    return []
  }
}

const KIND_LABEL = {
  js: 'JS接口', dir: '目录爆破', sub: '子域名', brute: '子域爆破',
  host: 'Host碰撞', net: '网络空间', origin: '源站探测',
  takeover: '接管检测', wayback: '历史URL', port: '端口扫描',
}
const kindLabel = (k) => KIND_LABEL[k] || k
const kindColor = (k) =>
  ({ js: 'cyan', dir: 'blue', sub: 'purple', brute: 'purple',
     host: 'volcano', net: 'green', origin: 'red', takeover: 'red',
     wayback: 'geekblue', port: 'orange' })[k] || 'default'

const diffCols = [
  { title: 'URL', dataIndex: 'url', ellipsis: true },
  { title: '类型', dataIndex: 'kind', width: 80 },
  { title: '提示', dataIndex: 'hint', width: 110, ellipsis: true },
  { title: '状态', dataIndex: 'status_code', width: 70,
    customRender: ({ text }) => text ?? '-' },
]
const diffChangedCols = [
  { title: 'URL', dataIndex: 'url', ellipsis: true },
  { title: '状态', key: 'st', width: 110,
    customRender: ({ record }) => `${record.old_status ?? '-'} → ${record.new_status ?? '-'}` },
  { title: '旧标题', dataIndex: 'old_title', ellipsis: true },
  { title: '新标题', dataIndex: 'new_title', ellipsis: true },
]
const diff = reactive({ open: false, loading: false, data: null })

async function showDiff(record) {
  diff.open = true
  diff.loading = true
  diff.data = null
  try {
    diff.data = (await api.exposureDiff(record.id)).data
  } finally {
    diff.loading = false
  }
}

async function download(rid, fmt) {
  const { data } = await api.exportExposure(rid, fmt)
  const url = URL.createObjectURL(data)
  const a = document.createElement('a')
  a.href = url
  a.download = `exposure_${rid}.${fmt}`
  a.click()
  URL.revokeObjectURL(url)
}

function viewRun(record) {
  selected.value = record
  kw.value = ''
  // jump to the results panel — on long lists it can be out of view
  nextTick(() =>
    document.getElementById('exp-result-card')
      ?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
  )
}

const rowClick = (record) => ({ onClick: () => viewRun(record) })
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
    api.exposureStats().then(({ data }) => { stats.value = data }).catch(() => {})
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
.stat-card :deep(.ant-card-body) { padding: 16px 18px; }
.stat-label {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--gray-60);
  font-size: 12.5px;
}
.stat-num {
  font-size: 30px;
  font-weight: 600;
  line-height: 1.3;
  margin-top: 2px;
  color: var(--ink);
}
.stat-sub {
  font-size: 12px;
  color: var(--gray-60);
  margin-top: 2px;
}
</style>
