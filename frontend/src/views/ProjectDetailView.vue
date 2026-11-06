<template>
  <div class="page">
    <a-breadcrumb style="margin-bottom: 16px">
      <a-breadcrumb-item><router-link to="/projects">项目</router-link></a-breadcrumb-item>
      <a-breadcrumb-item>{{ project?.name }}</a-breadcrumb-item>
    </a-breadcrumb>

    <a-card :bordered="false" style="margin-bottom: 16px">
      <a-row :gutter="24" align="middle">
        <a-col :flex="1">
          <div class="page-title">{{ project?.name }}</div>
          <div style="color: #737373; margin-top: 4px">{{ project?.description }}</div>
        </a-col>
        <a-col><a-statistic title="目标" :value="project?.targets?.length || 0" /></a-col>
        <a-col><a-statistic title="存活" :value="aliveCount" /></a-col>
        <a-col><a-statistic title="扫描轮次" :value="project?.scans?.length || 0" /></a-col>
        <a-col>
          <a-space>
            <a-button @click="showImport = true">导入目标</a-button>
            <a-button
              type="primary"
              :disabled="!project?.targets?.length || !!running"
              @click="showScan = true"
            >
              发起扫描
            </a-button>
            <a-button
              :disabled="!aliveCount || !!running"
              @click="rescanAlive"
            >
              二次扫描（存活目标）
            </a-button>
          </a-space>
        </a-col>
      </a-row>
      <a-progress
        v-if="running"
        :percent="running.total ? Math.round((running.done / running.total) * 100) : 0"
        :format="() => `${running.done}/${running.total}`"
        style="margin-top: 16px"
        status="active"
      />
    </a-card>

    <a-card :bordered="false">
      <a-tabs v-model:activeKey="tab">
        <a-tab-pane key="targets" :tab="`目标 (${project?.targets?.length || 0})`">
          <a-table
            :data-source="targetRows"
            :columns="targetCols"
            row-key="id"
            size="middle"
            :pagination="{ pageSize: 20, showSizeChanger: true }"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'status'">
                <a-badge v-if="record.latest" :status="record.latest.alive ? 'success' : 'error'"
                         :text="record.latest.alive ? '存活' : '失活'" />
                <a-tag v-if="record.latest?.protection" color="volcano"
                       style="margin-left: 4px">防护</a-tag>
                <span v-if="!record.latest" style="color: #a6a6a6">未扫描</span>
              </template>
              <template v-else-if="column.key === 'code'">
                <a-tag v-if="record.latest?.status_code">{{ record.latest.status_code }}</a-tag>
                <span v-else>-</span>
              </template>
              <template v-else-if="column.key === 'fps'">
                <template v-for="f in record.fps" :key="f.name">
                  <a-tag :color="catColor(f.category)">
                    {{ f.name }}{{ f.version ? ' ' + f.version : '' }}
                  </a-tag>
                </template>
              </template>
              <template v-else-if="column.key === 'shot'">
                <a-image v-if="record.latest?.screenshot" class="shot-thumb"
                         :src="`/screenshots/${record.latest.screenshot}`" />
                <span v-else>-</span>
              </template>
              <template v-else-if="column.key === 'op'">
                <a-space>
                  <router-link v-if="record.latest" :to="`/results/${record.latest.id}`">详情</router-link>
                  <a-popconfirm title="删除该目标？" @confirm="delTarget(record.id)">
                    <a style="color: #cf1322">删除</a>
                  </a-popconfirm>
                </a-space>
              </template>
            </template>
          </a-table>
        </a-tab-pane>

        <a-tab-pane key="scans" :tab="`扫描记录 (${project?.scans?.length || 0})`">
          <a-table
            :data-source="project?.scans || []"
            :columns="scanCols"
            row-key="id"
            size="middle"
            :pagination="{ pageSize: 10 }"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'kind'">
                <a-tag :color="record.kind === 'rescan' ? 'purple' : 'blue'">
                  {{ record.kind === 'rescan' ? '二次扫描' : '全量扫描' }}
                </a-tag>
              </template>
              <template v-else-if="column.key === 'status'">
                <a-badge
                  :status="record.status === 'running' ? 'processing'
                         : record.status === 'done' ? 'success' : 'error'"
                  :text="record.status === 'running'
                         ? `${record.done}/${record.total}`
                         : record.status"
                />
              </template>
            </template>
            <template #expandedRowRender="{ record }">
              <a-table
                :data-source="scanResults[record.id] || []"
                :columns="resultCols"
                row-key="id"
                size="small"
                :pagination="{ pageSize: 10 }"
              >
                <template #bodyCell="{ column, record: r }">
                  <template v-if="column.key === 'alive'">
                    <a-badge :status="r.alive ? 'success' : 'error'"
                             :text="r.alive ? '存活' : '失活'" />
                  </template>
                  <template v-else-if="column.key === 'fps'">
                    <a-tag v-for="f in parseFps(r)" :key="f.name" :color="catColor(f.category)">
                      {{ f.name }}{{ f.version ? ' ' + f.version : '' }}
                    </a-tag>
                  </template>
                  <template v-else-if="column.key === 'shot'">
                    <router-link v-if="r.screenshot" :to="`/results/${r.id}`">
                      <img class="shot-thumb" :src="`/screenshots/${r.screenshot}`" />
                    </router-link>
                    <span v-else>-</span>
                  </template>
                </template>
              </a-table>
            </template>
            <template #expandColumnTitle>
              <span />
            </template>
          </a-table>
        </a-tab-pane>
      </a-tabs>
    </a-card>

    <!-- 导入目标 -->
    <a-modal v-model:open="showImport" title="导入目标" ok-text="导入" cancel-text="取消"
             @ok="doImport">
      <a-tabs>
        <a-tab-pane key="text" tab="粘贴 URL">
          <a-textarea v-model:value="importText" :rows="8"
                      placeholder="每行一个，支持 http(s)://host/path、域名、IP:端口" />
        </a-tab-pane>
        <a-tab-pane key="file" tab="上传 xlsx / txt">
          <a-upload-dragger :before-upload="pickFile" :max-count="1" accept=".xlsx,.txt,.csv">
            <p style="padding: 24px 0">点击或拖拽文件到此处（xlsx 会自动提取所有 URL）</p>
          </a-upload-dragger>
          <div v-if="importFile" style="margin-top: 8px" class="mono">{{ importFile.name }}</div>
        </a-tab-pane>
      </a-tabs>
    </a-modal>

    <!-- 发起扫描 -->
    <a-modal v-model:open="showScan" title="发起扫描" ok-text="开始" cancel-text="取消"
             @ok="startScan()">
      <a-form layout="vertical">
        <a-form-item label="扫描范围">
          <a-radio-group v-model:value="scanOpts.scope">
            <a-radio value="all">全部目标（{{ project?.targets?.length || 0 }}）</a-radio>
            <a-radio value="alive">仅存活目标（{{ aliveCount }}，二次扫描）</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item label="主动探测（请求特征路径二次确认，可提高精度）">
          <a-switch v-model:checked="scanOpts.active_probe" />
        </a-form-item>
        <a-form-item label="网页截图（Playwright，同时采集渲染后 DOM/JS 信号）">
          <a-switch v-model:checked="scanOpts.screenshot" />
        </a-form-item>
        <a-form-item label="并发数">
          <a-input-number v-model:value="scanOpts.concurrency" :min="1" :max="200" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import api from '../api'

const props = defineProps({ id: String })
const pid = Number(props.id)

const project = ref(null)
const running = ref(null)
const scanResults = reactive({})
const tab = ref('targets')
const showImport = ref(false)
const showScan = ref(false)
const importText = ref('')
const importFile = ref(null)
const scanOpts = reactive({ scope: 'all', active_probe: true, screenshot: true, concurrency: 50 })
let timer = null

const CAT_COLORS = {
  CMS: 'blue', 'JavaScript framework': 'geekblue', 'JavaScript library': 'cyan',
  'UI framework': 'cyan', 'JavaScript graphics': 'cyan', 'Build tool': 'cyan',
  'Web framework': 'geekblue', Runtime: 'geekblue', 'Programming language': 'geekblue',
  'Web server': 'purple', 'CDN/WAF': 'red', WAF: 'red',
  OA: 'orange', ERP: 'orange', Middleware: 'gold', 'Ops panel': 'gold',
  'DevOps': 'green', 'CI/CD': 'green', 'Database tool': 'green',
  Analytics: 'green', 'API tool': 'green', '防护页': 'volcano',
}
const catColor = (c) => CAT_COLORS[c] || 'default'

const aliveCount = computed(() => {
  if (!project.value?.latest) return 0
  return Object.values(project.value.latest).filter((r) => r.alive).length
})

const targetRows = computed(() =>
  (project.value?.targets || []).map((t) => {
    const latest = project.value.latest?.[String(t.id)] || null
    return { ...t, latest, fps: latest ? parseFps(latest) : [] }
  })
)

function parseFps(r) {
  try {
    return JSON.parse(r.fingerprints || '[]')
  } catch {
    return []
  }
}

const targetCols = [
  { title: 'URL', dataIndex: 'url', ellipsis: true },
  { title: '状态', key: 'status', width: 90 },
  { title: 'HTTP', key: 'code', width: 80 },
  { title: '标题', dataIndex: ['latest', 'title'], ellipsis: true, customRender: ({ record }) => record.latest?.title || '-' },
  { title: '指纹', key: 'fps' },
  { title: '截图', key: 'shot', width: 140 },
  { title: '操作', key: 'op', width: 110 },
]

const scanCols = [
  { title: '#', dataIndex: 'id', width: 70 },
  { title: '类型', key: 'kind', width: 110 },
  { title: '状态', key: 'status', width: 130 },
  { title: '存活/总数', customRender: ({ record: r }) => `${r.alive}/${r.total}`, width: 110 },
  { title: '开始时间', dataIndex: 'started_at', width: 200 },
  { title: '结束时间', dataIndex: 'finished_at', width: 200, customRender: ({ text }) => text || '-' },
]

const resultCols = [
  { title: '状态', key: 'alive', width: 80 },
  { title: 'URL', dataIndex: 'final_url', ellipsis: true },
  { title: 'HTTP', dataIndex: 'status_code', width: 80 },
  { title: '标题', dataIndex: 'title', ellipsis: true },
  { title: '指纹', key: 'fps' },
  { title: '截图', key: 'shot', width: 140 },
]

async function load() {
  const { data } = await api.getProject(pid)
  project.value = data
  running.value = data.running
  for (const s of data.scans) {
    if (!scanResults[s.id] && s.status === 'done') {
      loadScanResults(s.id)
    }
  }
  if (running.value && !timer) startPolling()
}

async function loadScanResults(sid) {
  const { data } = await api.getScan(sid)
  scanResults[sid] = data.results
}

function startPolling() {
  timer = setInterval(async () => {
    await load()
    if (!running.value) {
      clearInterval(timer)
      timer = null
      const last = project.value?.scans?.[0]
      if (last) await loadScanResults(last.id)
      message.success('扫描完成')
    }
  }, 2500)
}

function pickFile(file) {
  importFile.value = file
  return false
}

async function doImport() {
  try {
    let res
    if (importFile.value) {
      res = (await api.uploadTargets(pid, importFile.value)).data
    } else {
      res = (await api.addTargets(pid, importText.value)).data
    }
    message.success(`解析 ${res.parsed} 个，新增 ${res.added}，重复 ${res.duplicates}`)
    showImport.value = false
    importText.value = ''
    importFile.value = null
    load()
  } catch (e) {
    message.error(e.response?.data?.detail || '导入失败')
  }
}

async function startScan(opts) {
  const o = opts || { ...scanOpts }
  if (o.scope === 'alive' && !aliveCount.value) return message.warning('没有存活目标')
  try {
    await api.createScan(pid, o)
    showScan.value = false
    message.success('扫描已开始')
    load()
  } catch (e) {
    message.error(e.response?.data?.detail || '启动失败')
  }
}

function rescanAlive() {
  startScan({ scope: 'alive', active_probe: true, screenshot: true, concurrency: 50 })
}

async function delTarget(tid) {
  await api.deleteTarget(tid)
  load()
}

onMounted(load)
onBeforeUnmount(() => timer && clearInterval(timer))
</script>
