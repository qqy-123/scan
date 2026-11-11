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
        <a-col><a-statistic title="存活" :value="aliveCount" :value-style="{ color: '#52c41a' }" /></a-col>
        <a-col><a-statistic title="失活" :value="deadCount" :value-style="{ color: '#ff4d4f' }" /></a-col>
        <a-col><a-statistic title="未探测" :value="unscannedCount" /></a-col>
        <a-col><a-statistic title="扫描轮次" :value="project?.scans?.length || 0" /></a-col>
        <a-col>
          <a-space>
            <a-button @click="showImport = true">
              <template #icon><ImportOutlined /></template>导入目标
            </a-button>
            <a-button
              type="primary"
              :disabled="!project?.targets?.length || !!running"
              @click="showScan = true"
            >
              <template #icon><PlayCircleOutlined /></template>发起扫描
            </a-button>
            <a-button
              :disabled="!aliveCount || !!running"
              @click="rescanAlive"
            >
              <template #icon><ReloadOutlined /></template>二次扫描
            </a-button>
            <a-button
              :disabled="!aliveCount || !!expRunning"
              @click="showExposure = true"
            >
              <template #icon><RadarChartOutlined /></template>暴露面测绘
            </a-button>
            <a-dropdown>
              <a-button><template #icon><EllipsisOutlined /></template></a-button>
              <template #overlay>
                <a-menu>
                  <a-menu-item key="edit" @click="openEditProject">编辑项目</a-menu-item>
                  <a-menu-item key="delete" danger @click="delProject">删除项目</a-menu-item>
                </a-menu>
              </template>
            </a-dropdown>
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
          <a-space style="margin-bottom: 8px">
            <a-popconfirm :title="`删除选中的 ${targetSel.length} 个目标？`"
                          :disabled="!targetSel.length" @confirm="delSelected">
              <a-button size="small" danger :disabled="!targetSel.length">
                删除选中{{ targetSel.length ? ` (${targetSel.length})` : '' }}
              </a-button>
            </a-popconfirm>
            <a-radio-group v-model:value="targetFilter" size="small" option-type="button">
              <a-radio-button value="all">全部</a-radio-button>
              <a-radio-button value="alive">存活</a-radio-button>
              <a-radio-button value="dead">失活</a-radio-button>
              <a-radio-button value="unscanned">未扫描</a-radio-button>
            </a-radio-group>
          </a-space>
          <a-table
            :data-source="filteredTargets"
            :columns="targetCols"
            :row-selection="targetRowSel"
            row-key="id"
            size="middle"
            :pagination="{ pageSize: 20, showSizeChanger: true, showQuickJumper: true,
                           showTotal: (t) => `共 ${t} 条` }"
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
                <FpTags :raw="record.fps" />
              </template>
              <template v-else-if="column.key === 'shot'">
                <a-image v-if="record.latest?.screenshot" class="shot-thumb"
                         :src="`/screenshots/${record.latest.screenshot}`" />
                <span v-else>-</span>
              </template>
              <template v-else-if="column.key === 'op'">
                <a-space :size="6">
                  <a-button v-if="record.latest" size="small"
                            @click="router.push(`/results/${record.latest.id}`)">详情</a-button>
                  <a-button size="small" @click="openEditTarget(record)">编辑</a-button>
                  <a-popconfirm title="删除该目标？" @confirm="delTarget(record.id)">
                    <a-button size="small" danger>删除</a-button>
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
            :pagination="{ pageSize: 10, showTotal: (t) => `共 ${t} 条` }"
            :custom-row="scanRowClick"
            :row-class-name="scanRowClass"
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
              <template v-else-if="column.key === 'op'">
                <a-button size="small" :disabled="record.status !== 'done'"
                          @click="viewScan(record)">查看</a-button>
              </template>
            </template>
          </a-table>
          <a-empty v-if="!project?.scans?.length" description="还没有扫描记录" />

          <template v-if="selectedScan">
            <div class="result-head">
              <span class="result-title">
                扫描结果 · 轮次 #{{ selectedScan.id }}
                <a-tag :color="selectedScan.kind === 'rescan' ? 'purple' : 'blue'"
                       style="margin-left: 8px">
                  {{ selectedScan.kind === 'rescan' ? '二次扫描' : '全量扫描' }}
                </a-tag>
                <a-tag color="default">存活 {{ selectedScan.alive }}/{{ selectedScan.total }}</a-tag>
              </span>
              <a-checkbox v-model:checked="onlyAlive" style="margin: 0 10px">只看存活</a-checkbox>
              <a-input-search v-model:value="scanKw" placeholder="过滤 URL / 标题 / 指纹"
                              style="width: 240px" size="small" allow-clear />
            </div>
            <a-table
              :data-source="filteredScanResults"
              :columns="resultCols"
              row-key="id"
              size="small"
              :pagination="{ pageSize: 10, showSizeChanger: true, showQuickJumper: true,
                            showTotal: (t) => `共 ${t} 条` }"
              :loading="scanResults[selectedScan.id] === undefined"
            >
              <template #bodyCell="{ column, record: r }">
                <template v-if="column.key === 'alive'">
                  <a-badge :status="r.alive ? 'success' : 'error'"
                           :text="r.alive ? '存活' : '失活'" />
                  <a-tag v-if="r.protection" color="volcano" style="margin-left: 4px">防护</a-tag>
                </template>
                <template v-else-if="column.key === 'fps'">
                  <FpTags :raw="r.fingerprints" />
                </template>
                <template v-else-if="column.key === 'shot'">
                  <router-link v-if="r.screenshot" :to="`/results/${r.id}`">
                    <img class="shot-thumb" :src="`/screenshots/${r.screenshot}`" />
                  </router-link>
                  <span v-else>-</span>
                </template>
                <template v-else-if="column.key === 'detail'">
                  <a-button size="small" @click="router.push(`/results/${r.id}`)">详情</a-button>
                </template>
                <template v-else-if="column.key === 'final_url'">
                  <a :href="r.final_url" target="_blank" rel="noopener" class="mono"
                     style="word-break: break-all">{{ r.final_url }}</a>
                </template>
              </template>
            </a-table>
          </template>
        </a-tab-pane>

        <a-tab-pane key="exposure" :tab="`暴露面 (${expRuns.length})`">
          <a-table
            :data-source="expRuns"
            :columns="expCols"
            row-key="id"
            size="middle"
            :pagination="{ pageSize: 10, showTotal: (t) => `共 ${t} 条` }"
            v-model:expandedRowKeys="expExpanded"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'kinds'">
                <a-tag v-for="k in parseKinds(record)" :key="k" :color="expKindColor(k)">
                  {{ expKindLabel(k) }}
                </a-tag>
              </template>
              <template v-else-if="column.key === 'status'">
                <a-badge :status="{ running: 'processing', done: 'success' }[record.status] || 'error'"
                         :text="record.status === 'running' ? `${record.done}/${record.total}` : record.status" />
              </template>
              <template v-else-if="column.key === 'found'">
                <span :style="{ color: record.found ? 'var(--red)' : 'inherit' }">{{ record.found }}</span>
              </template>
              <template v-else-if="column.key === 'deep'">
                <a-badge v-if="record.deep_status === 'running'" status="processing"
                         :text="`深扫中 ${record.deep_done}/${record.deep_total}`" />
                <a-tag v-else-if="record.deep_status === 'done'" color="green">已深扫</a-tag>
                <a-tag v-else-if="record.deep_status === 'failed'" color="red">深扫失败</a-tag>
                <span v-else style="color: #bfbfbf">-</span>
              </template>
              <template v-else-if="column.key === 'op'">
                <a-space :size="6">
                  <a-button size="small" :disabled="record.status !== 'done'"
                            @click="expExpanded = expExpanded.includes(record.id) ? [] : [record.id]">查看</a-button>
                  <a-button v-if="record.status === 'done' && record.deep_status !== 'running'"
                            size="small" @click="deepScan(record.id)">
                    {{ record.deep_status === 'done' ? '重新深扫' : '深扫' }}
                  </a-button>
                  <a-popconfirm title="删除该次测绘及结果？" @confirm="delExposure(record.id)">
                    <a-button size="small" danger>删除</a-button>
                  </a-popconfirm>
                </a-space>
              </template>
            </template>
            <template #expandedRowRender="{ record }">
              <ExposureResults :run-id="record.id" />
            </template>
            <template #expandColumnTitle><span /></template>
            <template #emptyText>
              <a-empty description="还没有测绘记录，点击右上角「暴露面扫描」" />
            </template>
          </a-table>
        </a-tab-pane>
      </a-tabs>
    </a-card>

    <!-- 暴露面扫描 -->
    <ExposureScanModal v-model:open="showExposure" :project="project"
                       @started="onExpStarted" />

    <!-- 导入目标 -->
    <a-modal v-model:open="showImport" title="导入目标" ok-text="导入" cancel-text="取消"
             width="640px" @ok="doImport">
      <a-tabs>
        <a-tab-pane key="text" tab="粘贴 URL">
          <a-textarea v-model:value="importText" :rows="8"
                      placeholder="每行一个，支持 http(s)://host/path、域名、IP:端口" />
        </a-tab-pane>
        <a-tab-pane key="file" tab="上传 xlsx / xls / txt">
          <a-upload-dragger :before-upload="pickFile" :max-count="10" multiple
                            :file-list="importFiles" accept=".xlsx,.xls,.xlsm,.txt,.csv"
                            @remove="onRemoveFile">
            <p style="padding: 24px 0">点击或拖拽文件（可多选），xlsx/xls 自动提取所有 URL</p>
          </a-upload-dragger>
          <div v-if="importFiles.length" class="mono" style="margin-top: 8px">
            <div v-for="f in importFiles" :key="f.uid">{{ f.name }}</div>
          </div>
        </a-tab-pane>
      </a-tabs>
    </a-modal>

    <!-- 编辑项目 -->
    <a-modal v-model:open="showEditProject" title="编辑项目" ok-text="保存" cancel-text="取消"
             width="480px" @ok="saveProject">
      <a-form layout="vertical">
        <a-form-item label="项目名称" required>
          <a-input v-model:value="editProjectForm.name" />
        </a-form-item>
        <a-form-item label="描述">
          <a-textarea v-model:value="editProjectForm.description" :rows="3" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 编辑目标 URL -->
    <a-modal v-model:open="showEditTarget" title="编辑目标 URL" ok-text="保存" cancel-text="取消"
             width="480px" @ok="saveTarget">
      <a-form layout="vertical">
        <a-form-item label="URL" required>
          <a-input v-model:value="editTargetUrl" class="mono" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 发起扫描 -->
    <a-modal v-model:open="showScan" title="发起扫描" ok-text="开始" cancel-text="取消"
             width="480px" @ok="startScan()">
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
import { useRoute, useRouter } from 'vue-router'
import { Modal, message } from 'ant-design-vue'
import { EllipsisOutlined, ImportOutlined, PlayCircleOutlined, RadarChartOutlined, ReloadOutlined } from '@ant-design/icons-vue'
import api from '../api'
import ExposureResults from '../components/ExposureResults.vue'
import ExposureScanModal from '../components/ExposureScanModal.vue'
import FpTags from '../components/FpTags.vue'

const props = defineProps({ id: String })
const pid = Number(props.id)
const router = useRouter()
const route = useRoute()

const project = ref(null)
const running = ref(null)
const scanResults = reactive({})
const tab = ref('targets')
const showImport = ref(false)
const showScan = ref(false)
const importText = ref('')
const importFiles = ref([])
const scanOpts = reactive({ scope: 'all', active_probe: true, screenshot: true, concurrency: 50 })
const settingsLoaded = ref(false)
const showExposure = ref(false)
const expRuns = ref([])
const expExpanded = ref([])
const expRunning = computed(() => expRuns.value.some((r) => r.status === 'running'))
let timer = null
let expTimer = null

const aliveCount = computed(() => {
  if (!project.value?.latest) return 0
  return Object.values(project.value.latest).filter((r) => r.alive).length
})

const deadCount = computed(() => {
  if (!project.value?.latest) return 0
  return Object.values(project.value.latest).filter((r) => !r.alive).length
})

const unscannedCount = computed(
  () => (project.value?.targets?.length || 0) - aliveCount.value - deadCount.value
)

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

const targetSel = ref([])
const targetFilter = ref('all')

const filteredTargets = computed(() => {
  const rows = targetRows.value
  if (targetFilter.value === 'alive') return rows.filter((r) => r.latest?.alive)
  if (targetFilter.value === 'dead') return rows.filter((r) => r.latest && !r.latest.alive)
  if (targetFilter.value === 'unscanned') return rows.filter((r) => !r.latest)
  return rows
})

const targetRowSel = computed(() => ({
  selectedRowKeys: targetSel.value,
  onChange: (keys) => { targetSel.value = keys },
}))

async function delSelected() {
  if (!targetSel.value.length) return
  const res = (await api.batchDeleteTargets(targetSel.value)).data
  message.success(`已删除 ${res.deleted} 个目标`)
  targetSel.value = []
  load()
}

const targetCols = [
  { title: '#', key: 'idx', width: 55, customRender: ({ index }) => index + 1 },
  { title: 'URL', dataIndex: 'url', ellipsis: true },
  { title: '状态', key: 'status', width: 90 },
  { title: 'HTTP', key: 'code', width: 80 },
  { title: '标题', dataIndex: ['latest', 'title'], ellipsis: true, customRender: ({ record }) => record.latest?.title || '-' },
  { title: '指纹', key: 'fps' },
  { title: '截图', key: 'shot', width: 140 },
  { title: '操作', key: 'op', width: 150 },
]

const scanCols = [
  { title: '#', dataIndex: 'id', width: 70 },
  { title: '类型', key: 'kind', width: 110 },
  { title: '状态', key: 'status', width: 130 },
  { title: '存活/总数', customRender: ({ record: r }) => `${r.alive}/${r.total}`, width: 110 },
  { title: '开始时间', dataIndex: 'started_at', width: 200 },
  { title: '结束时间', dataIndex: 'finished_at', width: 200, customRender: ({ text }) => text || '-' },
  { title: '操作', key: 'op', width: 90 },
]

const expCols = [
  { title: '#', dataIndex: 'id', width: 60 },
  { title: '方式', key: 'kinds', width: 150 },
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

const EXP_KIND_LABEL = {
  js: 'JS接口', dir: '目录爆破', sub: '子域名', brute: '子域爆破',
  host: 'Host碰撞', net: '网络空间',
}
const expKindLabel = (k) => EXP_KIND_LABEL[k] || k
const expKindColor = (k) =>
  ({ js: 'cyan', dir: 'blue', sub: 'purple', brute: 'purple',
     host: 'volcano', net: 'green' })[k] || 'default'

async function loadExposure() {
  expRuns.value = (await api.listExposure(pid)).data
  // auto-expand the newest run so results are visible without clicking
  if (!expExpanded.value.length && expRuns.value.length) {
    expExpanded.value = [expRuns.value[0].id]
  }
  const busy = expRuns.value.some(r => r.status === 'running' || r.deep_status === 'running')
  if (busy && !expTimer) {
    expTimer = setInterval(loadExposure, 4000)
  } else if (!busy && expTimer) {
    clearInterval(expTimer)
    expTimer = null
  }
}

function onExpStarted() {
  tab.value = 'exposure'
  loadExposure()
}

async function deepScan(id) {
  try {
    await api.deepScanExposure(id, 120)
    message.success('攻击面深扫已开始（指纹+截图）')
    loadExposure()
  } catch (e) {
    message.error(e.response?.data?.detail || '启动失败')
  }
}

async function delExposure(id) {
  await api.deleteExposure(id)
  loadExposure()
}

const resultCols = [
  { title: '状态', key: 'alive', width: 100 },
  { title: 'URL', key: 'final_url', ellipsis: true },
  { title: 'HTTP', dataIndex: 'status_code', width: 70 },
  { title: '标题', dataIndex: 'title', ellipsis: true },
  { title: '指纹', key: 'fps' },
  { title: '截图', key: 'shot', width: 130 },
  { title: '操作', key: 'detail', width: 70 },
]

// 轮次点选 -> 下方直接展示该轮扫描结果
const selectedScan = ref(null)
const scanKw = ref('')
const onlyAlive = ref(false)

function viewScan(record) {
  if (record.status !== 'done') return
  selectedScan.value = record
  scanKw.value = ''
  if (!scanResults[record.id]) loadScanResults(record.id)
}

const scanRowClick = (record) => ({ onClick: () => viewScan(record) })
const scanRowClass = (record) =>
  (selectedScan.value?.id === record.id ? 'row-selected ' : '') +
  (record.status === 'done' ? 'row-clickable' : 'row-disabled')

const filteredScanResults = computed(() => {
  const rows = scanResults[selectedScan.value?.id] || []
  const kw = scanKw.value.trim().toLowerCase()
  return rows.filter((r) => {
    if (onlyAlive.value && !r.alive) return false
    if (!kw) return true
    return [r.final_url, r.url, r.title, r.fingerprints, r.protection]
      .filter(Boolean).join(' ').toLowerCase().includes(kw)
  })
})

async function load() {
  const { data } = await api.getProject(pid)
  if (!settingsLoaded.value) {
    settingsLoaded.value = true
    api.getSettings().then(({ data: s }) => {
      scanOpts.active_probe = s.active_probe
      scanOpts.screenshot = s.screenshot
      scanOpts.concurrency = s.concurrency
    })
  }
  loadExposure()
  project.value = data
  running.value = data.running
  const ids = new Set((data.targets || []).map((t) => t.id))
  targetSel.value = targetSel.value.filter((id) => ids.has(id))
  // ?tab=scans&scan=N 直达指定轮次；否则默认选中最新一轮已完成的扫描
  if (route.query.tab === 'scans') tab.value = 'scans'
  const wantScan = Number(route.query.scan) || null
  if (!selectedScan.value) {
    const pick = (wantScan && data.scans.find((s) => s.id === wantScan))
      || data.scans.find((s) => s.status === 'done')
    if (pick) {
      selectedScan.value = pick
      if (pick.status === 'done') loadScanResults(pick.id)
    }
  } else {
    const cur = data.scans.find((s) => s.id === selectedScan.value.id)
    if (cur) selectedScan.value = cur
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
      const last = project.value?.scans?.find((s) => s.status === 'done')
      if (last) {
        selectedScan.value = last
        await loadScanResults(last.id)
      }
      message.success('扫描完成')
    }
  }, 2500)
}

function pickFile(_file, fileList) {
  importFiles.value = fileList
  return false
}

function onRemoveFile(file) {
  importFiles.value = importFiles.value.filter((f) => f.uid !== file.uid)
}

async function doImport() {
  try {
    if (importFiles.value.length) {
      let parsed = 0, added = 0, duplicates = 0
      const failed = []
      for (const f of importFiles.value) {
        try {
          const r = (await api.uploadTargets(pid, f)).data
          parsed += r.parsed; added += r.added; duplicates += r.duplicates
        } catch (e) {
          failed.push(`${f.name}: ${e.response?.data?.detail || '解析失败'}`)
        }
      }
      message.success(`解析 ${parsed} 个，新增 ${added}，重复 ${duplicates}`)
      if (failed.length) message.warning(`部分文件失败——${failed.join('；')}`, 8)
    } else {
      const res = (await api.addTargets(pid, importText.value)).data
      message.success(`解析 ${res.parsed} 个，新增 ${res.added}，重复 ${res.duplicates}`)
    }
    showImport.value = false
    importText.value = ''
    importFiles.value = []
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
  targetSel.value = targetSel.value.filter((id) => id !== tid)
  load()
}

// ---------- edit project / target ----------

const showEditProject = ref(false)
const editProjectForm = reactive({ name: '', description: '' })
const showEditTarget = ref(false)
const editTargetId = ref(null)
const editTargetUrl = ref('')

function openEditProject() {
  editProjectForm.name = project.value?.name || ''
  editProjectForm.description = project.value?.description || ''
  showEditProject.value = true
}

async function saveProject() {
  if (!editProjectForm.name.trim()) return message.warning('名称不能为空')
  try {
    await api.updateProject(pid, editProjectForm)
    message.success('已保存')
    showEditProject.value = false
    load()
  } catch (e) {
    message.error(e.response?.data?.detail || '保存失败')
  }
}

function delProject() {
  Modal.confirm({
    title: '删除项目？',
    content: '将同时删除该项目下全部目标、扫描轮次和历史结果，不可恢复。',
    okText: '删除',
    okType: 'danger',
    cancelText: '取消',
    async onOk() {
      await api.deleteProject(pid)
      message.success('项目已删除')
      router.push('/projects')
    },
  })
}

function openEditTarget(record) {
  editTargetId.value = record.id
  editTargetUrl.value = record.url
  showEditTarget.value = true
}

async function saveTarget() {
  if (!editTargetUrl.value.trim()) return message.warning('URL 不能为空')
  try {
    await api.updateTarget(editTargetId.value, editTargetUrl.value.trim())
    message.success('已保存')
    showEditTarget.value = false
    load()
  } catch (e) {
    message.error(e.response?.data?.detail || '保存失败')
  }
}

onMounted(load)
onBeforeUnmount(() => {
  timer && clearInterval(timer)
  expTimer && clearInterval(expTimer)
})
</script>
