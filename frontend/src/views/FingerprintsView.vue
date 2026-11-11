<template>
  <div class="page">
    <div class="page-header">
      <div>
        <div class="page-title">指纹库</div>
        <div class="page-sub">源码/系统指纹规则 · 学习 · 编辑 · 启停</div>
      </div>
    </div>

    <!-- 指纹学习 -->
    <a-card :bordered="false" title="指纹学习" style="margin-bottom: 16px">
      <a-space.Compact style="width: 560px; max-width: 100%">
        <a-input v-model:value="learnUrl" placeholder="输入已知系统的 URL，例如 https://xxx.com" />
        <a-button type="primary" :loading="extracting" @click="extract">提取特征</a-button>
      </a-space.Compact>
      <div style="color: #a6a6a6; margin-top: 8px; font-size: 12px">
        浏览器访问站点，抓全部触发数据包并提取源码特征，勾选后保存为指纹
      </div>

      <template v-if="preview">
        <a-alert v-if="!preview.ok" type="error" :message="preview.error" style="margin-top: 16px" show-icon />
        <template v-else>
          <a-descriptions :column="2" size="small" style="margin-top: 16px">
            <a-descriptions-item label="最终 URL"><span class="mono">{{ preview.final_url }}</span></a-descriptions-item>
            <a-descriptions-item label="标题">{{ preview.title }}</a-descriptions-item>
            <a-descriptions-item label="favicon mmh3">
              <span class="mono">{{ preview.favicon ?? '未获取' }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="已识别">
              <a-tag v-for="d in preview.detected" :key="d.name" :color="d.confidence === 'confirmed' ? 'green' : 'orange'">
                {{ d.name }}
              </a-tag>
              <span v-if="!preview.detected.length" style="color: #a6a6a6">无（新指纹）</span>
            </a-descriptions-item>
          </a-descriptions>

          <a-tabs v-model:activeKey="learnTab" style="margin-top: 8px">
            <!-- 特征选择 -->
            <a-tab-pane key="features" tab="特征选择">
              <a-form layout="vertical">
                <a-form-item v-if="preview.url_suggest.length" label="数据包路径特征（url 字段 · 匹配访问触发的所有请求 URL）">
                  <a-checkbox-group v-model:value="sel.urls" :options="preview.url_suggest" style="display: grid; grid-template-columns: repeat(3, 1fr)" />
                </a-form-item>
                <a-form-item v-if="preview.xhr_suggest.length" label="接口特征（xhr 字段 · 匹配 XHR/fetch 请求）">
                  <a-checkbox-group v-model:value="sel.xhr" :options="preview.xhr_suggest" style="display: grid; grid-template-columns: repeat(3, 1fr)" />
                </a-form-item>
                <a-form-item v-if="preview.headers.length" label="响应头特征（headers 字段 · 来自数据包响应头）">
                  <a-checkbox-group v-model:value="sel.headers" :options="preview.headers" style="display: grid; grid-template-columns: repeat(2, 1fr)" />
                </a-form-item>
                <a-form-item v-if="preview.js.length" label="JS 全局变量（js 字段 · 渲染后探测）">
                  <a-checkbox-group v-model:value="sel.js" :options="preview.js" style="display: grid; grid-template-columns: repeat(2, 1fr)" />
                </a-form-item>
                <a-form-item v-if="preview.paths.length" label="页面路径特征（html/scriptSrc 字段 · 来自 HTML src/href）">
                  <a-checkbox-group v-model:value="sel.paths" :options="preview.paths" style="display: grid; grid-template-columns: repeat(3, 1fr)" />
                </a-form-item>
                <a-form-item v-if="preview.keywords.length" label="页面关键字（html 字段 · 注释 / Powered-by 等）">
                  <a-checkbox-group v-model:value="sel.keywords" :options="preview.keywords" style="display: grid; grid-template-columns: repeat(2, 1fr)" />
                </a-form-item>
                <a-form-item v-if="metaKeys.length" label="Meta">
                  <a-checkbox-group v-model:value="sel.meta" :options="metaKeys" />
                </a-form-item>
                <a-form-item v-if="preview.cookies.length" label="Cookie 名">
                  <a-checkbox-group v-model:value="sel.cookies" :options="preview.cookies" />
                </a-form-item>
                <a-form-item v-if="preview.favicon">
                  <a-checkbox v-model:checked="sel.favicon">使用 favicon hash ({{ preview.favicon }})</a-checkbox>
                </a-form-item>
                <a-form-item label="自定义探测路径（probe 字段 · 可选，逗号分隔，如 /admin/login）">
                  <a-input v-model:value="probePaths" placeholder="/path1, /path2" style="width: 480px" />
                </a-form-item>
                <a-space>
                  <a-input v-model:value="fpName" placeholder="指纹名称（必填）" style="width: 240px" />
                  <a-input v-model:value="fpCategory" placeholder="分类" style="width: 160px" />
                  <a-button type="primary" :disabled="!canSave" @click="save">保存指纹</a-button>
                </a-space>
              </a-form>
            </a-tab-pane>

            <!-- 数据包 -->
            <a-tab-pane key="packets" :tab="`数据包（${preview.packets.length}）`">
              <div style="color: #a6a6a6; font-size: 12px; margin-bottom: 8px">
                访问该站点时浏览器触发的全部请求包。勾选某行可将其路径加入 url 指纹特征。
              </div>
              <a-table :data-source="preview.packets" :columns="pktCols" size="small"
                       :pagination="{ defaultPageSize: 10 }" row-key="url"
                       :row-selection="{ selectedRowKeys: sel.pktKeys, onChange: onPktSelect }">
                <template #bodyCell="{ column, record }">
                  <template v-if="column.key === 'type'">
                    <a-tag :color="pktColor(record.type)">{{ record.type }}</a-tag>
                  </template>
                  <template v-else-if="column.key === 'url'">
                    <span class="mono" style="word-break: break-all">{{ record.url }}</span>
                  </template>
                  <template v-else-if="column.key === 'status'">
                    <a-badge :status="record.status < 400 ? 'success' : 'error'" :text="String(record.status)" />
                  </template>
                </template>
              </a-table>
            </a-tab-pane>
          </a-tabs>
        </template>
      </template>
    </a-card>

    <!-- 指纹库 -->
    <a-card :bordered="false" :title="`指纹库（${rules.filter(r => !r.disabled).length} 生效 / ${rules.length} 总计）`">
      <a-table :data-source="rules" :columns="ruleCols" row-key="name" size="small"
               :pagination="{ defaultPageSize: 20, showSizeChanger: true, showQuickJumper: true,
                             showTotal: (t) => `共 ${t} 条` }">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'signals'">
            <a-tag v-for="(v, k) in record.signals" :key="k" style="margin-bottom: 4px">
              {{ k }}<template v-if="typeof v === 'number'">×{{ v }}</template>
            </a-tag>
            <span v-if="record.disabled" style="color: #bfbfbf">-</span>
          </template>
          <template v-else-if="column.key === 'file'">
            <a-tag v-if="record.disabled" color="red">已禁用</a-tag>
            <a-tag v-else-if="record.file === 'custom.json'" color="purple">自定义</a-tag>
            <a-tag v-else>{{ record.file }}</a-tag>
          </template>
          <template v-else-if="column.key === 'op'">
            <a-space :size="6">
              <a-button size="small" @click="openEdit(record)">编辑</a-button>
              <a-button v-if="record.disabled" size="small"
                        @click="toggleRule(record, false)">启用</a-button>
              <a-button v-else size="small" @click="toggleRule(record, true)">禁用</a-button>
              <a-popconfirm v-if="record.file === 'custom.json' && !record.disabled"
                            title="删除自定义规则？" ok-text="删除" @confirm="delRule(record.name)">
                <a-button size="small" danger>删除</a-button>
              </a-popconfirm>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- 编辑规则：结构化 + JSON 双模式 -->
    <a-modal v-model:open="showEdit" :title="`编辑指纹：${edit.name || editName}`" width="800px"
             ok-text="保存" cancel-text="取消" @ok="saveEdit">
      <div style="color: #a6a6a6; font-size: 12px; margin-bottom: 8px">
        所有字段均可修改，保存到 custom.json 同名覆盖内置；删除自定义覆盖即恢复。
        模式支持 <code>\;confidence:N</code> 权重和 <code>\;version:\1</code> 版本提取。
        <a-tag v-if="editDisabled" color="red" style="margin-left: 8px">当前禁用</a-tag>
      </div>

      <a-tabs v-model:activeKey="editTab" @change="onEditTab">
        <a-tab-pane key="form" tab="结构化编辑">
          <a-form layout="vertical">
            <a-row :gutter="12">
              <a-col :span="8"><a-form-item label="名称"><a-input v-model:value="edit.name" /></a-form-item></a-col>
              <a-col :span="8"><a-form-item label="分类"><a-input v-model:value="edit.category" /></a-form-item></a-col>
              <a-col :span="8"><a-form-item label="官网"><a-input v-model:value="edit.website" placeholder="https://" /></a-form-item></a-col>
            </a-row>

            <!-- list fields -->
            <a-form-item v-for="f in LIST_FIELDS" :key="f.key" :label="f.label" style="margin-bottom: 10px">
              <a-select v-model:value="edit.lists[f.key]" mode="tags" :placeholder="f.ph"
                        :open="false" size="small" :token-separators="['\n']" />
            </a-form-item>

            <!-- map fields -->
            <a-form-item v-for="f in MAP_FIELDS" :key="f.key" :label="f.label" style="margin-bottom: 10px">
              <div v-for="(row, i) in edit.maps[f.key]" :key="i" class="maprow">
                <a-input v-model:value="row.k" :placeholder="f.kph" style="width: 220px" size="small" />
                <a-select v-model:value="row.p" mode="tags" :open="false" size="small"
                          placeholder="匹配模式（回车添加多条）" style="flex: 1" />
                <a-button size="small" danger type="text"
                          @click="edit.maps[f.key].splice(i, 1)">删</a-button>
              </div>
              <a-button size="small" @click="edit.maps[f.key].push({ k: '', p: [] })">+ 添加</a-button>
            </a-form-item>

            <a-form-item label="dom（选择器 → 条件 JSON，可选）">
              <a-textarea v-model:value="edit.domText" :rows="3" class="mono"
                          placeholder='{"#app": {"text": ["Powered by"]}}' />
            </a-form-item>
          </a-form>
        </a-tab-pane>

        <a-tab-pane key="json" tab="JSON 源码">
          <a-textarea v-model:value="editJson" :rows="20" class="mono" spellcheck="false" />
        </a-tab-pane>
      </a-tabs>
      <a-alert v-if="editError" type="error" :message="editError" style="margin-top: 8px" />
    </a-modal>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import api from '../api'

const rules = ref([])
const learnUrl = ref('')
const extracting = ref(false)
const preview = ref(null)
const learnTab = ref('features')
const fpName = ref('')
const fpCategory = ref('自定义')
const probePaths = ref('')
const sel = reactive({
  paths: [], keywords: [], meta: [], cookies: [], favicon: true,
  urls: [], xhr: [], headers: [], js: [], pktKeys: [],
})

const metaKeys = computed(() =>
  preview.value ? Object.entries(preview.value.meta).map(([k, v]) => `${k}=${v}`) : []
)

const pktCols = [
  { title: '类型', key: 'type', width: 90 },
  { title: 'URL', key: 'url' },
  { title: '状态', key: 'status', width: 90 },
]

const pktColor = (t) =>
  ({ document: 'blue', xhr: 'purple', fetch: 'purple', script: 'cyan',
     stylesheet: 'geekblue', image: 'default', font: 'default' })[t] || 'default'

const onPktSelect = (keys) => { sel.pktKeys = keys }

const canSave = computed(
  () =>
    fpName.value.trim() &&
    (sel.paths.length || sel.keywords.length || sel.meta.length ||
      sel.cookies.length || sel.favicon || probePaths.value.trim() ||
      sel.urls.length || sel.xhr.length || sel.headers.length ||
      sel.js.length || sel.pktKeys.length)
)

const ruleCols = [
  { title: '名称', dataIndex: 'name', width: 180 },
  { title: '分类', dataIndex: 'category', width: 140 },
  { title: '信号', key: 'signals' },
  { title: '来源', key: 'file', width: 110 },
  { title: '操作', key: 'op', width: 160 },
]

// ---------------- rule editor ----------------

const LIST_FIELDS = [
  { key: 'html', label: 'html（页面源码正则）', ph: '回车添加，如 wp-content/' },
  { key: 'scriptSrc', label: 'scriptSrc（脚本 URL 正则）', ph: '如 wp-includes/js/' },
  { key: 'scripts', label: 'scripts（内联脚本正则）', ph: '内联 <script> 内容匹配' },
  { key: 'url', label: 'url（任意数据包 URL 正则）', ph: '匹配所有请求包 URL' },
  { key: 'xhr', label: 'xhr（XHR/fetch URL 正则）', ph: '匹配接口请求 URL' },
  { key: 'favicon', label: 'favicon（mmh3 哈希）', ph: 'favicon mmh3 值' },
  { key: 'implies', label: 'implies（命中后推断）', ph: '如 PHP' },
  { key: 'excludes', label: 'excludes（互斥剔除）', ph: '如 Apache' },
]

const MAP_FIELDS = [
  { key: 'headers', label: 'headers', kph: '响应头名（正则）' },
  { key: 'cookies', label: 'cookies', kph: 'Cookie 名（正则）' },
  { key: 'meta', label: 'meta', kph: 'meta name' },
  { key: 'js', label: 'js（JS 全局变量）', kph: '如 jQuery.fn.jquery' },
  { key: 'probe', label: 'probe（主动探测路径）', kph: '如 /wp-login.php' },
]

const showEdit = ref(false)
const editTab = ref('form')
const editName = ref('')
const editDisabled = ref(false)
const editJson = ref('')
const editError = ref('')
const edit = reactive({
  name: '', category: '', website: '',
  lists: {}, maps: {}, domText: '',
})

function blankEdit() {
  edit.lists = Object.fromEntries(LIST_FIELDS.map((f) => [f.key, []]))
  edit.maps = Object.fromEntries(MAP_FIELDS.map((f) => [f.key, []]))
  edit.domText = ''
}

function rawToEdit(raw) {
  blankEdit()
  edit.name = raw.name || ''
  edit.category = raw.category || ''
  edit.website = raw.website || ''
  for (const f of LIST_FIELDS) {
    edit.lists[f.key] = (raw[f.key] || []).map(String)
  }
  for (const f of MAP_FIELDS) {
    edit.maps[f.key] = Object.entries(raw[f.key] || {}).map(([k, v]) => ({
      k,
      p: (Array.isArray(v) ? v : [v]).map(String),
    }))
  }
  edit.domText = raw.dom ? JSON.stringify(raw.dom, null, 2) : ''
}

function editToRule() {
  const rule = { name: edit.name.trim(), category: edit.category.trim() || '自定义' }
  if (edit.website.trim()) rule.website = edit.website.trim()
  for (const f of LIST_FIELDS) {
    const v = edit.lists[f.key].filter((x) => x && x.trim())
    if (v.length) rule[f.key] = v
  }
  for (const f of MAP_FIELDS) {
    const m = {}
    for (const row of edit.maps[f.key]) {
      if (row.k.trim()) m[row.k.trim()] = row.p.length ? row.p : ['.*']
    }
    if (Object.keys(m).length) rule[f.key] = m
  }
  if (edit.domText.trim()) rule.dom = JSON.parse(edit.domText)
  return rule
}

async function openEdit(record) {
  editError.value = ''
  editTab.value = 'form'
  const { data } = await api.ruleRaw(record.name)
  editName.value = record.name
  editDisabled.value = !!data.disabled
  const raw = data.rule || { name: record.name, category: '自定义', html: [] }
  rawToEdit(raw)
  editJson.value = JSON.stringify(raw, null, 2)
  showEdit.value = true
}

function onEditTab(key) {
  editError.value = ''
  if (key === 'json') {
    try {
      editJson.value = JSON.stringify(editToRule(), null, 2)
    } catch (e) {
      editError.value = `dom JSON 错误：${e.message}`
      editTab.value = 'form'
    }
  } else {
    try {
      rawToEdit(JSON.parse(editJson.value))
    } catch (e) {
      editError.value = `JSON 格式错误：${e.message}`
      editTab.value = 'json'
    }
  }
}

async function saveEdit() {
  editError.value = ''
  let rule
  try {
    rule = editTab.value === 'json' ? JSON.parse(editJson.value) : editToRule()
  } catch (e) {
    editError.value = `格式错误：${e.message}`
    return
  }
  if (!rule.name?.trim()) {
    editError.value = '名称不能为空'
    return
  }
  if (editDisabled.value) rule._disabled = true  // keep disabled state
  try {
    await api.updateRule(rule)
    message.success('已保存（同名覆盖生效）')
    showEdit.value = false
    loadRules()
  } catch (e) {
    editError.value = e.response?.data?.detail || '保存失败'
  }
}

async function toggleRule(record, disabled) {
  await api.setRuleDisabled(record.name, disabled)
  message.success(disabled ? '已禁用' : '已启用')
  loadRules()
}

async function extract() {
  if (!learnUrl.value.trim()) return message.warning('请输入 URL')
  extracting.value = true
  preview.value = null
  try {
    const { data } = await api.learnPreview(learnUrl.value.trim())
    preview.value = data
    if (data.ok) {
      learnTab.value = 'features'
      sel.paths = data.paths.slice(0, 3)
      sel.keywords = []
      sel.meta = metaKeys.value
      sel.cookies = data.cookies
      sel.favicon = !!data.favicon
      sel.urls = data.url_suggest.slice(0, 3)
      sel.xhr = data.xhr_suggest
      sel.headers = data.headers
      sel.js = data.js
      sel.pktKeys = []
      fpName.value = ''
    }
  } catch (e) {
    message.error(e.response?.data?.detail || '提取失败')
  } finally {
    extracting.value = false
  }
}

async function save() {
  const pktUrls = sel.pktKeys.map((u) => {
    try {
      return new URL(u).pathname || u
    } catch {
      return u
    }
  })
  const selected = {
    html: [...sel.paths, ...sel.keywords],
    scriptSrc: sel.paths.filter((p) => p.includes('/')),
    url: [...sel.urls, ...pktUrls],
    xhr: sel.xhr,
    headers: Object.fromEntries(sel.headers.map(_splitKV)),
    js: sel.js,
    meta: Object.fromEntries(sel.meta.map(_splitKV)),
    cookies: sel.cookies,
    favicon: sel.favicon ? preview.value.favicon : null,
    probe: probePaths.value.split(',').map((s) => s.trim()).filter(Boolean),
  }
  try {
    await api.saveCustomRule({ name: fpName.value, category: fpCategory.value, selected })
    message.success(`指纹「${fpName.value}」已入库`)
    preview.value = null
    learnUrl.value = ''
    loadRules()
  } catch (e) {
    message.error(e.response?.data?.detail || '保存失败')
  }
}

function _splitKV(m) {
  const i = m.indexOf('=')
  return i === -1 ? [m, '.*'] : [m.slice(0, i), m.slice(i + 1)]
}

async function delRule(name) {
  await api.deleteCustomRule(name)
  message.success('已删除')
  loadRules()
}

async function loadRules() {
  rules.value = (await api.rulesDetail()).data
}

onMounted(loadRules)
</script>

<style scoped>
.maprow {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}
code {
  background: #f5f5f5;
  padding: 1px 5px;
  border-radius: 4px;
  font-size: 11px;
}
</style>
