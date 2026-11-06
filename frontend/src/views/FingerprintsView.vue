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
        抓取站点并提取源码特征（favicon hash / 特征路径 / Meta / Cookie / 关键字），勾选后保存为指纹
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

          <a-divider orientation="left" orientation-margin="0">选择入库特征</a-divider>

          <a-form layout="vertical">
            <a-form-item v-if="preview.paths.length" label="特征路径（来自 src/href，最能代表源码）">
              <a-checkbox-group v-model:value="sel.paths" :options="preview.paths" style="display: grid; grid-template-columns: repeat(3, 1fr)" />
            </a-form-item>
            <a-form-item v-if="preview.keywords.length" label="页面关键字（注释 / Powered-by 等）">
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
            <a-form-item label="自定义探测路径（可选，逗号分隔，如 /admin/login）">
              <a-input v-model:value="probePaths" placeholder="/path1, /path2" style="width: 480px" />
            </a-form-item>
            <a-space>
              <a-input v-model:value="fpName" placeholder="指纹名称（必填）" style="width: 240px" />
              <a-input v-model:value="fpCategory" placeholder="分类" style="width: 160px" />
              <a-button type="primary" :disabled="!canSave" @click="save">保存指纹</a-button>
            </a-space>
          </a-form>
        </template>
      </template>
    </a-card>

    <!-- 指纹库 -->
    <a-card :bordered="false" :title="`指纹库（${rules.filter(r => !r.disabled).length} 生效 / ${rules.length} 总计）`">
      <a-table :data-source="rules" :columns="ruleCols" row-key="name" size="small"
               :pagination="{ pageSize: 20 }">
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
            <a-space>
              <a v-if="!record.disabled" @click="openEdit(record)">编辑</a>
              <a v-if="record.disabled" @click="toggleRule(record, false)">启用</a>
              <a v-else @click="toggleRule(record, true)">禁用</a>
              <a-popconfirm v-if="record.file === 'custom.json' && !record.disabled"
                            title="删除自定义规则？" ok-text="删除" @confirm="delRule(record.name)">
                <a style="color: #cf1322">删除</a>
              </a-popconfirm>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- 编辑规则 -->
    <a-modal v-model:open="showEdit" :title="`编辑指纹：${editName}`" width="720px"
             ok-text="保存" cancel-text="取消" @ok="saveEdit">
      <div style="color: #a6a6a6; font-size: 12px; margin-bottom: 8px">
        修改后保存到 custom.json 同名覆盖内置规则；删除自定义覆盖即恢复内置。格式同 Wappalyzer 规则。
      </div>
      <a-textarea v-model:value="editJson" :rows="18" class="mono"
                  spellcheck="false" />
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
const fpName = ref('')
const fpCategory = ref('自定义')
const probePaths = ref('')
const sel = reactive({ paths: [], keywords: [], meta: [], cookies: [], favicon: true })

const metaKeys = computed(() =>
  preview.value ? Object.entries(preview.value.meta).map(([k, v]) => `${k}=${v}`) : []
)

const canSave = computed(
  () =>
    fpName.value.trim() &&
    (sel.paths.length || sel.keywords.length || sel.meta.length ||
      sel.cookies.length || sel.favicon || probePaths.value.trim())
)

const ruleCols = [
  { title: '名称', dataIndex: 'name', width: 180 },
  { title: '分类', dataIndex: 'category', width: 140 },
  { title: '信号', key: 'signals' },
  { title: '来源', key: 'file', width: 110 },
  { title: '操作', key: 'op', width: 150 },
]

const showEdit = ref(false)
const editName = ref('')
const editJson = ref('')
const editError = ref('')

async function openEdit(record) {
  editError.value = ''
  const { data } = await api.ruleRaw(record.name)
  editName.value = record.name
  editJson.value = data.rule
    ? JSON.stringify(data.rule, null, 2)
    : `{\n  "name": "${record.name}",\n  "category": "自定义",\n  "html": []\n}`
  showEdit.value = true
}

async function saveEdit() {
  editError.value = ''
  let rule
  try {
    rule = JSON.parse(editJson.value)
  } catch (e) {
    editError.value = `JSON 格式错误：${e.message}`
    return
  }
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
      sel.paths = data.paths.slice(0, 3)
      sel.keywords = []
      sel.meta = metaKeys.value
      sel.cookies = data.cookies
      sel.favicon = !!data.favicon
      fpName.value = ''
    }
  } catch (e) {
    message.error(e.response?.data?.detail || '提取失败')
  } finally {
    extracting.value = false
  }
}

async function save() {
  const selected = {
    html: [...sel.paths, ...sel.keywords],
    scriptSrc: sel.paths.filter((p) => p.includes('/')),
    meta: Object.fromEntries(
      sel.meta.map((m) => {
        const i = m.indexOf('=')
        return i === -1 ? [m, '.*'] : [m.slice(0, i), m.slice(i + 1)]
      })
    ),
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
