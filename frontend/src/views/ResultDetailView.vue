<template>
  <div class="page" v-if="result">
    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 16px">
      <a-button size="small" @click="goBack">
        <template #icon><ArrowLeftOutlined /></template>返回
      </a-button>
      <a-breadcrumb style="margin: 0">
        <a-breadcrumb-item><router-link to="/projects">项目</router-link></a-breadcrumb-item>
        <a-breadcrumb-item v-if="result?.project_id">
          <router-link :to="`/projects/${result.project_id}/scans/${result.scan_id}`">扫描记录</router-link>
        </a-breadcrumb-item>
        <a-breadcrumb-item>结果详情</a-breadcrumb-item>
      </a-breadcrumb>
      <a-space v-if="idx >= 0" style="margin-left: auto" :size="6">
        <a-button size="small" :disabled="!prevId" @click="goto(prevId)">上一条</a-button>
        <span style="color: #8c8c8c; font-size: 12px">{{ idx + 1 }}/{{ siblings.length }}</span>
        <a-button size="small" :disabled="!nextId" @click="goto(nextId)">下一条</a-button>
      </a-space>
    </div>

    <a-alert v-if="result.protection" type="warning" show-icon style="margin-bottom: 16px"
             :message="`检测到前台保护：${result.protection}，识别结果可能来自防护页面`" />
    <a-card :bordered="false" style="margin-bottom: 16px">
      <a-descriptions :column="2" size="small">
        <a-descriptions-item label="原始 URL">
          <span class="mono">{{ result.url }}</span>
        </a-descriptions-item>
        <a-descriptions-item label="最终 URL">
          <a :href="result.final_url" target="_blank" class="mono">{{ result.final_url }}</a>
        </a-descriptions-item>
        <a-descriptions-item label="状态">
          <a-badge :status="result.alive ? 'success' : 'error'"
                   :text="result.alive ? '存活' : '失活'" />
          <a-tag v-if="result.status_code" style="margin-left: 8px">{{ result.status_code }}</a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="标题">{{ result.title || '-' }}</a-descriptions-item>
        <a-descriptions-item label="Server">{{ result.server || '-' }}</a-descriptions-item>
        <a-descriptions-item label="耗时">{{ result.elapsed_ms ?? '-' }} ms</a-descriptions-item>
        <a-descriptions-item v-if="result.error" label="错误">
          <span style="color: #cf1322" class="mono">{{ result.error }}</span>
        </a-descriptions-item>
      </a-descriptions>
    </a-card>

    <a-row :gutter="16">
      <a-col :span="result.screenshot ? 14 : 24">
        <a-card :bordered="false" title="指纹识别">
          <a-table :data-source="result.fingerprints" :columns="fpCols" row-key="name"
                   size="small" :pagination="false">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'confidence'">
                <a-tag :color="{ confirmed: 'green', high: 'orange', low: 'default' }[fpLevel(record)]">
                  {{ { confirmed: '确认', high: '高可信', low: '低可信' }[fpLevel(record)] }}
                </a-tag>
              </template>
              <template v-else-if="column.key === 'evidence'">
                <div v-for="(e, i) in record.evidence" :key="i" class="mono"
                     style="color: #737373">
                  {{ e.field }}{{ e.key ? `[${e.key}]` : '' }} ~ {{ e.pattern }}
                </div>
              </template>
            </template>
          </a-table>
          <a-empty v-if="!result.fingerprints.length" description="未识别到指纹" />
        </a-card>
      </a-col>
      <a-col v-if="result.screenshot" :span="10">
        <a-card :bordered="false" title="页面截图">
          <a-image class="shot-full" :src="`/screenshots/${result.screenshot}`" />
        </a-card>
      </a-col>
    </a-row>
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ArrowLeftOutlined } from '@ant-design/icons-vue'
import api from '../api'

const props = defineProps({ id: String })
const result = ref(null)
const router = useRouter()

// 同轮次内上一条/下一条（按结果 id 顺序，与列表默认排序一致）
const siblings = ref([])
const rid = computed(() => Number(props.id))
const idx = computed(() => siblings.value.indexOf(rid.value))
const prevId = computed(() => (idx.value > 0 ? siblings.value[idx.value - 1] : null))
const nextId = computed(() =>
  idx.value >= 0 && idx.value < siblings.value.length - 1
    ? siblings.value[idx.value + 1] : null)

// replace 而不是 push：浏览 N 条后按返回仍直接回列表
function goto(id) { if (id) router.replace(`/results/${id}`) }

function goBack() {
  // SPA 内有上一步则原路返回（保留列表页筛选/滚动位置）；
  // 直接打开的深链则回退到该结果所属轮次的扫描结果页
  if (window.history.state?.back) return router.back()
  if (result.value?.project_id && result.value?.scan_id) {
    return router.push(
      `/projects/${result.value.project_id}/scans/${result.value.scan_id}`
    )
  }
  if (result.value?.project_id) {
    return router.push(`/projects/${result.value.project_id}?tab=scans`)
  }
  router.push('/projects')
}

const fpCols = [
  { title: '指纹', dataIndex: 'name', width: 160 },
  { title: '分类', dataIndex: 'category', width: 140 },
  { title: '置信度', key: 'confidence', width: 90 },
  { title: '版本', dataIndex: 'version', width: 100, customRender: ({ text }) => text || '-' },
  { title: '命中证据', key: 'evidence' },
]

// same tiers as backend hit_level(), with fallback for pre-level rows
function fpLevel(f) {
  if (f.level) return f.level
  if (f.confidence === 'implied') return 'low'
  const fields = new Set((f.evidence || []).map((e) => e.field))
  if (['probe', 'favicon', 'dom'].some((x) => fields.has(x))) return 'confirmed'
  return (f.score || 0) >= 100 ? 'high' : 'low'
}

async function load() {
  result.value = (await api.getResult(rid.value)).data
  if (result.value?.scan_id && !siblings.value.length) {
    const scan = (await api.getScan(result.value.scan_id)).data
    siblings.value = (scan.results || []).map((r) => r.id).sort((a, b) => a - b)
  }
}
onMounted(load)
watch(rid, load)  // 上一条/下一条复用组件，仅参数变化时重载
</script>
