<template>
  <div class="page" v-if="result">
    <a-breadcrumb style="margin-bottom: 16px">
      <a-breadcrumb-item><router-link to="/projects">项目</router-link></a-breadcrumb-item>
      <a-breadcrumb-item>结果详情</a-breadcrumb-item>
    </a-breadcrumb>

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
import { onMounted, ref } from 'vue'
import api from '../api'

const props = defineProps({ id: String })
const result = ref(null)

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

onMounted(async () => {
  result.value = (await api.getResult(Number(props.id))).data
})
</script>
