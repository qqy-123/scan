<template>
  <div class="page">
    <div class="page-header">
      <div class="page-title">工作台</div>
      <a-space>
        <a-button @click="$router.push('/fingerprints')">指纹学习</a-button>
        <a-button type="primary" @click="$router.push('/')">新建项目</a-button>
      </a-space>
    </div>

    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="4" v-for="s in stats" :key="s.label">
        <a-card :bordered="false">
          <a-statistic :title="s.label" :value="s.value" />
        </a-card>
      </a-col>
    </a-row>

    <a-row :gutter="16">
      <a-col :span="14">
        <a-card :bordered="false" title="最近扫描">
          <a-table :data-source="data?.recent_scans || []" :columns="scanCols" row-key="id"
                   size="small" :pagination="false">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'project'">
                <router-link :to="`/projects/${record.project_id}`">{{ record.project_name }}</router-link>
              </template>
              <template v-else-if="column.key === 'kind'">
                <a-tag :color="record.kind === 'rescan' ? 'purple' : 'blue'">
                  {{ record.kind === 'rescan' ? '二次扫描' : '全量' }}
                </a-tag>
              </template>
              <template v-else-if="column.key === 'status'">
                <a-badge :status="{ running: 'processing', done: 'success' }[record.status] || 'error'"
                         :text="record.status === 'running' ? `${record.done}/${record.total}` : record.status" />
              </template>
            </template>
          </a-table>
          <a-empty v-if="!data?.recent_scans?.length" description="暂无扫描" :image="simpleImg" />
        </a-card>
      </a-col>
      <a-col :span="10">
        <a-card :bordered="false" title="指纹命中 TOP">
          <div v-for="t in data?.top_fingerprints || []" :key="t.name" class="fp-row">
            <span class="fp-name">{{ t.name }}</span>
            <a-tag class="fp-cat">{{ t.category }}</a-tag>
            <span class="fp-count mono">{{ t.count }}</span>
          </div>
          <a-empty v-if="!data?.top_fingerprints?.length" description="暂无识别数据" :image="simpleImg" />
        </a-card>
      </a-col>
    </a-row>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { Empty } from 'ant-design-vue'
import api from '../api'

const simpleImg = Empty.PRESENTED_IMAGE_SIMPLE
const data = ref(null)

const stats = computed(() => [
  { label: '项目', value: data.value?.projects ?? 0 },
  { label: '资产目标', value: data.value?.targets ?? 0 },
  { label: '存活目标', value: data.value?.alive ?? 0 },
  { label: '扫描轮次', value: data.value?.scans ?? 0 },
  { label: '运行中', value: data.value?.running ?? 0 },
  { label: '指纹规则', value: data.value?.rules_count ?? 0 },
])

const scanCols = [
  { title: '项目', key: 'project' },
  { title: '类型', key: 'kind', width: 100 },
  { title: '状态', key: 'status', width: 130 },
  { title: '存活/总数', width: 110, customRender: ({ record: r }) => `${r.alive}/${r.total}` },
  { title: '开始时间', dataIndex: 'started_at', width: 190 },
]

onMounted(async () => {
  data.value = (await api.overview()).data
})
</script>

<style scoped>
.fp-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 0;
  border-bottom: 1px solid #f5f5f5;
}
.fp-name {
  flex: 1;
  font-weight: 500;
}
.fp-cat {
  font-size: 11px;
}
.fp-count {
  color: #2454e6;
  font-weight: 600;
}
</style>
