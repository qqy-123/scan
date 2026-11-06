<template>
  <div class="page">
    <div class="page-header">
      <div class="page-title">项目</div>
      <a-button type="primary" @click="showCreate = true">新建项目</a-button>
    </div>

    <a-table
      :data-source="projects"
      :columns="columns"
      :loading="loading"
      row-key="id"
      :pagination="{ pageSize: 20 }"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'name'">
          <router-link :to="`/projects/${record.id}`">{{ record.name }}</router-link>
        </template>
        <template v-else-if="column.key === 'created_at'">
          <span class="mono">{{ record.created_at }}</span>
        </template>
      </template>
      <template #emptyText>
        <a-empty description="还没有项目，点击右上角新建" />
      </template>
    </a-table>

    <a-modal
      v-model:open="showCreate"
      title="新建项目"
      ok-text="创建"
      cancel-text="取消"
      @ok="create"
    >
      <a-form layout="vertical">
        <a-form-item label="项目名称" required>
          <a-input v-model:value="form.name" placeholder="例如：2026Q4 资产梳理" />
        </a-form-item>
        <a-form-item label="描述">
          <a-textarea v-model:value="form.description" :rows="3" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import api from '../api'

const projects = ref([])
const loading = ref(false)
const showCreate = ref(false)
const form = reactive({ name: '', description: '' })

const columns = [
  { title: '项目名称', key: 'name', dataIndex: 'name' },
  { title: '目标数', dataIndex: 'target_count', width: 120 },
  { title: '扫描轮次', dataIndex: 'scan_count', width: 120 },
  { title: '创建时间', key: 'created_at', width: 200 },
]

async function load() {
  loading.value = true
  try {
    projects.value = (await api.listProjects()).data
  } finally {
    loading.value = false
  }
}

async function create() {
  if (!form.name.trim()) return message.warning('请填写项目名称')
  await api.createProject(form)
  showCreate.value = false
  form.name = ''
  form.description = ''
  message.success('已创建')
  load()
}

onMounted(load)
</script>
