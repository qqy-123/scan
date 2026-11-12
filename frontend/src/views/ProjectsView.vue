<template>
  <div class="page">
    <div class="page-header">
      <div style="display: flex; align-items: flex-start; gap: 12px">
        <a-button size="small" style="margin-top: 4px" @click="goBack">
          <template #icon><ArrowLeftOutlined /></template>返回
        </a-button>
        <div>
          <div class="page-title">项目</div>
          <div class="page-sub">资产管理 · 共 {{ projects.length }} 个项目</div>
        </div>
      </div>
      <a-button type="primary" @click="openCreate">新建项目</a-button>
    </div>

    <a-table
      :data-source="projects"
      :columns="columns"
      :loading="loading"
      row-key="id"
      :pagination="{ defaultPageSize: 20, showSizeChanger: true, showQuickJumper: true,
                     showTotal: (t) => `共 ${t} 条` }"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'name'">
          <span style="font-weight: 500">{{ record.name }}</span>
        </template>
        <template v-else-if="column.key === 'alive'">
          <a-badge status="success" :text="String(record.alive_count)" />
          <span style="margin: 0 6px; color: #d9d9d9">/</span>
          <a-badge status="error" :text="String(record.dead_count)" />
        </template>
        <template v-else-if="column.key === 'created_at'">
          <span class="mono">{{ record.created_at }}</span>
        </template>
        <template v-else-if="column.key === 'op'">
          <a-space :size="6">
            <a-button size="small" @click="router.push(`/projects/${record.id}`)">查看</a-button>
            <a-button size="small" @click="openEdit(record)">编辑</a-button>
            <a-popconfirm
              title="删除项目及其全部目标和扫描记录？"
              ok-text="删除"
              cancel-text="取消"
              @confirm="delProject(record.id)"
            >
              <a-button size="small" danger>删除</a-button>
            </a-popconfirm>
          </a-space>
        </template>
      </template>
      <template #emptyText>
        <a-empty description="还没有项目，点击右上角新建" />
      </template>
    </a-table>

    <a-modal
      v-model:open="showForm"
      width="480px"
      :title="editing ? '编辑项目' : '新建项目'"
      :ok-text="editing ? '保存' : '创建'"
      cancel-text="取消"
      @ok="submit"
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
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { ArrowLeftOutlined } from '@ant-design/icons-vue'
import api from '../api'
import { useBack } from '../back'

const router = useRouter()
const goBack = useBack('/')

const projects = ref([])
const loading = ref(false)
const showForm = ref(false)
const editing = ref(null)
const form = reactive({ name: '', description: '' })

const columns = [
  { title: '项目名称', key: 'name', dataIndex: 'name' },
  { title: '目标数', dataIndex: 'target_count', width: 100 },
  { title: '存活/失活', key: 'alive', width: 130 },
  { title: '扫描轮次', dataIndex: 'scan_count', width: 100 },
  { title: '创建时间', key: 'created_at', width: 190 },
  { title: '操作', key: 'op', width: 110 },
]

function openCreate() {
  editing.value = null
  form.name = ''
  form.description = ''
  showForm.value = true
}

function openEdit(record) {
  editing.value = record
  form.name = record.name
  form.description = record.description || ''
  showForm.value = true
}

async function submit() {
  if (!form.name.trim()) return message.warning('请输入项目名称')
  if (editing.value) {
    await api.updateProject(editing.value.id, form)
    message.success('已保存')
  } else {
    await api.createProject(form)
    message.success('项目已创建')
  }
  showForm.value = false
  load()
}

async function delProject(id) {
  await api.deleteProject(id)
  message.success('项目已删除')
  load()
}

async function load() {
  loading.value = true
  try {
    projects.value = (await api.listProjects()).data
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
