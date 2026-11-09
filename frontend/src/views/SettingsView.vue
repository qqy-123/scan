<template>
  <div class="page">
    <div class="page-header">
      <div>
        <div class="page-title">系统配置</div>
        <div class="page-sub">扫描默认值 · 探测参数 · 系统信息</div>
      </div>
      <a-space>
        <a-button @click="reset">恢复默认</a-button>
        <a-button type="primary" :loading="saving" @click="save">保存</a-button>
      </a-space>
    </div>

    <a-row :gutter="16">
      <a-col :span="14">
        <a-card :bordered="false" title="扫描默认值" style="margin-bottom: 16px">
          <a-form layout="vertical">
            <a-row :gutter="16">
              <a-col :span="12">
                <a-form-item label="目标并发（存活探测）">
                  <a-input-number v-model:value="form.concurrency" :min="1" :max="500" style="width: 100%" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item label="浏览器并发（抓包/截图，耗内存）">
                  <a-input-number v-model:value="form.browser_concurrency" :min="1" :max="16" style="width: 100%" />
                </a-form-item>
              </a-col>
            </a-row>
            <a-row :gutter="16">
              <a-col :span="12">
                <a-form-item label="连接超时（秒）">
                  <a-input-number v-model:value="form.connect_timeout" :min="1" :max="60" style="width: 100%" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item label="读取超时（秒）">
                  <a-input-number v-model:value="form.read_timeout" :min="1" :max="120" style="width: 100%" />
                </a-form-item>
              </a-col>
            </a-row>
            <a-form-item label="主动探测默认开启（请求特征路径二次确认）">
              <a-switch v-model:checked="form.active_probe" />
            </a-form-item>
            <a-form-item label="网页截图默认开启（同时采集渲染后信号）">
              <a-switch v-model:checked="form.screenshot" />
            </a-form-item>
            <a-divider style="margin: 8px 0 16px" />
            <a-form-item label="平台登录密码（修改后需要重新登录，至少 6 位；留空则不修改）">
              <a-input-password v-model:value="newPassword" placeholder="留空保持不变"
                                style="max-width: 320px" />
            </a-form-item>
          </a-form>
          <div style="color: #a6a6a6; font-size: 12px">
            这些值作为「发起扫描」弹窗的默认值和引擎的全局参数；单次扫描仍可在弹窗里覆盖。
          </div>
        </a-card>

        <a-card :bordered="false" title="网络空间测绘 API" style="margin-bottom: 16px">
          <a-form layout="vertical">
            <a-row :gutter="16">
              <a-col :span="12">
                <a-form-item label="FOFA 邮箱">
                  <a-input v-model:value="form.fofa_email" placeholder="fofa.info 账号邮箱" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item label="FOFA Key">
                  <a-input-password v-model:value="form.fofa_key" placeholder="fofa.info API key" />
                </a-form-item>
              </a-col>
            </a-row>
            <a-row :gutter="16">
              <a-col :span="12">
                <a-form-item label="Hunter（鹰图）Key">
                  <a-input-password v-model:value="form.hunter_key" placeholder="hunter.qianxin.com API key" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item label="Quake（360）Key">
                  <a-input-password v-model:value="form.quake_key" placeholder="quake.360.net API key" />
                </a-form-item>
              </a-col>
            </a-row>
          </a-form>
          <div style="color: #a6a6a6; font-size: 12px">
            用于暴露面扫描的「网络空间测绘」选项（FOFA / 鹰图 / Quake 资产搜索）。
            已配置的 key 以 **** 掩码显示，输入新值才会覆盖，留空保存不会改变已存 key。
          </div>
        </a-card>
      </a-col>

      <a-col :span="10">
        <a-card :bordered="false" title="系统信息" style="margin-bottom: 16px">
          <a-descriptions :column="1" size="small" v-if="info">
            <a-descriptions-item label="平台版本">{{ info.version }}</a-descriptions-item>
            <a-descriptions-item label="Python">{{ info.python }} · {{ info.platform }}</a-descriptions-item>
            <a-descriptions-item label="指纹规则">
              {{ info.rules_total }} 条（自定义 {{ info.rules_custom }} · 禁用 {{ info.rules_disabled }}）
            </a-descriptions-item>
            <a-descriptions-item label="浏览器引擎">
              <a-badge :status="info.browser === 'running' ? 'success' : 'default'"
                       :text="info.browser === 'running' ? '运行中' : '空闲'" />
            </a-descriptions-item>
            <a-descriptions-item label="数据库">{{ info.db_engine }}（{{ info.db_size_mb }} MB）</a-descriptions-item>
            <a-descriptions-item label="截图存档">{{ info.screenshots }} 张 / {{ info.screenshots_mb }} MB</a-descriptions-item>
          </a-descriptions>
          <a-skeleton v-else active />
        </a-card>

        <a-card :bordered="false" title="关于">
          <div style="font-size: 13px; color: #525252; line-height: 1.8">
            SCAN 安全检测平台 — 项目化资产测绘 + 源码指纹识别。<br />
            指纹学习 / 规则自定义 / 浏览器抓包识别 / 存活探测 / 截图分析。
          </div>
        </a-card>
      </a-col>
    </a-row>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import api from '../api'

const DEFAULTS = {
  concurrency: 50,
  browser_concurrency: 4,
  active_probe: true,
  screenshot: true,
  connect_timeout: 8,
  read_timeout: 15,
  fofa_email: '',
  fofa_key: '',
  hunter_key: '',
  quake_key: '',
}

const form = reactive({ ...DEFAULTS })
const info = ref(null)
const saving = ref(false)
const newPassword = ref('')

async function save() {
  saving.value = true
  try {
    const payload = { ...form }
    // 留空或掩码显示的 key 不提交 —— 只有输入新值才覆盖已存 key
    for (const k of ['fofa_key', 'hunter_key', 'quake_key']) {
      if (!payload[k] || payload[k].includes('****')) delete payload[k]
    }
    if (newPassword.value) {
      if (newPassword.value.length < 6) {
        message.warning('密码至少 6 位')
        return
      }
      payload.new_password = newPassword.value
    }
    const { data } = await api.updateSettings(payload)
    Object.assign(form, data)
    if (newPassword.value) {
      message.success('密码已修改，请重新登录')
      localStorage.removeItem('scan_token')
      setTimeout(() => (location.href = '/login'), 800)
      return
    }
    message.success('已保存')
  } finally {
    saving.value = false
  }
}

function reset() {
  const { fofa_email, fofa_key, hunter_key, quake_key, ...rest } = DEFAULTS
  Object.assign(form, rest)  // keys are not part of "恢复默认"
}

onMounted(async () => {
  const [s, i] = await Promise.all([api.getSettings(), api.systemInfo()])
  Object.assign(form, s.data)
  info.value = i.data
})
</script>
