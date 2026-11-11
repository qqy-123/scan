<template>
  <a-modal :open="open" title="发起暴露面测绘" ok-text="开始测绘" cancel-text="取消"
           width="640px" :confirm-loading="starting"
           @ok="start" @cancel="$emit('update:open', false)">
    <a-form layout="vertical">
      <a-form-item v-if="!project" label="选择项目">
        <a-select v-model:value="pid" placeholder="选择要测绘的项目" :options="projectOptions"
                  :loading="!projects.length" @change="pickProject" />
      </a-form-item>
      <a-form-item label="扫描范围">
        <a-radio-group v-model:value="opts.scope">
          <a-radio value="alive">存活目标（{{ aliveCount }}）</a-radio>
          <a-radio value="all">全部目标（{{ targetCount }}）</a-radio>
        </a-radio-group>
      </a-form-item>
      <div class="opt-group">站内测绘</div>
      <a-form-item>
        <a-checkbox-group v-model:value="opts.kinds" class="opt-list">
          <a-checkbox value="js">JS 接口提取（隐藏 API / 后台路径 / sourcemap + 参数攻击点分类 + 敏感信息检测）</a-checkbox>
          <a-checkbox value="dir">目录爆破（字典探测后台/备份/配置；命中目录自动递归多级；覆盖存活子域根与入口前缀）</a-checkbox>
        </a-checkbox-group>
      </a-form-item>
      <div class="opt-group">域名扩展</div>
      <a-form-item>
        <a-checkbox-group v-model:value="opts.kinds" class="opt-list">
          <a-checkbox value="sub">子域名收集（crt.name / crt.sh 证书透明日志 + 页面提取，解析到的自动探活）</a-checkbox>
          <a-checkbox value="brute">子域爆破（内置字典 DNS 枚举 + HTTP 验证）</a-checkbox>
          <a-checkbox value="host">Host 碰撞（对目标 IP 用 SNI+Host 探隐藏虚拟主机，依赖子域发现结果）</a-checkbox>
          <a-checkbox value="origin">源站探测 fuckcdn（对子域/测绘 IP 及所在 C 段做 SNI 碰撞，匹配首页签名定位 CDN 后真实源站 IP）</a-checkbox>
          <a-checkbox value="takeover">子域接管检测（CNAME 悬空指向 GitHub/Heroku/S3 等可认领服务的子域）</a-checkbox>
          <a-checkbox value="wayback">历史 URL（web.archive.org CDX 档案：已下线但可能仍存活的老接口/后台/带参端点）</a-checkbox>
          <a-checkbox value="port">端口扫描（存活主机 TOP 端口 + banner 识别 + Redis/ES/Mongo/Docker 未授权检测）</a-checkbox>
        </a-checkbox-group>
      </a-form-item>
      <div class="opt-group">
        网络空间测绘
        <a-tooltip title="在「系统配置 → 网络空间测绘 API」里配置 key">
          <a-button size="small" href="/settings" target="_blank">去配置</a-button>
        </a-tooltip>
      </div>
      <a-form-item>
        <a-checkbox-group v-model:value="opts.kinds" class="opt-list">
          <a-checkbox value="net" :disabled="!engines.any">
            资产搜索引擎（{{ engines.fofa ? 'FOFA✓ ' : 'FOFA✗ ' }}{{ engines.hunter ? '· 鹰图✓ ' : '· 鹰图✗ ' }}{{ engines.quake ? '· Quake✓' : '· Quake✗' }}）
          </a-checkbox>
        </a-checkbox-group>
        <div v-if="!engines.any" style="color: #a6a6a6; font-size: 12px; margin-top: -8px">
          未配置任何引擎 key —— 到系统配置里填 FOFA / 鹰图 / Quake key 即可启用
        </div>
      </a-form-item>
      <a-form-item>
        <a-checkbox v-model:checked="opts.auto_deep">完成后自动深扫（对真实攻击面截图 + 指纹识别，与首页相同的回声页不算攻击面）</a-checkbox>
      </a-form-item>
      <a-form-item v-if="opts.auto_deep" label="截图上限（探测全部URL，相同页面只截一次，存活子域优先）">
        <a-input-number v-model:value="opts.deep_limit" :min="10" :max="1000" style="width: 140px" />
        <a-checkbox v-model:checked="opts.fingerprint" style="margin-left: 16px">指纹识别</a-checkbox>
      </a-form-item>
    </a-form>
  </a-modal>
</template>

<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { message } from 'ant-design-vue'
import api from '../api'

const props = defineProps({
  open: Boolean,
  project: Object,          // fixed project (detail page); null → picker
})
const emit = defineEmits(['update:open', 'started'])

const opts = reactive({
  scope: 'alive', kinds: ['js', 'dir', 'sub'], auto_deep: true, deep_limit: 200,
  fingerprint: true,
})
const projects = ref([])
const pid = ref(null)
const picked = ref(null)    // fetched project detail when using the picker
const engines = reactive({ fofa: false, hunter: false, quake: false, any: false })
const starting = ref(false)

const active = computed(() => props.project || picked.value)
const targetCount = computed(() => active.value?.targets?.length || 0)
const aliveCount = computed(
  () => (active.value?.targets || []).filter((t) => t.alive).length,
)
const projectOptions = computed(() =>
  projects.value.map((p) => ({ value: p.id, label: p.name })),
)

async function pickProject(id) {
  picked.value = null
  if (!id) return
  const { data } = await api.getProject(id)
  picked.value = data
}

watch(
  () => props.open,
  async (v) => {
    if (!v) return
    api.getSettings().then(({ data }) => {
      engines.fofa = !!(data.fofa_email && data.fofa_key)
      engines.hunter = !!data.hunter_key
      engines.quake = !!data.quake_key
      engines.any = engines.fofa || engines.hunter || engines.quake
    })
    if (!props.project && !projects.value.length) {
      const { data } = await api.listProjects()
      projects.value = data
    }
  },
)

async function start() {
  const p = active.value
  if (!p) return message.warning('先选择一个项目')
  if (!opts.kinds.length) return message.warning('至少选一种测绘方式')
  starting.value = true
  try {
    await api.createExposure(p.id, { ...opts })
    message.success('测绘任务已开始')
    emit('update:open', false)
    emit('started')
  } catch (e) {
    message.warning(e.response?.data?.detail || '发起失败')
  } finally {
    starting.value = false
  }
}
</script>
