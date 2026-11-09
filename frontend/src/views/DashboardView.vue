<template>
  <div class="page">
    <div class="page-header">
      <div>
        <div class="page-title">总览</div>
        <div class="page-sub">系统全局状态 · 实时刷新</div>
      </div>
      <a-button type="primary" @click="$router.push('/projects')">
        <template #icon><PlusOutlined /></template>
        新建项目
      </a-button>
    </div>

    <!-- ARTEX-style stat cards: icon+label, big number, colored sub-items -->
    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="24 / 5" v-for="s in stats" :key="s.label" :flex="1">
        <a-card :bordered="false" class="stat-card">
          <div class="stat-top">
            <component :is="s.icon" class="stat-ico" />
            <span class="stat-label">{{ s.label }}</span>
          </div>
          <div class="stat-num">{{ s.value }}</div>
          <div class="stat-sub" v-if="s.sub">
            <span v-for="(it, i) in s.sub" :key="i" :style="{ color: it.color }">
              {{ it.text }}
            </span>
          </div>
        </a-card>
      </a-col>
    </a-row>

    <!-- charts -->
    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="8">
        <a-card :bordered="false" title="目标存活占比">
          <div ref="donutEl" class="chart" />
        </a-card>
      </a-col>
      <a-col :span="8">
        <a-card :bordered="false" title="HTTP 状态码分布">
          <div ref="statusEl" class="chart" />
        </a-card>
      </a-col>
      <a-col :span="8">
        <a-card :bordered="false" title="指纹命中 TOP 10">
          <div ref="barEl" class="chart" />
        </a-card>
      </a-col>
    </a-row>

    <!-- activity feed + per-project bars -->
    <a-row :gutter="16">
      <a-col :span="12">
        <a-card :bordered="false">
          <template #title><ThunderboltOutlined /> 最近扫描</template>
          <template #extra>
            <a-button size="small" @click="router.push('/projects')">全部 →</a-button>
          </template>
          <div v-if="data?.recent_scans?.length" class="feed">
            <div v-for="s in data.recent_scans" :key="s.id" class="feed-item">
              <a-tag :color="s.kind === 'rescan' ? 'purple' : 'blue'" class="feed-tag">
                {{ s.kind === 'rescan' ? '二次' : '全量' }}
              </a-tag>
              <div class="feed-body">
                <div class="feed-title">{{ s.project_name }}</div>
                <div class="feed-desc">
                  轮次 #{{ s.id }} ·
                  {{ s.status === 'running' ? `进行中 ${s.done}/${s.total}` : `存活 ${s.alive}/${s.total}` }}
                </div>
              </div>
              <div class="feed-time">{{ ago(s.started_at) }}</div>
              <a-button size="small" type="primary" ghost
                        @click="router.push(`/projects/${s.project_id}?tab=scans&scan=${s.id}`)">查看</a-button>
            </div>
          </div>
          <a-empty v-else description="暂无扫描" :image="simpleImg" />
        </a-card>
      </a-col>
      <a-col :span="12">
        <a-card :bordered="false">
          <template #title><DatabaseOutlined /> 项目存活概览</template>
          <template #extra>
            <a-button size="small" @click="router.push('/projects')">全部 →</a-button>
          </template>
          <div v-if="projects.length" class="plist">
            <div v-for="p in projects" :key="p.id" class="plist-item">
              <div class="plist-name">{{ p.name }}</div>
              <a-button size="small" type="primary" ghost style="flex-shrink: 0"
                        @click="router.push(`/projects/${p.id}`)">查看</a-button>
              <div class="pbar">
                <div class="seg green" :style="{ width: pct(p.alive_count, p) }" />
                <div class="seg red" :style="{ width: pct(p.dead_count, p) }" />
                <div class="seg gray" :style="{ width: pct(unscanned(p), p) }" />
              </div>
              <div class="plist-counts">
                <span style="color: var(--green)">{{ p.alive_count }} 存活</span>
                <span style="color: var(--red)">{{ p.dead_count }} 失活</span>
                <span style="color: var(--gray-40)">{{ unscanned(p) }} 未探测</span>
              </div>
            </div>
          </div>
          <a-empty v-else description="暂无项目" :image="simpleImg" />
        </a-card>
      </a-col>
    </a-row>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Empty } from 'ant-design-vue'
import {
  AimOutlined,
  CloudServerOutlined,
  DatabaseOutlined,
  GlobalOutlined,
  PlusOutlined,
  ProjectOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons-vue'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import 'dayjs/locale/zh-cn'
import api from '../api'
import { useChart } from '../chart'

dayjs.extend(relativeTime)
dayjs.locale('zh-cn')

const simpleImg = Empty.PRESENTED_IMAGE_SIMPLE
const router = useRouter()
const data = ref(null)
const projects = ref([])

const ago = (t) => (t ? dayjs(t).fromNow() : '-')
const unscanned = (p) => p.target_count - p.alive_count - p.dead_count
const pct = (n, p) => (p.target_count ? `${(n / p.target_count) * 100}%` : '0%')

const stats = computed(() => {
  const d = data.value || {}
  return [
    {
      label: '项目', value: d.projects ?? 0, icon: ProjectOutlined,
      sub: [{ text: `${d.targets ?? 0} 目标`, color: 'var(--gray-50)' }],
    },
    {
      label: '存活目标', value: d.alive ?? 0, icon: GlobalOutlined,
      sub: [
        { text: `失活 ${d.dead ?? 0}`, color: 'var(--red)' },
        { text: `未探测 ${d.unscanned ?? 0}`, color: 'var(--gray-40)' },
      ],
    },
    {
      label: '扫描轮次', value: d.scans ?? 0, icon: CloudServerOutlined,
      sub: [{ text: `运行中 ${d.running ?? 0}`, color: 'var(--accent)' }],
    },
    {
      label: 'HTTP 200', value: d.status_dist?.['200'] ?? 0, icon: ThunderboltOutlined,
      sub: [{ text: `${Object.keys(d.status_dist || {}).length} 种状态码`, color: 'var(--gray-50)' }],
    },
    {
      label: '指纹规则', value: d.rules_count ?? 0, icon: AimOutlined,
      sub: [{ text: '内置 + 自定义', color: 'var(--gray-50)' }],
    },
  ]
})

// donut: alive / dead / unscanned, center shows alive count
const donutEl = useChart(() => ({
  tooltip: { trigger: 'item' },
  legend: { bottom: 0, icon: 'circle', itemWidth: 8, textStyle: { fontSize: 11 } },
  title: {
    text: String(data.value?.alive ?? 0),
    subtext: '存活',
    left: 'center',
    top: '36%',
    itemGap: 2,
    textStyle: { fontSize: 30, fontWeight: 600, color: '#0a0a0a' },
    subtextStyle: { fontSize: 12, color: '#8c8c8c' },
  },
  series: [{
    type: 'pie',
    radius: ['58%', '80%'],
    center: ['50%', '42%'],
    label: { show: false },
    itemStyle: { borderColor: '#fff', borderWidth: 2, borderRadius: 4 },
    data: [
      { value: data.value?.alive ?? 0, name: '存活', itemStyle: { color: '#22c55e' } },
      { value: data.value?.dead ?? 0, name: '失活', itemStyle: { color: '#ef4444' } },
      { value: data.value?.unscanned ?? 0, name: '未探测', itemStyle: { color: '#d4d4d4' } },
    ],
  }],
}))

const statusEl = useChart(() => {
  const dist = data.value?.status_dist || {}
  return {
    tooltip: { trigger: 'item' },
    legend: { bottom: 0, icon: 'circle', itemWidth: 8, textStyle: { fontSize: 11 } },
    series: [{
      type: 'pie',
      radius: ['45%', '72%'],
      center: ['50%', '42%'],
      label: { show: true, formatter: '{b}: {c}', fontSize: 11, color: '#737373' },
      itemStyle: { borderColor: '#fff', borderWidth: 2, borderRadius: 4 },
      data: Object.entries(dist).map(([k, v]) => ({
        value: v,
        name: k,
        itemStyle: {
          color: k.startsWith('2') ? '#4e6ef2'
               : k.startsWith('3') ? '#a855f7'
               : k.startsWith('4') ? '#f59e0b'
               : '#ef4444',
        },
      })),
    }],
  }
})

const barEl = useChart(() => {
  const top = (data.value?.top_fingerprints || []).slice(0, 10).reverse()
  return {
    tooltip: {},
    grid: { left: 8, right: 28, top: 8, bottom: 8, containLabel: true },
    xAxis: { type: 'value', splitLine: { lineStyle: { color: '#f0f0f0' } }, axisLabel: { fontSize: 10, color: '#a6a6a6' } },
    yAxis: { type: 'category', data: top.map((t) => t.name), axisLabel: { fontSize: 11, color: '#525252' }, axisLine: { show: false }, axisTick: { show: false } },
    series: [{
      type: 'bar',
      data: top.map((t) => t.count),
      barWidth: 12,
      itemStyle: { color: '#4e6ef2', borderRadius: [0, 6, 6, 0] },
      label: { show: true, position: 'right', fontSize: 10, color: '#8c8c8c' },
    }],
  }
})

onMounted(async () => {
  const [ov, pj] = await Promise.all([api.overview(), api.listProjects()])
  data.value = ov.data
  projects.value = pj.data.slice(0, 6)
})
</script>

<style scoped>
.chart {
  height: 230px;
}

/* stat cards */
.stat-card :deep(.ant-card-body) {
  padding: 16px 18px;
}
.stat-top {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--gray-60);
  font-size: 12.5px;
}
.stat-ico {
  font-size: 13px;
}
.stat-num {
  font-size: 30px;
  font-weight: 600;
  line-height: 1.3;
  margin-top: 2px;
  color: var(--ink);
}
.stat-sub {
  display: flex;
  gap: 10px;
  font-size: 12px;
  margin-top: 2px;
}

/* feed list */
.more {
  font-size: 12px;
  color: var(--gray-50);
}
.feed-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 0;
  border-bottom: 1px solid #f3f3f3;
}
.feed-item:last-child {
  border-bottom: none;
}
.feed-tag {
  margin-top: 1px;
}
.feed-body {
  flex: 1;
  min-width: 0;
}
.feed-title {
  font-size: 13.5px;
  font-weight: 500;
  color: var(--ink);
}
.feed-desc {
  font-size: 12px;
  color: var(--gray-50);
  margin-top: 2px;
}
.feed-time {
  font-size: 12px;
  color: var(--gray-40);
  white-space: nowrap;
}

/* per-project stacked bars */
.plist-item {
  padding: 10px 0;
  border-bottom: 1px solid #f3f3f3;
}
.plist-item:last-child {
  border-bottom: none;
}
.plist-name {
  font-size: 13.5px;
  font-weight: 500;
  color: var(--ink);
}
.pbar {
  display: flex;
  height: 8px;
  border-radius: 4px;
  overflow: hidden;
  background: #f0f0f0;
  margin: 8px 0 6px;
}
.seg.green { background: var(--green); }
.seg.red { background: var(--red); }
.seg.gray { background: #d4d4d4; }
.plist-counts {
  display: flex;
  gap: 12px;
  font-size: 12px;
}
</style>
