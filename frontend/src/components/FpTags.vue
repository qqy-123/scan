<template>
  <template v-if="list.length">
    <a-tooltip v-for="f in list" :key="f.name" :title="tip(f)">
      <a-tag :color="lvColor(level(f))" style="margin-bottom: 2px">
        {{ lvText(level(f)) }}·{{ f.name }}{{ f.version ? ' ' + f.version : '' }}
      </a-tag>
    </a-tooltip>
  </template>
  <a-tag v-else>无记录</a-tag>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({ raw: [String, Array] })

const LV = {
  confirmed: { text: '确认', color: 'green' },
  high: { text: '高可信', color: 'orange' },
  low: { text: '低可信', color: 'default' },
}
const lvText = (l) => (LV[l] || LV.low).text
const lvColor = (l) => (LV[l] || LV.low).color

// same tiers as backend hit_level(), with fallback for hits stored
// before the level field existed
function level(f) {
  if (f.level) return f.level
  if (f.confidence === 'implied') return 'low'
  const fields = new Set((f.evidence || []).map((e) => e.field))
  if (['probe', 'favicon', 'dom'].some((x) => fields.has(x))) return 'confirmed'
  return (f.score || 0) >= 100 ? 'high' : 'low'
}

function tip(f) {
  const fields = [...new Set((f.evidence || []).map((e) => e.field))].join('/')
  return `${f.category || ''} · score ${f.score ?? '-'}${fields ? ' · 证据 ' + fields : ''}`
}

const list = computed(() => {
  const r = props.raw
  if (Array.isArray(r)) return r
  if (!r) return []
  try {
    return JSON.parse(r) || []
  } catch {
    return []
  }
})
</script>
