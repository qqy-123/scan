<template>
  <div class="nf">
    <a-result status="404" title="404" sub-title="访问的页面不存在">
      <template #extra>
        <a-button type="primary" @click="goBack">
          <template #icon><ArrowLeftOutlined /></template>返回上一级
        </a-button>
      </template>
    </a-result>
  </div>
</template>

<script setup>
import { ArrowLeftOutlined } from '@ant-design/icons-vue'
import { useBack } from '../back'

const goBack = useBack('/')
</script>

<style scoped>
.nf {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 70vh;
}
</style>
