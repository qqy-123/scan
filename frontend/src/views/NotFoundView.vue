<template>
  <div class="nf">
    <a-result status="404" title="404" sub-title="访问的页面不存在">
      <template #extra>
        <router-link to="/">返回首页</router-link>
      </template>
    </a-result>
  </div>
</template>

<style scoped>
.nf {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 70vh;
}
</style>
