<template>
  <a-config-provider :theme="theme">
    <a-layout style="min-height: 100vh">
      <a-layout-header class="topbar">
        <router-link to="/" class="brand">
          <span class="brand-mark">S</span>
          SCAN · 网站指纹识别平台
        </router-link>
        <nav class="nav">
          <router-link to="/" class="nav-link">项目</router-link>
          <router-link to="/fingerprints" class="nav-link">指纹库</router-link>
        </nav>
      </a-layout-header>
      <a-layout-content>
        <router-view />
      </a-layout-content>
    </a-layout>
  </a-config-provider>
</template>

<script setup>
const theme = {
  token: {
    colorPrimary: '#2454e6',
    borderRadius: 8,
    fontFamily:
      '"PingFang SC", "Microsoft YaHei", Roboto, "Helvetica Neue", Helvetica, Arial, sans-serif',
  },
}
</script>

<style scoped>
.topbar {
  display: flex;
  align-items: center;
  background: #1a1a1a;
  padding: 0 24px;
  height: 56px;
  line-height: 56px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #fff;
  font-size: 16px;
  font-weight: 600;
}
.nav {
  margin-left: 48px;
  display: flex;
  gap: 24px;
}
.nav-link {
  color: #a6a6a6;
  font-size: 14px;
}
.nav-link.router-link-exact-active {
  color: #fff;
}
.brand-mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border-radius: 8px;
  background: #2454e6;
  color: #fff;
  font-weight: 700;
}
</style>
