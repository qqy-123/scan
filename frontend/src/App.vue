<template>
  <a-config-provider :theme="theme">
    <a-layout style="min-height: 100vh">
      <a-layout-sider :width="216" theme="light" class="sider">
        <router-link to="/" class="brand">
          <span class="brand-mark">S</span>
          <span class="brand-name">SCAN</span>
        </router-link>
        <a-menu mode="inline" :selected-keys="[$route.path]" :open-keys="openKeys">
          <a-menu-item key="/" @click="$router.push('/')">
            <template #icon><DatabaseOutlined /></template>
            项目管理
          </a-menu-item>
          <a-menu-item key="/fingerprints" @click="$router.push('/fingerprints')">
            <template #icon><AimOutlined /></template>
            指纹库
          </a-menu-item>
        </a-menu>
        <div class="sider-foot">网站指纹识别平台</div>
      </a-layout-sider>
      <a-layout>
        <a-layout-content>
          <router-view />
        </a-layout-content>
      </a-layout>
    </a-layout>
  </a-config-provider>
</template>

<script setup>
import { ref } from 'vue'
import { AimOutlined, DatabaseOutlined } from '@ant-design/icons-vue'

const openKeys = ref([])
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
.sider {
  border-right: 1px solid #eaeaea;
  display: flex;
  flex-direction: column;
}
.brand {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 16px;
  height: 56px;
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
.brand-name {
  font-size: 16px;
  font-weight: 600;
  color: #1a1a1a;
}
.sider-foot {
  position: absolute;
  bottom: 16px;
  left: 0;
  right: 0;
  text-align: center;
  color: #a6a6a6;
  font-size: 12px;
}
</style>
