<template>
  <a-config-provider :theme="theme">
    <a-layout style="min-height: 100vh">
      <a-layout-sider :width="216" theme="light" class="sider">
        <router-link to="/" class="brand">
          <span class="brand-mark">S</span>
          <span>
            <div class="brand-name">SCAN</div>
            <div class="brand-sub">安全检测平台</div>
          </span>
        </router-link>
        <a-menu
          mode="inline"
          :selected-keys="[menuKey]"
          style="border-inline-end: none"
        >
          <a-menu-item key="/" @click="$router.push('/')">
            <template #icon><DashboardOutlined /></template>
            工作台
          </a-menu-item>
          <a-menu-item-group title="资产测绘">
            <a-menu-item key="/projects" @click="$router.push('/projects')">
              <template #icon><DatabaseOutlined /></template>
              项目管理
            </a-menu-item>
            <a-menu-item key="/fingerprints" @click="$router.push('/fingerprints')">
              <template #icon><AimOutlined /></template>
              指纹库
            </a-menu-item>
          </a-menu-item-group>
          <a-menu-item-group title="功能扩展">
            <a-menu-item key="/future" disabled>
              <template #icon><AppstoreAddOutlined /></template>
              <span style="color: #bfbfbf">更多模块待接入…</span>
            </a-menu-item>
          </a-menu-item-group>
        </a-menu>
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
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import {
  AimOutlined,
  AppstoreAddOutlined,
  DashboardOutlined,
  DatabaseOutlined,
} from '@ant-design/icons-vue'

const route = useRoute()
const menuKey = computed(() => {
  if (route.path.startsWith('/projects')) return '/projects'
  if (route.path.startsWith('/fingerprints')) return '/fingerprints'
  return '/'
})

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
}
.brand {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 16px;
  height: 64px;
  margin-bottom: 8px;
}
.brand-mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border-radius: 8px;
  background: #2454e6;
  color: #fff;
  font-weight: 700;
  font-size: 16px;
}
.brand-name {
  font-size: 16px;
  font-weight: 600;
  color: #1a1a1a;
  line-height: 1.2;
}
.brand-sub {
  font-size: 12px;
  color: #a6a6a6;
  line-height: 1.2;
}
</style>
