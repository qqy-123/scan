<template>
  <a-config-provider :theme="theme">
    <router-view v-if="route.name === 'login'" />
    <a-layout v-else class="app">
      <!-- ARTEX-style light sidebar -->
      <aside class="sider" :class="{ collapsed }">
        <router-link to="/" class="brand">
          <svg class="logo" viewBox="0 0 24 24" fill="none">
            <circle cx="7" cy="7" r="3" stroke="#0a0a0a" stroke-width="2" />
            <circle cx="17" cy="7" r="3" stroke="#0a0a0a" stroke-width="2" />
            <circle cx="7" cy="17" r="3" stroke="#0a0a0a" stroke-width="2" />
            <circle cx="17" cy="17" r="3" stroke="#0a0a0a" stroke-width="2" />
          </svg>
          <span v-if="!collapsed" class="brand-name">SCAN</span>
        </router-link>

        <nav class="nav">
          <div v-if="!collapsed" class="nav-group">功能</div>
          <router-link
            v-for="it in navMain"
            :key="it.path"
            :to="it.path"
            class="nav-item"
            :class="{ active: isActive(it.path) }"
            :title="it.label"
          >
            <component :is="it.icon" class="nav-icon" />
            <span v-if="!collapsed">{{ it.label }}</span>
          </router-link>

          <div v-if="!collapsed" class="nav-group">系统</div>
          <router-link
            to="/settings"
            class="nav-item"
            :class="{ active: isActive('/settings') }"
            title="系统配置"
          >
            <SettingOutlined class="nav-icon" />
            <span v-if="!collapsed">系统配置</span>
          </router-link>
        </nav>

        <a-dropdown :trigger="['click']" placement="topRight">
          <div class="sider-foot">
            <a-avatar :size="24" style="background: #0a0a0a; font-size: 12px">S</a-avatar>
            <span v-if="!collapsed">SCAN 平台</span>
            <MoreOutlined v-if="!collapsed" style="margin-left: auto; color: #a6a6a6" />
          </div>
          <template #overlay>
            <a-menu>
              <a-menu-item key="settings" @click="$router.push('/settings')">系统配置</a-menu-item>
              <a-menu-item key="about" @click="showAbout">关于平台</a-menu-item>
              <a-menu-divider />
              <a-menu-item key="logout" @click="logout">退出登录</a-menu-item>
            </a-menu>
          </template>
        </a-dropdown>
      </aside>

      <a-layout>
        <!-- top bar -->
        <header class="topbar">
          <MenuFoldOutlined class="tb-btn" @click="collapsed = !collapsed" />
          <div class="tb-space" />
          <a-dropdown :trigger="['click']">
            <a-avatar :size="28" style="background: #e5e5e5; color: #525252; cursor: pointer">A</a-avatar>
            <template #overlay>
              <a-menu>
                <a-menu-item key="settings" @click="$router.push('/settings')">系统配置</a-menu-item>
                <a-menu-item key="about" @click="showAbout">关于平台</a-menu-item>
                <a-menu-divider />
                <a-menu-item key="logout" @click="logout">退出登录</a-menu-item>
              </a-menu>
            </template>
          </a-dropdown>
        </header>

        <a-layout-content class="content">
          <router-view />
        </a-layout-content>
      </a-layout>
    </a-layout>
  </a-config-provider>
</template>

<script setup>
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Modal } from 'ant-design-vue'
import {
  AimOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  MenuFoldOutlined,
  MoreOutlined,
  RadarChartOutlined,
  SettingOutlined,
} from '@ant-design/icons-vue'

const route = useRoute()
const router = useRouter()
const collapsed = ref(false)

// monochrome theme: black primary buttons like ARTEX
const theme = {
  token: {
    colorPrimary: '#0a0a0a',
    colorLink: '#0a0a0a',
    colorInfo: '#0a0a0a',
    borderRadius: 8,
    fontFamily:
      '"PingFang SC", "Microsoft YaHei", Roboto, "Helvetica Neue", Helvetica, Arial, sans-serif',
  },
}

const navMain = [
  { path: '/', label: '仪表盘', icon: DashboardOutlined },
  { path: '/projects', label: '项目管理', icon: DatabaseOutlined },
  { path: '/exposure', label: '暴露面测绘', icon: RadarChartOutlined },
  { path: '/fingerprints', label: '指纹库', icon: AimOutlined },
]

const isActive = (p) =>
  p === '/' ? route.path === '/' : route.path.startsWith(p)

const logout = () => {
  localStorage.removeItem('scan_token')
  router.push('/login')
}

const showAbout = () =>
  Modal.info({
    title: '关于 SCAN',
    content:
      'SCAN 安全检测平台 — 项目化资产测绘 + 源码指纹识别。' +
      '支持指纹学习、规则自定义、浏览器抓包识别、存活探测与截图分析。',
    okText: '知道了',
  })
</script>

<style scoped>
.app {
  min-height: 100vh;
  display: flex;
  flex-direction: row;
}

/* sidebar */
.sider {
  width: 232px;
  flex-shrink: 0;
  background: var(--bg-sider);
  border-right: 1px solid var(--gray-20);
  display: flex;
  flex-direction: column;
  height: 100vh;
  position: sticky;
  top: 0;
  transition: width 0.2s;
}
.sider.collapsed {
  width: 64px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 16px 18px;
}
.logo {
  width: 22px;
  height: 22px;
  flex-shrink: 0;
}
.brand-name {
  font-size: 16px;
  font-weight: 700;
  color: var(--ink);
  letter-spacing: 0.5px;
}
.brand:hover {
  text-decoration: none;
}

.nav {
  flex: 1;
  padding: 4px 12px;
  overflow-y: auto;
}
.nav-group {
  font-size: 11px;
  color: var(--gray-40);
  padding: 16px 10px 6px;
}
.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border-radius: 8px;
  font-size: 13.5px;
  color: var(--gray-80);
  margin-bottom: 2px;
}
.nav-item:hover {
  background: #ececec;
  text-decoration: none;
}
.nav-item.active {
  background: #e8e8e8;
  color: var(--ink);
  font-weight: 500;
}
.nav-item.disabled {
  color: var(--gray-40);
  cursor: default;
}
.nav-item.disabled:hover {
  background: none;
}
.nav-icon {
  font-size: 15px;
  flex-shrink: 0;
}
.soon {
  margin-left: auto;
  font-size: 11px;
  color: var(--gray-30);
}
.collapsed .nav-item {
  justify-content: center;
  padding: 10px;
}

.sider-foot {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px 18px;
  border-top: 1px solid var(--gray-20);
  font-size: 13px;
  color: var(--gray-80);
  cursor: pointer;
}
.sider-foot:hover {
  background: #ececec;
}

/* topbar */
.topbar {
  display: flex;
  align-items: center;
  gap: 16px;
  height: 56px;
  padding: 0 20px;
  background: #fff;
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 10;
}
.tb-btn {
  font-size: 15px;
  color: var(--gray-60);
  cursor: pointer;
}
.tb-space {
  flex: 1;
}

.content {
  min-height: calc(100vh - 56px);
}
</style>
