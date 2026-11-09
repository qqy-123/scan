<template>
  <div class="login-wrap">
    <div class="login-card">
      <div class="login-logo">SCAN</div>
      <div class="login-sub">安全检测平台 · 输入密码进入</div>
      <a-input-password
        v-model:value="password"
        size="large"
        placeholder="平台密码"
        class="login-input"
        @pressEnter="doLogin"
      >
        <template #prefix><LockOutlined /></template>
      </a-input-password>
      <a-button type="primary" size="large" block :loading="loading" @click="doLogin">
        登 录
      </a-button>
      <div class="login-tip">密码可在「系统配置」中修改</div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { LockOutlined } from '@ant-design/icons-vue'
import api from '../api'

const password = ref('')
const loading = ref(false)
const route = useRoute()
const router = useRouter()

async function doLogin() {
  if (!password.value) return message.warning('请输入密码')
  loading.value = true
  try {
    const { data } = await api.login(password.value)
    localStorage.setItem('scan_token', data.token)
    router.replace(route.query.next || '/')
  } catch (e) {
    message.error(e.response?.data?.detail || '密码错误')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-wrap {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f5f5f5;
}
.login-card {
  width: 360px;
  background: #fff;
  border: 1px solid #eaeaea;
  border-radius: 12px;
  padding: 40px 36px 28px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.04);
}
.login-logo {
  font-size: 28px;
  font-weight: 800;
  letter-spacing: 6px;
  text-align: center;
}
.login-sub {
  text-align: center;
  color: #8c8c8c;
  font-size: 13px;
  margin: 8px 0 28px;
}
.login-input { margin-bottom: 16px; }
.login-tip {
  margin-top: 20px;
  text-align: center;
  color: #bfbfbf;
  font-size: 12px;
}
</style>
