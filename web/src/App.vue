<template>
  <el-container class="app-shell">
    <el-aside width="228px" class="sidebar">
      <div class="brand">
        <div class="brand-logo">PS</div>
        <div>
          <div class="brand-title">ProtoSim</div>
          <div class="brand-sub">协议靶场与探针观测</div>
        </div>
      </div>

      <el-menu
        :default-active="activeTab"
        background-color="#0f172a"
        text-color="#cbd5e1"
        active-text-color="#38bdf8"
        @select="(k: string) => (activeTab = k)"
      >
        <el-menu-item index="dashboard">
          <el-icon><DataAnalysis /></el-icon>
          <span>态势总览</span>
        </el-menu-item>
        <el-menu-item index="probes">
          <el-icon><Collection /></el-icon>
          <span>探针聚类库</span>
        </el-menu-item>
        <el-menu-item index="testruns">
          <el-icon><Finished /></el-icon>
          <span>测试批次与覆盖率</span>
        </el-menu-item>
        <el-menu-item index="sessions">
          <el-icon><Connection /></el-icon>
          <span>会话检索与回放</span>
        </el-menu-item>
        <el-menu-item index="live">
          <el-icon><Monitor /></el-icon>
          <span>实时事件流</span>
        </el-menu-item>
        <el-menu-item index="scenarios">
          <el-icon><Grid /></el-icon>
          <span>场景与服务编排</span>
        </el-menu-item>
        <el-menu-item index="settings">
          <el-icon><Setting /></el-icon>
          <span>打标规则与设置</span>
        </el-menu-item>
      </el-menu>

      <div class="sidebar-footer" v-if="health">
        <div class="status-row">
          <span class="dot-ok"></span>
          <span>{{ health.mode }} · {{ health.services }} 服务</span>
        </div>
        <div class="meta-line">场景: {{ health.scenario || '-' }}</div>
        <div class="meta-line" style="display: flex; justify-content: space-between; align-items: center">
          <span>版本: v{{ health.version }}</span>
          <el-button v-if="health.auth_enabled" link type="warning" size="small" @click="logout">退出登录</el-button>
        </div>
      </div>
    </el-aside>

    <el-container class="main-wrap">
      <el-main class="main-content" :key="authEpoch">
        <DashboardView v-if="activeTab === 'dashboard'" @navigate="activeTab = $event" />
        <ProbeLibraryView v-else-if="activeTab === 'probes'" />
        <TestRunsView v-else-if="activeTab === 'testruns'" />
        <SessionsView v-else-if="activeTab === 'sessions'" />
        <LiveStreamView v-else-if="activeTab === 'live'" />
        <ScenariosServicesView v-else-if="activeTab === 'scenarios'" @changed="loadHealth" />
        <SettingsRulesView v-else-if="activeTab === 'settings'" />
      </el-main>
    </el-container>

    <el-dialog v-model="authDialog" title="ProtoSim 访问认证" width="400px" :close-on-click-modal="false" :show-close="false">
      <p style="margin: 0 0 12px; font-size: 13px; color: #475569">当前实例已启用访问鉴权，请输入启动时配置的 API Token：</p>
      <el-input v-model="tokenInput" type="password" show-password placeholder="请输入 API Token" @keyup.enter="submitToken" />
      <template #footer>
        <el-button type="primary" :loading="authChecking" @click="submitToken">验证并登录</el-button>
      </template>
    </el-dialog>
  </el-container>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from './api'
import DashboardView from './views/DashboardView.vue'
import ProbeLibraryView from './views/ProbeLibraryView.vue'
import TestRunsView from './views/TestRunsView.vue'
import SessionsView from './views/SessionsView.vue'
import LiveStreamView from './views/LiveStreamView.vue'
import ScenariosServicesView from './views/ScenariosServicesView.vue'
import SettingsRulesView from './views/SettingsRulesView.vue'

const activeTab = ref('dashboard')
const health = ref<any>(null)
const authDialog = ref(false)
const authChecking = ref(false)
const tokenInput = ref('')
const authEpoch = ref(0)

async function loadHealth() {
  try {
    health.value = await api.health()
    if (health.value?.auth_enabled && !localStorage.getItem('protosim_token')) {
      authDialog.value = true
    }
  } catch {}
}

function onUnauthorized() {
  authDialog.value = true
}

async function submitToken() {
  const t = tokenInput.value.trim()
  if (!t) return
  authChecking.value = true
  try {
    localStorage.setItem('protosim_token', t)
    await api.config()
    authDialog.value = false
    tokenInput.value = ''
    authEpoch.value++
    ElMessage.success('认证成功')
  } catch {
    localStorage.removeItem('protosim_token')
    ElMessage.error('Token 无效，请检查后重试')
  } finally {
    authChecking.value = false
  }
}

function logout() {
  localStorage.removeItem('protosim_token')
  authDialog.value = true
}

onMounted(() => {
  window.addEventListener('protosim:unauthorized', onUnauthorized)
  loadHealth()
  setInterval(loadHealth, 15000)
})

onUnmounted(() => {
  window.removeEventListener('protosim:unauthorized', onUnauthorized)
})
</script>

<style>
html, body, #app {
  margin: 0;
  padding: 0;
  height: 100%;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
  background: #f1f5f9;
  color: #0f172a;
}
.app-shell {
  height: 100vh;
}
.sidebar {
  background: #0f172a;
  color: #e2e8f0;
  display: flex;
  flex-direction: column;
  border-right: 1px solid #1e293b;
}
.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 18px 16px;
  border-bottom: 1px solid #1e293b;
}
.brand-logo {
  width: 36px;
  height: 36px;
  border-radius: 8px;
  background: linear-gradient(135deg, #0284c7, #38bdf8);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 800;
  color: #fff;
  letter-spacing: 0.5px;
}
.brand-title {
  font-size: 16px;
  font-weight: 700;
  color: #f8fafc;
}
.brand-sub {
  font-size: 11px;
  color: #94a3b8;
}
.el-menu {
  border-right: none !important;
  flex: 1;
}
.sidebar-footer {
  padding: 14px 16px;
  border-top: 1px solid #1e293b;
  font-size: 12px;
  color: #94a3b8;
}
.status-row {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #e2e8f0;
  font-weight: 500;
  margin-bottom: 4px;
}
.dot-ok {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #22c55e;
  display: inline-block;
}
.meta-line {
  margin-top: 2px;
  font-size: 11px;
  color: #94a3b8;
}
.main-wrap {
  background: #f1f5f9;
  overflow: auto;
}
.main-content {
  padding: 20px 24px;
}
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.page-title {
  font-size: 20px;
  font-weight: 700;
  color: #0f172a;
  margin: 0;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
.hexdump {
  background: #0f172a;
  color: #e2e8f0;
  padding: 12px;
  border-radius: 6px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  line-height: 1.5;
  overflow-x: auto;
  white-space: pre;
  margin: 0;
}
</style>
