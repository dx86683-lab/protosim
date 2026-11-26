<template>
  <el-config-provider :locale="elementLocale">
    <el-container class="app-shell">
      <el-aside width="228px" class="sidebar">
        <div class="brand">
          <div class="brand-logo">PS</div>
          <div>
            <div class="brand-title">ProtoSim</div>
            <div class="brand-sub">{{ t('协议靶场与探针观测') }}</div>
          </div>
        </div>

        <el-menu
          class="sidebar-menu"
          :default-active="activeTab"
          @select="(k: string) => (activeTab = k)"
        >
          <el-menu-item index="dashboard">
            <el-icon><DataAnalysis /></el-icon>
            <span>{{ t('态势总览') }}</span>
          </el-menu-item>
          <el-menu-item index="probes">
            <el-icon><Collection /></el-icon>
            <span>{{ t('探针聚类库') }}</span>
          </el-menu-item>
          <el-menu-item index="testruns">
            <el-icon><Finished /></el-icon>
            <span>{{ t('测试批次与覆盖率') }}</span>
          </el-menu-item>
          <el-menu-item index="sessions">
            <el-icon><Connection /></el-icon>
            <span>{{ t('会话检索与回放') }}</span>
          </el-menu-item>
          <el-menu-item index="live">
            <el-icon><Monitor /></el-icon>
            <span>{{ t('实时事件流') }}</span>
          </el-menu-item>
          <el-menu-item index="scenarios">
            <el-icon><Grid /></el-icon>
            <span>{{ t('场景与服务编排') }}</span>
          </el-menu-item>
          <el-menu-item index="settings">
            <el-icon><Setting /></el-icon>
            <span>{{ t('打标规则与设置') }}</span>
          </el-menu-item>
        </el-menu>

        <div class="sidebar-footer" v-if="health">
          <div class="status-row">
            <span class="dot-ok"></span>
            <span>{{ health.mode }} · {{ t('服务数：{count}', { count: health.services }) }}</span>
          </div>
          <div class="meta-line">{{ t('场景：{scenario}', { scenario: health.scenario || '-' }) }}</div>
          <div class="meta-line" style="display: flex; justify-content: space-between; align-items: center">
            <span>{{ t('版本 {version}', { version: `v${health.version}` }) }}</span>
            <el-button v-if="health.auth_enabled" link type="warning" size="small" @click="logout">{{ t('退出登录') }}</el-button>
          </div>
        </div>
      </el-aside>

      <el-container class="main-wrap" direction="vertical">
        <div class="app-toolbar" role="group" :aria-label="t('显示偏好')">
          <el-button size="small" :lang="locale === 'en' ? 'zh-CN' : 'en'" @click="toggleLocale">
            {{ locale === 'en' ? '中文' : 'English' }}
          </el-button>
          <el-button size="small" @click="toggleTheme">
            <el-icon aria-hidden="true"><Sunny v-if="theme === 'dark'" /><Moon v-else /></el-icon>
            <span>{{ t(theme === 'dark' ? '浅色' : '深色') }}</span>
          </el-button>
        </div>
        <el-main class="main-content">
          <DashboardView v-if="activeTab === 'dashboard'" @navigate="activeTab = $event" />
          <ProbeLibraryView v-else-if="activeTab === 'probes'" />
          <TestRunsView v-else-if="activeTab === 'testruns'" />
          <SessionsView v-else-if="activeTab === 'sessions'" />
          <LiveStreamView v-else-if="activeTab === 'live'" />
          <ScenariosServicesView v-else-if="activeTab === 'scenarios'" @changed="loadHealth" />
          <SettingsRulesView v-else-if="activeTab === 'settings'" />
        </el-main>
      </el-container>
    </el-container>
  </el-config-provider>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import en from 'element-plus/es/locale/lang/en'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import { api } from './api'
import { locale, t, theme, toggleLocale, toggleTheme } from './i18n'
import DashboardView from './views/DashboardView.vue'
import ProbeLibraryView from './views/ProbeLibraryView.vue'
import TestRunsView from './views/TestRunsView.vue'
import SessionsView from './views/SessionsView.vue'
import LiveStreamView from './views/LiveStreamView.vue'
import ScenariosServicesView from './views/ScenariosServicesView.vue'
import SettingsRulesView from './views/SettingsRulesView.vue'

const activeTab = ref('dashboard')
const health = ref<any>(null)
const elementLocale = computed(() => locale.value === 'en' ? en : zhCn)

async function loadHealth() {
  try {
    health.value = await api.health()
  } catch {}
}

async function logout() {
  try {
    await api.logout()
  } finally {
    window.location.replace('/login')
  }
}

onMounted(() => {
  loadHealth()
  setInterval(loadHealth, 15000)
})
</script>

<style>
html, body, #app {
  margin: 0;
  padding: 0;
  height: 100%;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
  background: var(--el-bg-color-page);
  color: var(--el-text-color-primary);
}
.dark { color-scheme: dark; }
.app-shell {
  height: 100vh;
  height: 100dvh;
}
.sidebar {
  background: var(--el-bg-color);
  display: flex;
  flex-direction: column;
  border-right: 1px solid var(--el-border-color-light);
}
.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 18px 16px;
  border-bottom: 1px solid var(--el-border-color-light);
}
.brand-logo {
  flex-shrink: 0;
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
  color: var(--el-text-color-primary);
}
.brand-sub {
  font-size: 11px;
  color: var(--el-text-color-secondary);
}
.sidebar .sidebar-menu {
  border-right: none;
  flex: 1;
}
.sidebar-footer {
  padding: 14px 16px;
  border-top: 1px solid var(--el-border-color-light);
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.status-row {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--el-text-color-primary);
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
}
.main-wrap {
  min-width: 0;
  min-height: 0;
}
.app-toolbar {
  flex: none;
  display: flex;
  justify-content: flex-end;
  padding: 10px 24px;
  background: var(--el-bg-color);
  border-bottom: 1px solid var(--el-border-color-light);
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
  color: var(--el-text-color-primary);
  margin: 0;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
.hexdump {
  background: var(--el-fill-color-light);
  color: var(--el-text-color-primary);
  padding: 12px;
  border-radius: 6px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  line-height: 1.5;
  overflow-x: auto;
  white-space: pre;
  margin: 0;
}
@media (max-width: 720px) {
  .app-shell.el-container { flex-direction: column; }
  .app-shell .sidebar { width: 100%; border-right: 0; flex: none; }
  .sidebar .sidebar-menu { display: flex; overflow-x: auto; }
  .sidebar-menu .el-menu-item { flex: none; }
  .app-toolbar, .main-content { padding-inline: 16px; }
}
</style>
