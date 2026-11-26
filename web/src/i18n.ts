import { ref, watchEffect } from 'vue'
import management from './messages-management'
import monitoring from './messages-monitoring'

const languageKey = 'protosim.locale'
const themeKey = 'protosim.theme'

function readPreference(key: string): string | null {
  try {
    return window.localStorage.getItem(key)
  } catch {
    return null
  }
}

function writePreference(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value)
  } catch {
    // Preferences still apply to the current page if storage is unavailable.
  }
}

export const locale = ref<'zh-CN' | 'en'>(readPreference(languageKey) === 'en' ? 'en' : 'zh-CN')
export const theme = ref<'light' | 'dark'>(readPreference(themeKey) === 'dark' ? 'dark' : 'light')

const english: Record<string, string> = {
  ...management,
  ...monitoring,
  '协议': 'Protocol',
  '端口': 'Port',
  '扫描器': 'Scanner',
  '扫描器标签': 'Scanner Tag',
  '刷新': 'Refresh',
  '状态': 'Status',
  '独立IP': 'Unique IPs',
  '首次发现': 'First Seen',
  '全部': 'All',
  '查询': 'Search',
  '操作': 'Actions',
  '取消': 'Cancel',
  '协议扫描模拟器与探针观测平台': 'Protocol Scan Simulator and Probe Observatory',
  '协议靶场与探针观测': 'Protocol probe observatory',
  '态势总览': 'Overview',
  '探针聚类库': 'Probe Library',
  '测试批次与覆盖率': 'Test Runs & Coverage',
  '会话检索与回放': 'Sessions & Replay',
  '实时事件流': 'Live Events',
  '场景与服务编排': 'Scenarios & Services',
  '打标规则与设置': 'Rules & Settings',
  '显示偏好': 'Display preferences',
  '深色': 'Dark',
  '浅色': 'Light',
  '服务数：{count}': 'Services: {count}',
  '场景：{scenario}': 'Scenario: {scenario}',
  '版本 {version}': 'Version {version}',
  '退出登录': 'Sign Out',
  '需要认证，正在跳转登录页': 'Authentication required. Redirecting to sign in.',
  '（空）': '(empty)',
}

export function t(label: string, values?: Record<string, string | number>): string {
  const message = locale.value === 'en' && Object.hasOwn(english, label) ? english[label] : label
  return values ? message.replace(/\{(\w+)\}/g, (placeholder, key) => String(values[key] ?? placeholder)) : message
}

export function toggleLocale() {
  locale.value = locale.value === 'en' ? 'zh-CN' : 'en'
  writePreference(languageKey, locale.value)
}

export function toggleTheme() {
  theme.value = theme.value === 'dark' ? 'light' : 'dark'
  writePreference(themeKey, theme.value)
}

watchEffect(() => {
  document.documentElement.lang = locale.value
  document.documentElement.classList.toggle('dark', theme.value === 'dark')
  document.title = `ProtoSim — ${t('协议扫描模拟器与探针观测平台')}`
})
