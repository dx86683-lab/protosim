<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">{{ t('场景与服务编排') }}</h2>
      <div style="display: flex; gap: 8px">
        <el-button type="primary" size="small" @click="addDialog = true">{{ t('+ 新增监听服务') }}</el-button>
        <el-button size="small" @click="loadAll">{{ t('刷新') }}</el-button>
      </div>
    </div>

    <el-row :gutter="14" style="margin-bottom: 16px">
      <el-col v-for="sc in localizedScenarios" :key="sc.id" :span="6">
        <el-card shadow="never" :class="{ 'active-scenario': activeScenario === sc.id }">
          <div style="font-weight: 700; font-size: 14px; margin-bottom: 6px">{{ sc.name }}</div>
          <div class="scenario-description">{{ sc.description }}</div>
          <div style="display: flex; justify-content: space-between; align-items: center">
            <el-tag size="small" type="info">{{ sc.mode }}</el-tag>
            <el-button size="small" :type="activeScenario === sc.id ? 'success' : 'primary'" @click="applyScenario(sc.id)">
              {{ activeScenario === sc.id ? t('当前运行') : t('一键切换') }}
            </el-button>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never" style="margin-bottom: 16px">
      <template #header><span>{{ t('Catch-All 未知探针兜底端口') }}</span></template>
      <el-form :inline="true" size="small">
        <el-form-item :label="t('启用')">
          <el-switch v-model="catchAll.enabled" />
        </el-form-item>
        <el-form-item :label="t('TCP 端口 (逗号分隔)')">
          <el-input v-model="catchTcpText" placeholder="9999,10000" style="width: 200px" />
        </el-form-item>
        <el-form-item :label="t('UDP 端口 (逗号分隔)')">
          <el-input v-model="catchUdpText" placeholder="9999" style="width: 180px" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="saveCatchAll">{{ t('应用 Catch-All') }}</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-tabs v-model="tab">
      <el-tab-pane :label="t('运行中服务 ({count})', { count: services.length })" name="services">
        <el-card shadow="never">
          <el-input v-model="svcSearch" size="small" :placeholder="t('按协议名或端口搜索运行中服务')" clearable class="service-search" />
          <el-table :data="filteredServices" size="small" stripe>
            <el-table-column prop="protocol" :label="t('协议')" width="140">
              <template #default="{ row }"><el-tag size="small">{{ row.protocol }}</el-tag></template>
            </el-table-column>
            <el-table-column prop="transport" :label="t('传输')" width="90" />
            <el-table-column prop="ip" :label="t('绑定 IP')" width="140" class-name="mono" />
            <el-table-column prop="port" :label="t('端口')" width="90" class-name="mono" />
            <el-table-column :label="t('启动时间')" width="170">
              <template #default="{ row }">{{ formatTime(row.started_at) }}</template>
            </el-table-column>
            <el-table-column :label="t('操作')" width="90">
              <template #default="{ row }">
                <el-button link type="danger" size="small" @click="stopService(row.id)">{{ t('停止') }}</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-tab-pane>

      <el-tab-pane :label="t('已注册协议目录 ({count})', { count: protocols.length })" name="protocols">
        <el-card shadow="never">
          <el-input v-model="protoSearch" size="small" :placeholder="t('按协议名或端口搜索已注册协议')" clearable class="service-search" />
          <el-table :data="filteredProtocols" size="small" stripe>
            <el-table-column prop="name" :label="t('协议名')" width="170" class-name="mono" />
            <el-table-column prop="transport" :label="t('传输层')" width="100" />
            <el-table-column prop="default_port" :label="t('默认端口')" width="100" class-name="mono" />
            <el-table-column :label="t('支持参数')">
              <template #default="{ row }">
                <span class="mono" style="font-size: 12px">{{ Object.keys(row.params || {}).join(', ') || '-' }}</span>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="addDialog" :title="t('动态新增监听服务')" width="420px">
      <el-form label-width="80px" size="small">
        <el-form-item :label="t('协议')">
          <el-select v-model="newSvc.protocol" filterable style="width: 100%" @change="onProtoChange">
            <el-option v-for="p in protocols" :key="p.name" :label="`${p.name} (${p.default_port})`" :value="p.name" />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('绑定 IP')">
          <el-input v-model="newSvc.ip" placeholder="0.0.0.0" />
        </el-form-item>
        <el-form-item :label="t('端口')">
          <el-input-number v-model="newSvc.port" :min="1" :max="65535" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="addDialog = false">{{ t('取消') }}</el-button>
        <el-button type="primary" @click="addService">{{ t('启动服务') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { api, formatTime } from '../api'
import { locale, t } from '../i18n'

interface Scenario {
  id: string
  name: string
  description: string
  mode: string
}

const chineseScenarios: Record<string, Pick<Scenario, 'name' | 'description'>> = {
  'all-standard': {
    name: '全部 159 种协议（标准端口）',
    description: '在标准端口监听全部 159 种通过 RFC 验证的协议。安全模式下，SSH 使用 2222 端口。',
  },
  'high-ports-obfuscated': {
    name: '全部 159 种协议（非标准高端口）',
    description: '将全部 159 种协议移至 20001–20159 端口，测试不依赖端口的协议识别能力。',
  },
  'core-20-quick': {
    name: '核心 20 种协议（快速实验）',
    description: '涵盖 20 种常用的 Web、远程访问、数据库和工控协议，用于快速迭代扫描器。',
  },
  'virtual-multi-ip-gvisor': {
    name: '虚拟多 IP 子网（gVisor）',
    description: '使用三台虚拟主机（Web、数据库、工控）模拟 gVisor 自定义子网。',
  },
}

const emit = defineEmits(['changed'])
const tab = ref('services')
const scenarios = ref<Scenario[]>([])
const activeScenario = ref('')
const services = ref<any[]>([])
const protocols = ref<any[]>([])
const svcSearch = ref('')
const protoSearch = ref('')

const localizedScenarios = computed(() => {
  if (locale.value !== 'zh-CN') return scenarios.value
  return scenarios.value.map((scenario) => ({ ...scenario, ...chineseScenarios[scenario.id] }))
})

const filteredServices = computed(() => {
  const q = svcSearch.value.trim().toLowerCase()
  if (!q) return services.value
  return services.value.filter((s) => s.protocol.toLowerCase().includes(q) || String(s.port).includes(q))
})

const filteredProtocols = computed(() => {
  const q = protoSearch.value.trim().toLowerCase()
  if (!q) return protocols.value
  return protocols.value.filter((p) => p.name.toLowerCase().includes(q) || String(p.default_port).includes(q))
})
const catchAll = ref({ enabled: false, tcp_ports: [] as number[], udp_ports: [] as number[] })
const catchTcpText = ref('')
const catchUdpText = ref('')

const addDialog = ref(false)
const newSvc = ref({ protocol: 'http', ip: '0.0.0.0', port: 8080 })

function parsePortList(txt: string): number[] {
  return txt
    .split(',')
    .map((s) => parseInt(s.trim(), 10))
    .filter((n) => !isNaN(n) && n > 0 && n <= 65535)
}

async function loadAll() {
  const [scRes, svcRes, pRes] = await Promise.all([api.scenarios(), api.services(), api.protocols()])
  scenarios.value = scRes.builtins || []
  activeScenario.value = scRes.active || ''
  services.value = svcRes.items || []
  catchAll.value = svcRes.catch_all || { enabled: false, tcp_ports: [], udp_ports: [] }
  catchTcpText.value = (catchAll.value.tcp_ports || []).join(',')
  catchUdpText.value = (catchAll.value.udp_ports || []).join(',')
  protocols.value = pRes.items || []
}

async function applyScenario(id: string) {
  const res = await api.applyScenario(id)
  ElMessage.success(t('场景 {id} 已切换，启动 {count} 个服务', { id, count: res.started }))
  await loadAll()
  emit('changed')
}

async function stopService(id: string) {
  await api.stopService(id)
  ElMessage.success(t('服务已停止'))
  await loadAll()
  emit('changed')
}

function onProtoChange(name: string) {
  const found = protocols.value.find((p) => p.name === name)
  if (found) newSvc.value.port = found.default_port
}

async function addService() {
  await api.addService(newSvc.value)
  addDialog.value = false
  ElMessage.success(t('服务已启动'))
  await loadAll()
  emit('changed')
}

async function saveCatchAll() {
  await api.updateCatchAll({
    enabled: catchAll.value.enabled,
    tcp_ports: parsePortList(catchTcpText.value),
    udp_ports: parsePortList(catchUdpText.value),
  })
  ElMessage.success(t('Catch-All 配置已生效'))
  await loadAll()
}

onMounted(loadAll)
</script>

<style scoped>
.active-scenario {
  border-color: var(--el-color-primary);
  background: var(--el-color-primary-light-9);
}
.scenario-description {
  font-size: 12px;
  color: var(--el-text-color-regular);
  min-height: 36px;
  margin-bottom: 10px;
}
.service-search {
  width: 320px;
  max-width: 100%;
  margin-bottom: 10px;
}
</style>
