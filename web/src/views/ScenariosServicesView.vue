<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">场景与服务编排</h2>
      <div style="display: flex; gap: 8px">
        <el-button type="primary" size="small" @click="addDialog = true">+ 新增监听服务</el-button>
        <el-button size="small" @click="loadAll">刷新</el-button>
      </div>
    </div>

    <el-row :gutter="14" style="margin-bottom: 16px">
      <el-col :span="6" v-for="sc in scenarios" :key="sc.id">
        <el-card shadow="never" :class="{ 'active-scenario': activeScenario === sc.id }">
          <div style="font-weight: 700; font-size: 14px; margin-bottom: 6px">{{ sc.name }}</div>
          <div style="font-size: 12px; color: #64748b; min-height: 36px; margin-bottom: 10px">{{ sc.description }}</div>
          <div style="display: flex; justify-content: space-between; align-items: center">
            <el-tag size="small" type="info">{{ sc.mode }}</el-tag>
            <el-button size="small" :type="activeScenario === sc.id ? 'success' : 'primary'" @click="applyScenario(sc.id)">
              {{ activeScenario === sc.id ? '当前运行' : '一键切换' }}
            </el-button>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never" style="margin-bottom: 16px">
      <template #header><span>Catch-All 未知探针兜底端口</span></template>
      <el-form :inline="true" size="small">
        <el-form-item label="启用">
          <el-switch v-model="catchAll.enabled" />
        </el-form-item>
        <el-form-item label="TCP 端口 (逗号分隔)">
          <el-input v-model="catchTcpText" placeholder="9999,10000" style="width: 200px" />
        </el-form-item>
        <el-form-item label="UDP 端口 (逗号分隔)">
          <el-input v-model="catchUdpText" placeholder="9999" style="width: 180px" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="saveCatchAll">应用 Catch-All</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-tabs v-model="tab">
      <el-tab-pane :label="`运行中服务 (${services.length})`" name="services">
        <el-card shadow="never">
          <el-input v-model="svcSearch" size="small" placeholder="按协议名或端口搜索运行中服务" clearable style="width: 240px; margin-bottom: 10px" />
          <el-table :data="filteredServices" size="small" stripe>
            <el-table-column prop="protocol" label="协议" width="140">
              <template #default="{ row }"><el-tag size="small">{{ row.protocol }}</el-tag></template>
            </el-table-column>
            <el-table-column prop="transport" label="传输" width="90" />
            <el-table-column prop="ip" label="绑定 IP" width="140" class-name="mono" />
            <el-table-column prop="port" label="端口" width="90" class-name="mono" />
            <el-table-column label="启动时间" width="170">
              <template #default="{ row }">{{ formatTime(row.started_at) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="90">
              <template #default="{ row }">
                <el-button link type="danger" size="small" @click="stopService(row.id)">停止</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-tab-pane>

      <el-tab-pane :label="`已注册协议目录 (${protocols.length})`" name="protocols">
        <el-card shadow="never">
          <el-input v-model="protoSearch" size="small" placeholder="按协议名或端口搜索已注册协议" clearable style="width: 240px; margin-bottom: 10px" />
          <el-table :data="filteredProtocols" size="small" stripe>
            <el-table-column prop="name" label="协议名" width="170" class-name="mono" />
            <el-table-column prop="transport" label="传输层" width="100" />
            <el-table-column prop="default_port" label="默认端口" width="100" class-name="mono" />
            <el-table-column label="支持参数">
              <template #default="{ row }">
                <span class="mono" style="font-size: 12px">{{ Object.keys(row.params || {}).join(', ') || '-' }}</span>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="addDialog" title="动态新增监听服务" width="420px">
      <el-form label-width="80px" size="small">
        <el-form-item label="协议">
          <el-select v-model="newSvc.protocol" filterable style="width: 100%" @change="onProtoChange">
            <el-option v-for="p in protocols" :key="p.name" :label="`${p.name} (${p.default_port})`" :value="p.name" />
          </el-select>
        </el-form-item>
        <el-form-item label="绑定 IP">
          <el-input v-model="newSvc.ip" placeholder="0.0.0.0" />
        </el-form-item>
        <el-form-item label="端口">
          <el-input-number v-model="newSvc.port" :min="1" :max="65535" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="addDialog = false">取消</el-button>
        <el-button type="primary" @click="addService">启动服务</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { api, formatTime } from '../api'

const emit = defineEmits(['changed'])
const tab = ref('services')
const scenarios = ref<any[]>([])
const activeScenario = ref('')
const services = ref<any[]>([])
const protocols = ref<any[]>([])
const svcSearch = ref('')
const protoSearch = ref('')

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
  ElMessage.success(`场景 ${id} 已切换，启动 ${res.started} 个服务`)
  await loadAll()
  emit('changed')
}

async function stopService(id: string) {
  await api.stopService(id)
  ElMessage.success('服务已停止')
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
  ElMessage.success('服务已启动')
  await loadAll()
  emit('changed')
}

async function saveCatchAll() {
  await api.updateCatchAll({
    enabled: catchAll.value.enabled,
    tcp_ports: parsePortList(catchTcpText.value),
    udp_ports: parsePortList(catchUdpText.value),
  })
  ElMessage.success('Catch-All 配置已生效')
  await loadAll()
}

onMounted(loadAll)
</script>

<style scoped>
.active-scenario {
  border-color: #0284c7;
  background: #f0f9ff;
}
</style>
