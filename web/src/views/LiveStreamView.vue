<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">实时事件流 (SSE)</h2>
      <div style="display: flex; gap: 8px; align-items: center">
        <el-tag :type="connected ? 'success' : 'danger'" size="small">{{ connected ? 'SSE 已连接' : '连接中断' }}</el-tag>
        <el-input v-model="protoFilter" size="small" placeholder="按协议过滤" clearable style="width: 140px" />
        <el-button size="small" :type="paused ? 'warning' : 'default'" @click="paused = !paused">
          {{ paused ? '继续滚动' : '暂停' }}
        </el-button>
        <el-button size="small" @click="loadRecent">加载最近 50 条</el-button>
        <el-button size="small" @click="events = []">清空</el-button>
      </div>
    </div>

    <el-card shadow="never">
      <el-table :data="filteredEvents" size="small" height="72vh" stripe>
        <el-table-column label="时间" width="165">
          <template #default="{ row }">{{ formatTime(row.ts) }}</template>
        </el-table-column>
        <el-table-column label="类型" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="typeTag(row)">{{ row.is_new_probe ? 'NEW PROBE' : row.type }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="protocol" label="协议" width="115">
          <template #default="{ row }"><el-tag size="small" effect="plain">{{ row.protocol }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="remote_ip" label="来源 IP" width="145" class-name="mono" />
        <el-table-column prop="local_port" label="端口" width="75" />
        <el-table-column prop="scanner_tag" label="扫描器" width="110" />
        <el-table-column prop="summary" label="摘要" show-overflow-tooltip />
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { api, formatTime } from '../api'

const connected = ref(false)
const paused = ref(false)
const protoFilter = ref('')
const events = ref<any[]>([])
let es: EventSource | null = null

const filteredEvents = computed(() => {
  const f = protoFilter.value.trim().toLowerCase()
  if (!f) return events.value
  return events.value.filter((e) => (e.protocol || '').toLowerCase().includes(f))
})

function typeTag(row: any) {
  if (row.is_new_probe || row.type === 'new_probe') return 'danger'
  if (row.type === 'credential') return 'warning'
  if (row.type === 'session') return 'success'
  return 'info'
}

async function loadRecent() {
  try {
    const res = await api.events({ limit: 50 })
    const hist = (res.items || []).map((ev: any) => ({
      type: ev.kind || 'event',
      ts: ev.ts,
      protocol: ev.protocol,
      remote_ip: ev.remote_ip,
      local_port: ev.local_port,
      scanner_tag: '-',
      session_id: ev.session_id,
      summary: ev.summary,
    }))
    events.value = hist
  } catch {}
}

function connect() {
  const token = localStorage.getItem('protosim_token')
  const url = token ? `/api/v2/stream?token=${encodeURIComponent(token)}` : '/api/v2/stream'
  es = new EventSource(url)
  es.onopen = () => {
    connected.value = true
  }
  es.onerror = () => {
    connected.value = false
  }
  es.onmessage = (ev) => {
    if (paused.value) return
    try {
      const msg = JSON.parse(ev.data)
      events.value.unshift(msg)
      if (events.value.length > 300) {
        events.value.pop()
      }
    } catch {}
  }
}

onMounted(async () => {
  await loadRecent()
  connect()
})
onUnmounted(() => {
  es?.close()
})
</script>
