<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">态势总览</h2>
      <div style="display: flex; gap: 10px; align-items: center">
        <el-radio-group v-model="windowVal" size="small" @change="load">
          <el-radio-button value="1h">近 1 小时</el-radio-button>
          <el-radio-button value="24h">近 24 小时</el-radio-button>
          <el-radio-button value="7d">近 7 天</el-radio-button>
        </el-radio-group>
        <el-button size="small" type="primary" :loading="loading" @click="load">刷新</el-button>
      </div>
    </div>

    <el-row :gutter="14" style="margin-bottom: 16px">
      <el-col :span="4" v-for="card in kpiCards" :key="card.label">
        <el-card shadow="never" class="kpi-card">
          <div class="kpi-label">{{ card.label }}</div>
          <div class="kpi-value" :style="{ color: card.color }">{{ card.value }}</div>
          <div class="kpi-sub">{{ card.sub }}</div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="16" style="margin-bottom: 16px">
      <el-col :span="16">
        <el-card shadow="never">
          <template #header><span>探测会话与事件趋势</span></template>
          <div ref="trendChartEl" style="height: 270px"></div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card shadow="never">
          <template #header><span>扫描器身份分布</span></template>
          <div ref="scannerChartEl" style="height: 270px"></div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="16" style="margin-bottom: 16px">
      <el-col :span="12">
        <el-card shadow="never">
          <template #header><span>协议命中 Top 12</span></template>
          <div ref="protoChartEl" style="height: 260px"></div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="never">
          <template #header><span>来源 IP Top 10</span></template>
          <el-table :data="stats?.top_source_ips || []" size="small" height="260" stripe>
            <el-table-column prop="name" label="来源 IP" class-name="mono" />
            <el-table-column prop="count" label="会话数" width="110" align="right" />
          </el-table>
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>最新发现的未归档探针 (status = new)</span>
          <el-button link type="primary" @click="$emit('navigate', 'probes')">前往探针库 →</el-button>
        </div>
      </template>
      <el-table :data="stats?.recent_new_probes || []" size="small" stripe>
        <el-table-column prop="protocol" label="协议" width="120">
          <template #default="{ row }"><el-tag size="small">{{ row.protocol }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="port" label="端口" width="80" />
        <el-table-column label="指纹" width="130">
          <template #default="{ row }"><span class="mono">{{ row.hash?.slice(0, 12) }}</span></template>
        </el-table-column>
        <el-table-column prop="hit_count" label="命中" width="75" align="right" />
        <el-table-column prop="unique_ips" label="独立IP" width="80" align="right" />
        <el-table-column label="扫描器标签" width="150">
          <template #default="{ row }">
            <el-tag v-for="t in row.scanner_tags || []" :key="t" size="small" type="info" style="margin-right: 4px">{{ t }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="首包预览 (ASCII)" show-overflow-tooltip>
          <template #default="{ row }"><span class="mono">{{ row.sample_ascii || '(empty)' }}</span></template>
        </el-table-column>
        <el-table-column label="首次发现" width="170">
          <template #default="{ row }">{{ formatTime(row.first_seen) }}</template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue'
import * as echarts from 'echarts'
import { api, formatTime, formatBytes } from '../api'

defineEmits(['navigate'])

const windowVal = ref('24h')
const loading = ref(false)
const stats = ref<any>(null)

const trendChartEl = ref<HTMLElement>()
const scannerChartEl = ref<HTMLElement>()
const protoChartEl = ref<HTMLElement>()
let trendChart: echarts.ECharts | null = null
let scannerChart: echarts.ECharts | null = null
let protoChart: echarts.ECharts | null = null

const kpiCards = computed(() => [
  { label: '探测会话', value: stats.value?.total_sessions ?? 0, sub: `时间窗 ${windowVal.value}`, color: '#0284c7' },
  { label: '协议事件', value: stats.value?.total_events ?? 0, sub: '全量记录', color: '#2563eb' },
  { label: '唯一探针', value: stats.value?.unique_probes ?? 0, sub: `新发现 ${stats.value?.new_probes ?? 0}`, color: '#7c3aed' },
  { label: '捕获凭证', value: stats.value?.total_credentials ?? 0, sub: '认证尝试', color: '#d97706' },
  { label: '独立来源 IP', value: stats.value?.unique_ips ?? 0, sub: `解析异常 ${stats.value?.parse_error_count ?? 0}`, color: '#059669' },
  { label: 'SQLite 存储', value: formatBytes(stats.value?.db_size_bytes), sub: 'WAL 模式', color: '#475569' },
])

function renderCharts() {
  if (!stats.value) return
  if (trendChartEl.value) {
    trendChart = trendChart || echarts.init(trendChartEl.value)
    const tl = stats.value.timeline || []
    trendChart.setOption({
      tooltip: { trigger: 'axis' },
      legend: { data: ['会话数', '事件数'] },
      grid: { left: 45, right: 20, top: 32, bottom: 28 },
      xAxis: { type: 'category', data: tl.map((x: any) => x.bucket) },
      yAxis: { type: 'value' },
      series: [
        { name: '会话数', type: 'line', smooth: true, areaStyle: { opacity: 0.15 }, data: tl.map((x: any) => x.sessions) },
        { name: '事件数', type: 'line', smooth: true, data: tl.map((x: any) => x.events) },
      ],
    })
  }
  if (scannerChartEl.value) {
    scannerChart = scannerChart || echarts.init(scannerChartEl.value)
    const sc = stats.value.top_scanners || []
    scannerChart.setOption({
      tooltip: { trigger: 'item' },
      series: [
        {
          type: 'pie',
          radius: ['42%', '70%'],
          data: sc.map((x: any) => ({ name: x.name, value: x.count })),
        },
      ],
    })
  }
  if (protoChartEl.value) {
    protoChart = protoChart || echarts.init(protoChartEl.value)
    const pr = (stats.value.top_protocols || []).slice().reverse()
    protoChart.setOption({
      tooltip: { trigger: 'axis' },
      grid: { left: 90, right: 24, top: 10, bottom: 24 },
      xAxis: { type: 'value' },
      yAxis: { type: 'category', data: pr.map((x: any) => x.name) },
      series: [{ type: 'bar', data: pr.map((x: any) => x.count), itemStyle: { color: '#0284c7', borderRadius: [0, 4, 4, 0] } }],
    })
  }
}

async function load() {
  loading.value = true
  try {
    stats.value = await api.overview(windowVal.value)
    await nextTick()
    renderCharts()
  } finally {
    loading.value = false
  }
}

function onResize() {
  trendChart?.resize()
  scannerChart?.resize()
  protoChart?.resize()
}

onMounted(() => {
  load()
  window.addEventListener('resize', onResize)
})

onUnmounted(() => {
  window.removeEventListener('resize', onResize)
  trendChart?.dispose()
  scannerChart?.dispose()
  protoChart?.dispose()
})
</script>

<style scoped>
.kpi-card { text-align: left; }
.kpi-label { font-size: 12px; color: #64748b; }
.kpi-value { font-size: 24px; font-weight: 700; margin: 4px 0; }
.kpi-sub { font-size: 11px; color: #94a3b8; }
</style>
