<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">{{ t('会话检索与回放') }}</h2>
      <el-button type="primary" size="small" :loading="loading" @click="load">{{ t('刷新') }}</el-button>
    </div>

    <el-card shadow="never" style="margin-bottom: 14px">
      <el-form :inline="true" size="small">
        <el-form-item :label="t('协议')">
          <el-input v-model="filter.protocol" placeholder="http / ssh / mysql" clearable style="width: 140px" />
        </el-form-item>
        <el-form-item :label="t('来源 IP')">
          <el-input v-model="filter.remote_ip" placeholder="192.168." clearable style="width: 140px" />
        </el-form-item>
        <el-form-item :label="t('扫描器')">
          <el-input v-model="filter.scanner_tag" placeholder="nmap / unknown" clearable style="width: 130px" />
        </el-form-item>
        <el-form-item :label="t('解析')">
          <el-select v-model="filter.parse" clearable :placeholder="t('全部')" style="width: 110px">
            <el-option :label="t('正常')" value="ok" />
            <el-option :label="t('解析异常')" value="error" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="page = 1; load()">{{ t('查询') }}</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never">
      <el-table :data="items" size="small" stripe v-loading="loading" @row-click="openDetail" style="cursor: pointer">
        <el-table-column :label="t('时间')" width="165">
          <template #default="{ row }">{{ formatTime(row.started_at) }}</template>
        </el-table-column>
        <el-table-column prop="protocol" :label="t('协议')" width="110">
          <template #default="{ row }"><el-tag size="small">{{ row.protocol }}</el-tag></template>
        </el-table-column>
        <el-table-column :label="t('来源')" width="165">
          <template #default="{ row }"><span class="mono">{{ row.remote_ip }}:{{ row.remote_port }}</span></template>
        </el-table-column>
        <el-table-column :label="t('目标端口')" width="120">
          <template #default="{ row }">{{ row.transport }}/{{ row.local_port }}</template>
        </el-table-column>
        <el-table-column prop="scanner_tag" :label="t('扫描器')" width="110">
          <template #default="{ row }"><el-tag size="small" type="info">{{ row.scanner_tag }}</el-tag></template>
        </el-table-column>
        <el-table-column :label="t('流量 (In / Out)')" width="135">
          <template #default="{ row }">{{ formatBytes(row.bytes_in) }} / {{ formatBytes(row.bytes_out) }}</template>
        </el-table-column>
        <el-table-column prop="duration_ms" :label="t('耗时(ms)')" width="115" align="right" />
        <el-table-column prop="event_count" :label="t('事件数')" width="75" align="right" />
        <el-table-column :label="t('状态')" width="130">
          <template #default="{ row }">
            <el-tag size="small" :type="sessionStatusTag(row)">{{ sessionStatusLabel(row) }}</el-tag>
          </template>
        </el-table-column>
      </el-table>

      <div style="margin-top: 12px; display: flex; justify-content: flex-end">
        <el-pagination v-model:current-page="page" :page-size="50" :total="total" layout="total, prev, pager, next" @current-change="load" />
      </div>
    </el-card>

    <el-drawer v-model="drawerOpen" :title="t('会话完整时间线与报文回放')" size="58%">
      <div v-if="detail">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px">
          <div>
            <el-tag>{{ detail.session.protocol }}</el-tag>
            <span class="mono" style="margin-left: 8px">{{ detail.session.remote_ip }}:{{ detail.session.remote_port }} → :{{ detail.session.local_port }}</span>
          </div>
          <a :href="api.sessionPcapUrl(detail.session.id)" target="_blank">
            <el-button type="primary" size="small">{{ t('下载 .pcap') }}</el-button>
          </a>
        </div>

        <el-descriptions :column="2" border size="small" style="margin-bottom: 14px">
          <el-descriptions-item :label="t('会话 ID')"><span class="mono">{{ detail.session.id }}</span></el-descriptions-item>
          <el-descriptions-item :label="t('扫描器标签')">{{ detail.session.scanner_tag }}</el-descriptions-item>
          <el-descriptions-item :label="t('JA3 指纹')"><span class="mono">{{ detail.session.ja3 || '-' }}</span></el-descriptions-item>
          <el-descriptions-item :label="t('探针指纹')"><span class="mono">{{ detail.session.probe_hash?.slice(0, 16) || '-' }}</span></el-descriptions-item>
        </el-descriptions>

        <el-tabs v-model="detailTab">
          <el-tab-pane :label="t('事件时间线 ({count})', { count: detail.events.length })" name="events">
            <el-timeline style="padding-left: 8px">
              <el-timeline-item v-for="ev in detail.events" :key="ev.id" :timestamp="formatTime(ev.ts)" placement="top">
                <el-tag size="small" style="margin-right: 6px">{{ eventKindLabel(ev.kind) }}</el-tag>
                <b>{{ ev.summary }}</b>
                <pre v-if="ev.detail_json" class="hexdump" style="margin-top: 6px; max-height: 160px">{{ ev.detail_json }}</pre>
              </el-timeline-item>
            </el-timeline>
          </el-tab-pane>

          <el-tab-pane :label="t('原始收发报文 ({count})', { count: detail.payloads.length })" name="payloads">
            <div v-for="pl in detail.payloads" :key="pl.id" style="margin-bottom: 12px">
              <div style="font-size: 12px; margin-bottom: 4px">
                <el-tag size="small" :type="pl.direction === 'in' ? 'warning' : 'success'">{{ t(pl.direction === 'in' ? '客户端 → 服务端' : '服务端 → 客户端') }}</el-tag>
                <span style="margin-left: 8px; color: var(--el-text-color-secondary)">#{{ pl.seq }} · {{ formatTime(pl.ts) }}</span>
              </div>
              <pre class="hexdump">{{ formatHexDump(pl.hex) }}</pre>
            </div>
            <el-empty v-if="detail.payloads.length === 0" :description="t('无载荷记录')" />
          </el-tab-pane>

          <el-tab-pane :label="t('认证凭证 ({count})', { count: detail.credentials.length })" name="creds">
            <el-table :data="detail.credentials" size="small" stripe>
              <el-table-column prop="username" :label="t('用户名')" class-name="mono" />
              <el-table-column prop="secret" :label="t('口令 / Token')" class-name="mono" />
              <el-table-column prop="mechanism" :label="t('方式')" />
              <el-table-column :label="t('结果')" width="80">
                <template #default="{ row }">{{ t(row.accepted ? '允许' : '拒绝') }}</template>
              </el-table-column>
            </el-table>
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api, formatTime, formatBytes, formatHexDump } from '../api'
import { t } from '../i18n'
import { eventLabels } from '../messages-monitoring'

const loading = ref(false)
const items = ref<any[]>([])
const total = ref(0)
const page = ref(1)
const filter = ref({ protocol: '', remote_ip: '', scanner_tag: '', parse: '' })

const drawerOpen = ref(false)
const detail = ref<any>(null)
const detailTab = ref('events')

const sessionStatuses = new Map([
  ['open', '已打开'],
  ['closed', '已关闭'],
  ['timeout', '超时'],
])

async function load() {
  loading.value = true
  try {
    const res = await api.sessions({ ...filter.value, page: page.value, limit: 50 })
    items.value = res.items || []
    total.value = res.total || 0
  } finally {
    loading.value = false
  }
}

async function openDetail(row: any) {
  detail.value = await api.sessionDetail(row.id)
  detailTab.value = 'events'
  drawerOpen.value = true
}

function sessionStatusTag(row: any) {
  if (!row.parse_ok || row.status === 'parse_error') return 'danger'
  if (row.status === 'connect_only' || (row.bytes_in === 0 && row.bytes_out === 0)) return 'warning'
  if (row.status === 'banner_only' || (row.bytes_in === 0 && row.bytes_out > 0)) return 'primary'
  return 'success'
}

function sessionStatusLabel(row: any) {
  if (!row.parse_ok || row.status === 'parse_error') return t('解析异常')
  if (row.status === 'connect_only' || (row.bytes_in === 0 && row.bytes_out === 0)) return t('空连接')
  if (row.status === 'banner_only' || (row.bytes_in === 0 && row.bytes_out > 0)) return t('仅 Banner')
  const status = row.status || 'closed'
  const label = sessionStatuses.get(status)
  return label ? t(label) : status
}

function eventKindLabel(kind: string) {
  const label = eventLabels.get(kind)
  return label ? t(label) : kind
}

onMounted(load)
</script>
