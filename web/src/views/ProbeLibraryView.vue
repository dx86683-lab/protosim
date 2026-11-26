<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">{{ t('探针聚类库（永久保留）') }}</h2>
      <el-button type="primary" size="small" :loading="loading" @click="load">{{ t('刷新') }}</el-button>
    </div>

    <el-card shadow="never" style="margin-bottom: 14px">
      <el-form :inline="true" size="small">
        <el-form-item :label="t('协议')">
          <el-input v-model="filter.protocol" :placeholder="t('如 http / ssh / catch_all')" clearable style="width: 160px" />
        </el-form-item>
        <el-form-item :label="t('状态')">
          <el-select v-model="filter.status" clearable :placeholder="t('全部')" style="width: 130px">
            <el-option :label="t('新发现 (new)')" value="new" />
            <el-option :label="t('已知 (known)')" value="known" />
            <el-option :label="t('已吸收 (adopted)')" value="adopted" />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('扫描器')">
          <el-input v-model="filter.scanner_tag" :placeholder="t('如 nmap / zgrab')" clearable style="width: 140px" />
        </el-form-item>
        <el-form-item>
          <el-checkbox v-model="filter.pinned">{{ t('仅收藏') }}</el-checkbox>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="page = 1; load()">{{ t('查询') }}</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never">
      <el-table :data="items" size="small" stripe v-loading="loading" @row-click="openDrawer" style="cursor: pointer">
        <el-table-column width="48" align="center">
          <template #default="{ row }">
            <span @click.stop="togglePin(row)" style="cursor: pointer; font-size: 16px">{{ row.pinned ? '★' : '☆' }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="protocol" :label="t('协议')" width="120">
          <template #default="{ row }"><el-tag size="small">{{ row.protocol }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="port" :label="t('端口')" width="75" />
        <el-table-column :label="t('指纹 (SHA256)')" width="130">
          <template #default="{ row }"><span class="mono">{{ row.hash.slice(0, 12) }}</span></template>
        </el-table-column>
        <el-table-column :label="t('状态')" width="95">
          <template #default="{ row }">
            <el-tag size="small" :type="statusType(row.status)">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="hit_count" :label="t('命中数')" width="75" align="right" />
        <el-table-column prop="unique_ips" :label="t('独立IP')" width="75" align="right" />
        <el-table-column :label="t('扫描器')" width="150">
          <template #default="{ row }">
            <el-tag v-for="tag in row.scanner_tags || []" :key="tag" size="small" type="info" style="margin-right: 4px">{{ tag }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('首包 ASCII 预览')" show-overflow-tooltip>
          <template #default="{ row }"><span class="mono">{{ row.sample_ascii || t('（空）') }}</span></template>
        </el-table-column>
        <el-table-column :label="t('最近命中')" width="165">
          <template #default="{ row }">{{ formatTime(row.last_seen) }}</template>
        </el-table-column>
      </el-table>

      <div style="margin-top: 12px; display: flex; justify-content: flex-end">
        <el-pagination
          v-model:current-page="page"
          :page-size="50"
          :total="total"
          layout="total, prev, pager, next"
          @current-change="load"
        />
      </div>
    </el-card>

    <el-drawer v-model="drawerOpen" :title="t('探针详情与用例导出')" size="52%">
      <div v-if="current">
        <el-descriptions :column="2" border size="small" style="margin-bottom: 14px">
          <el-descriptions-item :label="t('协议 / 端口')">{{ current.protocol }} ({{ current.transport }}:{{ current.port }})</el-descriptions-item>
          <el-descriptions-item :label="t('命中 / 独立IP')">{{ current.hit_count }} / {{ current.unique_ips }}</el-descriptions-item>
          <el-descriptions-item label="SHA256" :span="2"><span class="mono">{{ current.hash }}</span></el-descriptions-item>
          <el-descriptions-item :label="t('首次发现')">{{ formatTime(current.first_seen) }}</el-descriptions-item>
          <el-descriptions-item :label="t('最近命中')">{{ formatTime(current.last_seen) }}</el-descriptions-item>
        </el-descriptions>

        <el-form label-width="auto" size="small" style="margin-bottom: 16px">
          <el-form-item :label="t('归档状态')">
            <el-radio-group v-model="editForm.status">
              <el-radio-button value="new">{{ t('新发现 (new)') }}</el-radio-button>
              <el-radio-button value="known">{{ t('已知 (known)') }}</el-radio-button>
              <el-radio-button value="adopted">{{ t('已吸收 (adopted)') }}</el-radio-button>
            </el-radio-group>
            <el-checkbox v-model="editForm.pinned" style="margin-left: 16px">{{ t('永久收藏样本') }}</el-checkbox>
          </el-form-item>
          <el-form-item :label="t('分析备注')">
            <el-input v-model="editForm.note" type="textarea" :rows="2" :placeholder="t('记录探针特征、是否已合入 internal-scanner 等')" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="saveProbe">{{ t('保存标注') }}</el-button>
          </el-form-item>
        </el-form>

        <h4 style="margin: 12px 0 6px">{{ t('原始首包 Hex + ASCII') }}</h4>
        <pre class="hexdump">{{ formatHexDump(current.sample_hex) }}</pre>

        <div style="margin-top: 16px; display: flex; justify-content: space-between; align-items: center">
          <h4 style="margin: 0">{{ t('一键导出复现代码') }}</h4>
          <el-button-group size="small">
            <el-button @click="loadSnippet('hex')">Hex</el-button>
            <el-button @click="loadSnippet('python')">Python</el-button>
            <el-button @click="loadSnippet('go')">Go</el-button>
            <el-button type="success" @click="copySnippet" :disabled="!snippet">{{ t('复制') }}</el-button>
          </el-button-group>
        </div>
        <pre v-if="snippet" class="hexdump" style="margin-top: 8px">{{ snippet }}</pre>
      </div>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { api, formatTime, formatHexDump } from '../api'
import { t } from '../i18n'

const loading = ref(false)
const items = ref<any[]>([])
const total = ref(0)
const page = ref(1)
const filter = ref({ protocol: '', status: '', scanner_tag: '', pinned: false })

const drawerOpen = ref(false)
const current = ref<any>(null)
const editForm = ref({ status: 'new', note: '', pinned: false })
const snippet = ref('')

function statusType(st: string) {
  if (st === 'adopted') return 'success'
  if (st === 'known') return 'info'
  return 'warning'
}

function statusLabel(status: string) {
  if (status === 'new') return t('新发现')
  if (status === 'known') return t('已知')
  if (status === 'adopted') return t('已吸收')
  return status
}

async function load() {
  loading.value = true
  try {
    const res = await api.probes({ ...filter.value, page: page.value, limit: 50 })
    items.value = res.items || []
    total.value = res.total || 0
  } finally {
    loading.value = false
  }
}

function openDrawer(row: any) {
  current.value = row
  editForm.value = { status: row.status, note: row.note || '', pinned: !!row.pinned }
  snippet.value = ''
  drawerOpen.value = true
}

async function saveProbe() {
  if (!current.value) return
  const updated = await api.updateProbe(current.value.hash, editForm.value)
  current.value = updated
  ElMessage.success(t('已保存标注'))
  load()
}

async function togglePin(row: any) {
  await api.updateProbe(row.hash, { pinned: !row.pinned })
  load()
}

async function loadSnippet(fmt: 'hex' | 'python' | 'go') {
  if (!current.value) return
  const res = await api.exportProbe(current.value.hash, fmt)
  snippet.value = res.snippet || ''
}

async function copySnippet() {
  if (!snippet.value) return
  await navigator.clipboard.writeText(snippet.value)
  ElMessage.success(t('已复制到剪贴板'))
}

onMounted(load)
</script>
