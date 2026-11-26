<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">{{ t('测试批次与全协议覆盖率') }}</h2>
      <div style="display: flex; gap: 8px">
        <el-button type="primary" size="small" @click="createDialog = true">{{ t('+ 开始新测试批次') }}</el-button>
        <el-button size="small" @click="load">{{ t('刷新') }}</el-button>
      </div>
    </div>

    <el-row :gutter="16">
      <el-col :span="9">
        <el-card shadow="never">
          <template #header><span>{{ t('历史测试批次') }}</span></template>
          <el-table :data="runs" size="small" highlight-current-row @current-change="selectRun">
            <el-table-column prop="name" :label="t('批次名称')" show-overflow-tooltip />
            <el-table-column :label="t('状态')" width="95">
              <template #default="{ row }">
                <el-tag size="small" :type="row.ended_at ? 'info' : 'success'">{{ t(row.ended_at ? '已结束' : '进行中') }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column :label="t('操作')" width="76">
              <template #default="{ row }">
                <el-button v-if="!row.ended_at" link type="danger" size="small" @click.stop="stopRun(row.id)">{{ t('结束') }}</el-button>
              </template>
            </el-table-column>
          </el-table>

          <div style="margin-top: 16px; border-top: 1px solid var(--el-border-color); padding-top: 12px">
            <div style="font-size: 13px; font-weight: 600; margin-bottom: 8px">{{ t('双批次覆盖率对比 (Diff)') }}</div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap">
              <el-select v-model="diffBase" size="small" :placeholder="t('基准批次')" style="width: 140px">
                <el-option v-for="r in runs" :key="r.id" :label="r.name" :value="r.id" />
              </el-select>
              <el-select v-model="diffTarget" size="small" :placeholder="t('目标批次')" style="width: 140px">
                <el-option v-for="r in runs" :key="r.id" :label="r.name" :value="r.id" />
              </el-select>
              <el-button size="small" type="primary" :disabled="!diffBase || !diffTarget" @click="runDiff">{{ t('对比') }}</el-button>
            </div>
          </div>
        </el-card>
      </el-col>

      <el-col :span="15">
        <el-card shadow="never" v-if="diffResult" style="margin-bottom: 14px">
          <template #header>
            <div style="display: flex; justify-content: space-between">
              <span>{{ t('批次对比: {base} → {target}', { base: diffResult.base_run.name, target: diffResult.target_run.name }) }}</span>
              <el-button link size="small" @click="diffResult = null">{{ t('关闭对比') }}</el-button>
            </div>
          </template>
          <div style="display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 10px; font-size: 13px">
            <span>{{ t('基准覆盖率: {coverage}%', { coverage: diffResult.base_coverage_pct.toFixed(1) }) }}</span>
            <span>{{ t('目标覆盖率: {coverage}%', { coverage: diffResult.target_coverage_pct.toFixed(1) }) }}</span>
            <span style="color: var(--el-color-success-dark-2)">{{ t('新增命中: {protocols}', { protocols: diffResult.newly_hit.join(', ') || t('无') }) }}</span>
            <span style="color: var(--el-color-danger-dark-2)">{{ t('退化缺失: {protocols}', { protocols: diffResult.regressed.join(', ') || t('无') }) }}</span>
          </div>
        </el-card>

        <el-card shadow="never" v-if="coverage">
          <template #header>
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px">
              <span>{{ t('{name} — 交互命中 {coverage}%（含 Banner {effectiveCoverage}%）', {
                name: coverage.run.name,
                coverage: coverage.coverage_pct.toFixed(1),
                effectiveCoverage: (coverage.effective_coverage_pct ?? coverage.coverage_pct).toFixed(1),
              }) }}</span>
              <div style="display: flex; gap: 6px; flex-wrap: wrap">
                <el-tag type="success" size="small">{{ t('协议交互 {count}', { count: coverage.hit_count }) }}</el-tag>
                <el-tag type="primary" size="small">{{ t('仅 Banner {count}', { count: coverage.banner_only_count || 0 }) }}</el-tag>
                <el-tag type="warning" size="small">{{ t('空连接/探活 {count}', { count: coverage.connect_only_count || 0 }) }}</el-tag>
                <el-tag type="danger" size="small">{{ t('解析异常 {count}', { count: coverage.error_only_count }) }}</el-tag>
                <el-tag type="info" size="small">{{ t('未命中 {count}', { count: coverage.missed_count }) }}</el-tag>
              </div>
            </div>
          </template>

          <div style="display: flex; gap: 8px; margin-bottom: 10px; flex-wrap: wrap">
            <el-input v-model="protoSearch" size="small" :placeholder="t('筛选协议名')" clearable style="width: 170px" />
            <el-radio-group v-model="statusFilter" size="small">
              <el-radio-button value="all">{{ t('全部 ({count})', { count: coverage.total_protocols }) }}</el-radio-button>
              <el-radio-button value="hit">{{ t('协议交互 ({count})', { count: coverage.hit_count }) }}</el-radio-button>
              <el-radio-button value="banner_only">{{ t('仅 Banner ({count})', { count: coverage.banner_only_count || 0 }) }}</el-radio-button>
              <el-radio-button value="connect_only">{{ t('空连接 ({count})', { count: coverage.connect_only_count || 0 }) }}</el-radio-button>
              <el-radio-button value="parse_error">{{ t('异常 ({count})', { count: coverage.error_only_count }) }}</el-radio-button>
              <el-radio-button value="missed">{{ t('未命中 ({count})', { count: coverage.missed_count }) }}</el-radio-button>
            </el-radio-group>
          </div>

          <div class="matrix-grid">
            <div v-for="p in filteredProtocols" :key="p.protocol" class="matrix-cell" :class="'cell-' + p.status">
              <div class="cell-name">{{ p.protocol }}</div>
              <div class="cell-meta">{{ t('{sessions} 会话 · {events} 事件 · {latency}ms', { sessions: p.session_count, events: p.event_count, latency: p.avg_latency_ms.toFixed(0) }) }}</div>
            </div>
          </div>
        </el-card>
        <el-empty v-else :description="t('请选择或创建一个测试批次查看全协议覆盖矩阵')" />
      </el-col>
    </el-row>

    <el-dialog v-model="createDialog" :title="t('开始新测试批次')" width="420px">
      <el-form label-width="auto" size="small">
        <el-form-item :label="t('批次名称')">
          <el-input v-model="newRun.name" :placeholder="t('例如 internal-scanner-v2.4 全量回归')" />
        </el-form-item>
        <el-form-item :label="t('备注')">
          <el-input v-model="newRun.notes" type="textarea" :rows="2" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createDialog = false">{{ t('取消') }}</el-button>
        <el-button type="primary" @click="createRun">{{ t('立即开始') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { t } from '../i18n'

const runs = ref<any[]>([])
const coverage = ref<any>(null)
const protoSearch = ref('')
const statusFilter = ref('all')

const filteredProtocols = computed(() => {
  const list = coverage.value?.protocols || []
  const q = protoSearch.value.trim().toLowerCase()
  return list.filter((p: any) => {
    if (statusFilter.value !== 'all' && p.status !== statusFilter.value) return false
    if (q && !p.protocol.toLowerCase().includes(q)) return false
    return true
  })
})
const createDialog = ref(false)
const newRun = ref({ name: '', notes: '' })
const diffBase = ref('')
const diffTarget = ref('')
const diffResult = ref<any>(null)

async function load() {
  const res = await api.testRuns()
  runs.value = res.items || []
  if (runs.value.length > 0 && !coverage.value) {
    selectRun(runs.value[0])
  }
}

async function selectRun(row: any) {
  if (!row) return
  coverage.value = await api.testRunCoverage(row.id)
}

async function createRun() {
  const created = await api.createTestRun(newRun.value)
  createDialog.value = false
  newRun.value = { name: '', notes: '' }
  ElMessage.success(t('测试批次已开始'))
  await load()
  await selectRun(created)
}

async function stopRun(id: string) {
  await api.stopTestRun(id)
  ElMessage.success(t('测试批次已结束'))
  await load()
  if (coverage.value?.run?.id === id) {
    coverage.value = await api.testRunCoverage(id)
  }
}

async function runDiff() {
  diffResult.value = await api.testRunDiff(diffBase.value, diffTarget.value)
}

onMounted(load)
</script>

<style scoped>
.matrix-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(126px, 1fr));
  gap: 8px;
}
.matrix-cell {
  border-radius: 6px;
  padding: 8px 10px;
  border: 1px solid var(--el-border-color);
}
.cell-hit {
  background: var(--el-color-success-light-9);
  border-color: var(--el-color-success-light-5);
  color: var(--el-color-success-dark-2);
}
.cell-banner_only {
  background: var(--el-color-primary-light-9);
  border-color: var(--el-color-primary-light-5);
  color: var(--el-color-primary-dark-2);
}
.cell-connect_only {
  background: var(--el-color-warning-light-9);
  border-color: var(--el-color-warning-light-5);
  color: var(--el-color-warning-dark-2);
}
.cell-parse_error {
  background: var(--el-color-danger-light-9);
  border-color: var(--el-color-danger-light-5);
  color: var(--el-color-danger-dark-2);
}
.cell-missed {
  background: var(--el-fill-color-light);
  color: var(--el-text-color-secondary);
}
.cell-name {
  font-weight: 600;
  font-size: 13px;
}
.cell-meta {
  font-size: 11px;
  margin-top: 2px;
}
</style>
