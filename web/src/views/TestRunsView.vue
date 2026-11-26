<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">测试批次与全协议覆盖率</h2>
      <div style="display: flex; gap: 8px">
        <el-button type="primary" size="small" @click="createDialog = true">+ 开始新测试批次</el-button>
        <el-button size="small" @click="load">刷新</el-button>
      </div>
    </div>

    <el-row :gutter="16">
      <el-col :span="9">
        <el-card shadow="never">
          <template #header><span>历史测试批次</span></template>
          <el-table :data="runs" size="small" highlight-current-row @current-change="selectRun">
            <el-table-column prop="name" label="批次名称" show-overflow-tooltip />
            <el-table-column label="状态" width="76">
              <template #default="{ row }">
                <el-tag size="small" :type="row.ended_at ? 'info' : 'success'">{{ row.ended_at ? '已结束' : '进行中' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="76">
              <template #default="{ row }">
                <el-button v-if="!row.ended_at" link type="danger" size="small" @click.stop="stopRun(row.id)">结束</el-button>
              </template>
            </el-table-column>
          </el-table>

          <div style="margin-top: 16px; border-top: 1px solid #e2e8f0; padding-top: 12px">
            <div style="font-size: 13px; font-weight: 600; margin-bottom: 8px">双批次覆盖率对比 (Diff)</div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap">
              <el-select v-model="diffBase" size="small" placeholder="基准批次" style="width: 140px">
                <el-option v-for="r in runs" :key="r.id" :label="r.name" :value="r.id" />
              </el-select>
              <el-select v-model="diffTarget" size="small" placeholder="目标批次" style="width: 140px">
                <el-option v-for="r in runs" :key="r.id" :label="r.name" :value="r.id" />
              </el-select>
              <el-button size="small" type="primary" :disabled="!diffBase || !diffTarget" @click="runDiff">对比</el-button>
            </div>
          </div>
        </el-card>
      </el-col>

      <el-col :span="15">
        <el-card shadow="never" v-if="diffResult" style="margin-bottom: 14px">
          <template #header>
            <div style="display: flex; justify-content: space-between">
              <span>批次对比: {{ diffResult.base_run.name }} → {{ diffResult.target_run.name }}</span>
              <el-button link size="small" @click="diffResult = null">关闭对比</el-button>
            </div>
          </template>
          <div style="display: flex; gap: 16px; margin-bottom: 10px; font-size: 13px">
            <span>基准覆盖率: <b>{{ diffResult.base_coverage_pct.toFixed(1) }}%</b></span>
            <span>目标覆盖率: <b>{{ diffResult.target_coverage_pct.toFixed(1) }}%</b></span>
            <span style="color: #16a34a">新增命中: {{ diffResult.newly_hit.join(', ') || '无' }}</span>
            <span style="color: #dc2626">退化缺失: {{ diffResult.regressed.join(', ') || '无' }}</span>
          </div>
        </el-card>

        <el-card shadow="never" v-if="coverage">
          <template #header>
            <div style="display: flex; justify-content: space-between; align-items: center">
              <span>{{ coverage.run.name }} — 覆盖率 {{ coverage.coverage_pct.toFixed(1) }}%</span>
              <div style="display: flex; gap: 8px">
                <el-tag type="success" size="small">命中 {{ coverage.hit_count }}</el-tag>
                <el-tag type="danger" size="small">解析失败 {{ coverage.error_only_count }}</el-tag>
                <el-tag type="info" size="small">未命中 {{ coverage.missed_count }}</el-tag>
              </div>
            </div>
          </template>

          <div style="display: flex; gap: 8px; margin-bottom: 10px">
            <el-input v-model="protoSearch" size="small" placeholder="筛选协议名" clearable style="width: 180px" />
            <el-radio-group v-model="statusFilter" size="small">
              <el-radio-button value="all">全部 ({{ coverage.total_protocols }})</el-radio-button>
              <el-radio-button value="hit">已命中 ({{ coverage.hit_count }})</el-radio-button>
              <el-radio-button value="missed">未命中 ({{ coverage.missed_count }})</el-radio-button>
              <el-radio-button value="parse_error">异常 ({{ coverage.error_only_count }})</el-radio-button>
            </el-radio-group>
          </div>

          <div class="matrix-grid">
            <div v-for="p in filteredProtocols" :key="p.protocol" class="matrix-cell" :class="'cell-' + p.status">
              <div class="cell-name">{{ p.protocol }}</div>
              <div class="cell-meta">{{ p.session_count }} 会话 · {{ p.avg_latency_ms.toFixed(0) }}ms</div>
            </div>
          </div>
        </el-card>
        <el-empty v-else description="请选择或创建一个测试批次查看全协议覆盖矩阵" />
      </el-col>
    </el-row>

    <el-dialog v-model="createDialog" title="开始新测试批次" width="420px">
      <el-form label-width="80px" size="small">
        <el-form-item label="批次名称">
          <el-input v-model="newRun.name" placeholder="例如 internal-scanner-v2.4 全量回归" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="newRun.notes" type="textarea" :rows="2" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createDialog = false">取消</el-button>
        <el-button type="primary" @click="createRun">立即开始</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'

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
  ElMessage.success('测试批次已开始')
  await load()
  await selectRun(created)
}

async function stopRun(id: string) {
  await api.stopTestRun(id)
  ElMessage.success('测试批次已结束')
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
  border: 1px solid #e2e8f0;
}
.cell-hit {
  background: #f0fdf4;
  border-color: #86efac;
  color: #166534;
}
.cell-parse_error {
  background: #fef2f2;
  border-color: #fca5a5;
  color: #991b1b;
}
.cell-missed {
  background: #f8fafc;
  border-color: #e2e8f0;
  color: #64748b;
}
.cell-name {
  font-weight: 600;
  font-size: 13px;
}
.cell-meta {
  font-size: 11px;
  margin-top: 2px;
  opacity: 0.85;
}
</style>
