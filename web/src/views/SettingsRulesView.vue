<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">扫描器打标规则与系统设置</h2>
      <el-button type="primary" size="small" @click="ruleDialog = true">+ 新增打标规则</el-button>
    </div>

    <el-card shadow="never" style="margin-bottom: 16px">
      <template #header><span>扫描器身份归因规则 (CIDR / UA / JA3 / 首包正则)</span></template>
      <el-table :data="rules" size="small" stripe>
        <el-table-column prop="name" label="规则名称" width="210" />
        <el-table-column prop="tag" label="扫描器标签" width="130">
          <template #default="{ row }"><el-tag size="small">{{ row.tag }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="match_type" label="匹配维度" width="120" />
        <el-table-column prop="pattern" label="匹配表达式" class-name="mono" show-overflow-tooltip />
        <el-table-column label="启用" width="80">
          <template #default="{ row }">
            <el-switch v-model="row.enabled" size="small" @change="toggleRule(row)" />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="80">
          <template #default="{ row }">
            <el-button link type="danger" size="small" @click="delRule(row.id)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-row :gutter="16" v-if="cfg">
      <el-col :span="12">
        <el-card shadow="never">
          <template #header><span>存储、载荷与保留策略</span></template>
          <el-form label-width="150px" size="small">
            <el-form-item label="SQLite 路径"><span class="mono">{{ cfg.storage.db_path }}</span></el-form-item>
            <el-form-item label="记录原始载荷">
              <el-switch v-model="cfg.storage.payload_enabled" />
            </el-form-item>
            <el-form-item label="凭证脱敏存储">
              <el-switch v-model="cfg.storage.redact_credentials" />
            </el-form-item>
            <el-form-item label="保留天数">
              <el-input-number v-model="cfg.storage.retention_days" :min="1" :max="3650" />
            </el-form-item>
            <el-form-item label="存储上限 (MB)">
              <el-input-number v-model="cfg.storage.max_size_mb" :min="64" :max="102400" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="saveRuntime">保存运行时配置</el-button>
              <el-button @click="runRetention">立即执行滚动清理</el-button>
            </el-form-item>
          </el-form>
        </el-card>
      </el-col>

      <el-col :span="12">
        <el-card shadow="never">
          <template #header><span>新探针 Webhook 通知与鉴权状态</span></template>
          <el-form label-width="140px" size="small">
            <el-form-item label="启用 Webhook">
              <el-switch v-model="cfg.webhook.enabled" />
            </el-form-item>
            <el-form-item label="Webhook URL">
              <el-input v-model="cfg.webhook.url" placeholder="https://hooks.example.com/protosim" />
            </el-form-item>
            <el-form-item label="仅首次发现触发">
              <el-switch v-model="cfg.webhook.on_new_probe" />
            </el-form-item>
            <el-form-item label="管理端鉴权">
              <el-tag :type="cfg.api.auth.enabled ? 'success' : 'info'">
                {{ cfg.api.auth.enabled ? '已开启认证' : '内网免密模式' }}
              </el-tag>
            </el-form-item>
            <el-form-item label="限流状态">
              <el-tag :type="cfg.rate_limit.enabled ? 'warning' : 'info'">
                {{ cfg.rate_limit.enabled ? `${cfg.rate_limit.per_ip_per_sec}/s` : '默认不限流' }}
              </el-tag>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="saveRuntime">保存 Webhook</el-button>
            </el-form-item>
          </el-form>
        </el-card>
      </el-col>
    </el-row>

    <el-dialog v-model="ruleDialog" title="新增扫描器打标规则" width="440px">
      <el-form label-width="90px" size="small">
        <el-form-item label="规则名称">
          <el-input v-model="newRule.name" placeholder="例如 己方扫描器网段" />
        </el-form-item>
        <el-form-item label="扫描器标签">
          <el-input v-model="newRule.tag" placeholder="如 self-scanner" />
        </el-form-item>
        <el-form-item label="匹配维度">
          <el-select v-model="newRule.match_type" style="width: 100%">
            <el-option label="IP / CIDR" value="cidr" />
            <el-option label="HTTP User-Agent" value="ua" />
            <el-option label="TLS JA3" value="ja3" />
            <el-option label="首包正则 (payload_regex)" value="payload_regex" />
          </el-select>
        </el-form-item>
        <el-form-item label="匹配表达式">
          <el-input v-model="newRule.pattern" placeholder="如 192.168.124.0/24 或 internal-scanner" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="ruleDialog = false">取消</el-button>
        <el-button type="primary" @click="createRule">保存规则</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'

const rules = ref<any[]>([])
const cfg = ref<any>(null)
const ruleDialog = ref(false)
const newRule = ref({ name: '', tag: '', match_type: 'cidr', pattern: '', enabled: true })

async function load() {
  const [rRes, cRes] = await Promise.all([api.scannerRules(), api.config()])
  rules.value = rRes.items || []
  cfg.value = cRes
}

async function createRule() {
  await api.createScannerRule(newRule.value)
  ruleDialog.value = false
  newRule.value = { name: '', tag: '', match_type: 'cidr', pattern: '', enabled: true }
  ElMessage.success('规则已添加并实时生效')
  load()
}

async function toggleRule(row: any) {
  await api.updateScannerRule(row.id, row)
  ElMessage.success('规则状态已更新')
}

async function delRule(id: number) {
  await api.deleteScannerRule(id)
  ElMessage.success('规则已删除')
  load()
}

async function saveRuntime() {
  await api.updateRuntimeConfig({ storage: cfg.value.storage, webhook: cfg.value.webhook })
  ElMessage.success('运行时配置已更新')
}

async function runRetention() {
  const res = await api.runRetention()
  ElMessage.success(`清理完成，删除过期会话 ${res.deleted_sessions} 条（探针库与收藏样本已永久保留）`)
}

onMounted(load)
</script>
