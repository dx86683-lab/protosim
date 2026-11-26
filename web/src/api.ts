import { locale, t } from './i18n'

export interface ApiOptions {
  method?: string
  body?: any
}

async function req<T = any>(path: string, opts: ApiOptions = {}): Promise<T> {
  const headers: Record<string, string> = {}
  const init: RequestInit = { method: opts.method || 'GET', headers, credentials: 'same-origin' }
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(opts.body)
  }
  const resp = await fetch(`/api/v2${path}`, init)
  if (resp.status === 401) {
    window.location.replace('/login')
    throw new Error(t('需要认证，正在跳转登录页'))
  }
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`
    try {
      const err = await resp.json()
      if (err?.error) msg = err.error
    } catch {}
    throw new Error(msg)
  }
  return resp.json()
}

export const api = {
  health: () => req('/health'),
  overview: (window = '24h') => req(`/overview?window=${encodeURIComponent(window)}`),

  sessions: (params: Record<string, any> = {}) => {
    const q = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
    })
    return req(`/sessions?${q.toString()}`)
  },
  sessionDetail: (id: string) => req(`/sessions/${encodeURIComponent(id)}`),
  sessionPcapUrl: (id: string) => `/api/v2/sessions/${encodeURIComponent(id)}/pcap`,
  logout: () => req('/auth/logout', { method: 'POST' }),

  events: (params: Record<string, any> = {}) => {
    const q = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
    })
    return req(`/events?${q.toString()}`)
  },
  credentials: (params: Record<string, any> = {}) => {
    const q = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
    })
    return req(`/credentials?${q.toString()}`)
  },

  probes: (params: Record<string, any> = {}) => {
    const q = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
    })
    return req(`/probes?${q.toString()}`)
  },
  updateProbe: (hash: string, body: { status?: string; note?: string; pinned?: boolean }) =>
    req(`/probes/${encodeURIComponent(hash)}`, { method: 'PATCH', body }),
  exportProbe: (hash: string, format: 'hex' | 'python' | 'go') =>
    req(`/probes/${encodeURIComponent(hash)}/export?format=${format}`),

  testRuns: () => req('/test-runs'),
  createTestRun: (body: { name: string; scenario?: string; notes?: string }) =>
    req('/test-runs', { method: 'POST', body }),
  stopTestRun: (id: string) => req(`/test-runs/${encodeURIComponent(id)}/stop`, { method: 'POST' }),
  testRunCoverage: (id: string) => req(`/test-runs/${encodeURIComponent(id)}/coverage`),
  testRunDiff: (base: string, target: string) =>
    req(`/test-runs/diff?base=${encodeURIComponent(base)}&target=${encodeURIComponent(target)}`),

  scannerRules: () => req('/scanner-rules'),
  createScannerRule: (body: any) => req('/scanner-rules', { method: 'POST', body }),
  updateScannerRule: (id: number, body: any) => req(`/scanner-rules/${id}`, { method: 'PUT', body }),
  deleteScannerRule: (id: number) => req(`/scanner-rules/${id}`, { method: 'DELETE' }),

  scenarios: () => req('/scenarios'),
  applyScenario: (id: string) => req('/scenarios/apply', { method: 'POST', body: { id } }),

  services: () => req('/services'),
  addService: (body: any) => req('/services', { method: 'POST', body }),
  stopService: (id: string) => req(`/services/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  updateCatchAll: (body: any) => req('/catch-all', { method: 'PUT', body }),

  protocols: () => req('/protocols'),
  config: () => req('/config'),
  updateRuntimeConfig: (body: any) => req('/config/runtime', { method: 'PUT', body }),
  runRetention: () => req('/retention/run', { method: 'POST' }),
}

export function formatTime(ts?: string | null): string {
  if (!ts) return '-'
  const d = new Date(ts)
  if (isNaN(d.getTime())) return ts
  return d.toLocaleString(locale.value, { hourCycle: 'h23' })
}

export function formatBytes(n?: number): string {
  if (!n) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

export function formatHexDump(hexStr: string): string {
  if (!hexStr) return t('（空）')
  const bytes: number[] = []
  for (let i = 0; i < hexStr.length; i += 2) {
    bytes.push(parseInt(hexStr.slice(i, i + 2), 16))
  }
  const lines: string[] = []
  for (let off = 0; off < bytes.length; off += 16) {
    const slice = bytes.slice(off, off + 16)
    const hexPart = slice.map((b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ')
    const asciiPart = slice.map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('')
    lines.push(`${off.toString(16).padStart(4, '0')}  ${hexPart}  |${asciiPart}|`)
  }
  return lines.join('\n')
}
