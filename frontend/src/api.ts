import axios from 'axios'
import type { RiskReport } from './types'

const BASE = 'http://localhost:8000'

export async function analyzeAddress(payload: {
  address: string
  chain?: string
  chains?: string[]
  no_hop2?: boolean
  days?: number
}): Promise<{ task_id: string }> {
  const res = await axios.post(`${BASE}/analyze`, payload)
  return res.data
}

export async function pollTask(
  taskId: string,
  onStatus: (s: string) => void,
  intervalMs = 2000,
  maxWaitMs = 120_000,
): Promise<RiskReport> {
  const start = Date.now()
  while (Date.now() - start < maxWaitMs) {
    await new Promise(r => setTimeout(r, intervalMs))
    const res = await axios.get(`${BASE}/task/${taskId}`)
    const { status, result, error } = res.data
    if (status === 'done') return result as RiskReport
    if (status === 'error') throw new Error(error || '分析失败')
    onStatus(status === 'running' ? '分析中...' : '等待中...')
  }
  throw new Error('分析超时（120s）')
}
