import { useState } from 'react'
import AddressInput from './components/AddressInput'
import RiskDashboard from './components/RiskDashboard'
import TraceGraph from './components/TraceGraph'
import EvidenceList from './components/EvidenceList'
import { analyzeAddress, pollTask } from './api'
import type { RiskReport } from './types'
import './App.css'

export default function App() {
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState('')
  const [report, setReport] = useState<RiskReport | null>(null)
  const [error, setError] = useState('')

  async function handleAnalyze(address: string, chain: string, noHop2: boolean) {
    setLoading(true)
    setError('')
    setReport(null)
    setStatus('提交分析任务...')
    try {
      const { task_id } = await analyzeAddress({ address, chain: chain || undefined, no_hop2: noHop2 })
      setStatus('分析中，请稍候...')
      const result = await pollTask(task_id, (s) => setStatus(s))
      setReport(result)
      setStatus('')
    } catch (e: any) {
      setError(e.message || '分析失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1 className="logo"><span>T</span>ravis</h1>
        <p className="logo-sub">TRAceable Verification Intelligence System</p>
      </header>

      <main className="app-main">
        <AddressInput onAnalyze={handleAnalyze} loading={loading} />

        {status && <div className="status-bar">{status}</div>}
        {error  && <div className="error-bar">{error}</div>}

        {report && (
          <>
            <RiskDashboard report={report} />
            <div className="panels">
              <div className="panel panel-graph">
                <h2>资金路径图</h2>
                <TraceGraph report={report} />
              </div>
              <div className="panel panel-evidence">
                <h2>风险证据</h2>
                <EvidenceList report={report} />
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  )
}
