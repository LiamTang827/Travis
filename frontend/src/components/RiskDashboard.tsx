import type { RiskReport } from '../types'

const LEVEL_COLOR: Record<string, string> = {
  LOW: '#22c55e',
  MEDIUM: '#f59e0b',
  HIGH: '#ef4444',
  CRITICAL: '#a855f7',
}

function fmt(n: number) {
  return n.toLocaleString('en-US', { maximumFractionDigits: 2 })
}

interface Props { report: RiskReport }

export default function RiskDashboard({ report }: Props) {
  const color = LEVEL_COLOR[report.risk_level] ?? '#888'

  return (
    <div className="dashboard">
      {/* 风险等级 */}
      <div className="card card-score" style={{ borderColor: color }}>
        <div className="score-num" style={{ color }}>{report.risk_score}</div>
        <div className="score-label" style={{ color }}>{report.risk_level}</div>
        <div className="score-sub">污染比例 {(report.taint_ratio * 100).toFixed(2)}%</div>
        {report.is_blacklisted && (
          <div className="badge-blacklist">直接命中黑名单</div>
        )}
      </div>

      {/* 基础信息 */}
      <div className="card card-info">
        <div className="info-row"><span>地址</span><code>{report.address.slice(0,10)}...{report.address.slice(-6)}</code></div>
        <div className="info-row"><span>链</span><span>{report.chain}</span></div>
        <div className="info-row"><span>余额</span><span>{report.account_info?.balance ?? 'N/A'}</span></div>
        <div className="info-row"><span>交易数</span><span>{report.total_transactions}</span></div>
        <div className="info-row"><span>对手方</span><span>{report.total_counterparties}</span></div>
        <div className="info-row"><span>USDT 流入</span><span className="inflow">${fmt(report.total_inflow_usdt)}</span></div>
        <div className="info-row"><span>USDT 流出</span><span className="outflow">${fmt(report.total_outflow_usdt)}</span></div>
      </div>

      {/* 暴露细节 */}
      <div className="card card-exposure">
        <div className="exp-bar-wrap">
          <span>收入侧暴露</span>
          <div className="exp-bar"><div className="exp-fill" style={{ width: `${report.received_exposure * 100}%`, background: color }} /></div>
          <span>{(report.received_exposure * 100).toFixed(1)}%</span>
        </div>
        <div className="exp-bar-wrap">
          <span>转出侧暴露</span>
          <div className="exp-bar"><div className="exp-fill" style={{ width: `${report.sent_exposure * 100}%`, background: color }} /></div>
          <span>{(report.sent_exposure * 100).toFixed(1)}%</span>
        </div>
        {report.warnings.length > 0 && (
          <div className="warnings">
            {report.warnings.map((w, i) => <div key={i} className="warning-item">⚠ {w}</div>)}
          </div>
        )}
      </div>
    </div>
  )
}
