import type { RiskReport } from '../types'

const CATEGORY_LABEL: Record<string, string> = {
  blacklist: '黑名单',
  mixer: '混币器',
  opaque_bridge: '不透明桥',
  high_risk_exchange: '高风险交易所',
  transparent_bridge_with_bl: '透明桥(有黑名单)',
  transparent_bridge: '透明桥',
  ofac_sanctioned: 'OFAC制裁',
}

const CATEGORY_COLOR: Record<string, string> = {
  blacklist: '#ef4444',
  mixer: '#f97316',
  opaque_bridge: '#f59e0b',
  high_risk_exchange: '#eab308',
  transparent_bridge_with_bl: '#84cc16',
  transparent_bridge: '#22c55e',
}

function short(addr: string) {
  return addr.slice(0, 8) + '...' + addr.slice(-6)
}

function fmt(n: number) {
  return n.toLocaleString('en-US', { maximumFractionDigits: 2 })
}

interface Props { report: RiskReport }

export default function EvidenceList({ report }: Props) {
  const inds = report.indicators
    .filter(i => i.amount_usdt > 0)
    .sort((a, b) => a.hop - b.hop || b.amount_usdt - a.amount_usdt)

  if (inds.length === 0) {
    return <p className="empty">无 USDT 风险证据</p>
  }

  return (
    <div className="evidence-list">
      {inds.map((ind, i) => {
        const color = CATEGORY_COLOR[ind.category] ?? '#888'
        const label = CATEGORY_LABEL[ind.category] ?? ind.category
        const basis = ind.direction === 'IN' ? report.total_inflow_usdt : report.total_outflow_usdt
        const contrib = basis > 0 ? (ind.amount_usdt * ind.category_weight * ind.hop_decay / basis * 100) : 0

        const center = short(report.address)
        const cp = short(ind.counterparty)
        const via = ind.via_address ? short(ind.via_address) : null

        let path = ''
        if (ind.hop === 1) {
          path = ind.direction === 'IN'
            ? `${cp} ──${fmt(ind.amount_usdt)} USDT──▶ ${center}`
            : `${center} ──${fmt(ind.amount_usdt)} USDT──▶ ${cp}`
        } else if (ind.hop === 2) {
          path = ind.direction === 'IN'
            ? `${cp} ──▶ ${via ?? '?'} ──▶ ${center}`
            : `${center} ──▶ ${via ?? '?'} ──▶ ${cp}`
        } else {
          path = ind.direction === 'IN'
            ? `${cp} ──▶ ${via ?? '?'} ──▶ ${center}`
            : `${center} ──▶ ${via ?? '?'} ──▶ ${cp}`
        }

        return (
          <div key={i} className="evidence-item" style={{ borderLeftColor: color }}>
            <div className="ev-header">
              <span className="ev-badge" style={{ background: color }}>{ind.hop}-hop · {label}</span>
              <span className="ev-chain">[{ind.chain}]</span>
              <span className="ev-contrib">污染贡献 {contrib.toFixed(2)}%{ind.hop === 2 ? ' ×0.3' : ''}</span>
            </div>
            <div className="ev-amount">${fmt(ind.amount_usdt)} USDT</div>
            <div className="ev-path">{path}</div>
            {ind.tx_hashes.length > 0 && (
              <div className="ev-tx">
                tx: <code>{ind.tx_hashes[0].slice(0, 20)}...</code>
                {ind.tx_hashes.length > 1 && ` 等${ind.tx_hashes.length}笔`}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
