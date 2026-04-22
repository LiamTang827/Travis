export interface RiskIndicator {
  indicator_type: string
  category: string
  category_weight: number
  counterparty: string
  direction: string
  amount_usdt: number
  hop: number
  hop_decay: number
  tx_hashes: string[]
  timestamps: string[]
  chain: string
  via_address: string
  note: string
}

export interface RiskReport {
  address: string
  chain: string
  tron_address: string
  is_blacklisted: boolean
  blacklist_time: string
  risk_score: number
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  taint_ratio: number
  received_exposure: number
  sent_exposure: number
  account_info: Record<string, any>
  total_inflow_usdt: number
  total_outflow_usdt: number
  total_counterparties: number
  total_transactions: number
  chains_analyzed: string[]
  per_chain_inflow: Record<string, number>
  per_chain_outflow: Record<string, number>
  indicators: RiskIndicator[]
  top_counterparties: any[]
  bridge_interactions: any[]
  opaque_bridge_interactions: any[]
  mixer_interactions: any[]
  high_risk_exchanges: any[]
  cross_chain_findings: any[]
  warnings: string[]
}
