import { useState } from 'react'

const CHAINS = [
  { id: '', label: '自动检测' },
  { id: 'ethereum', label: 'Ethereum' },
  { id: 'bsc', label: 'BSC' },
  { id: 'polygon', label: 'Polygon' },
  { id: 'arbitrum', label: 'Arbitrum' },
  { id: 'optimism', label: 'Optimism' },
  { id: 'avalanche', label: 'Avalanche' },
  { id: 'base', label: 'Base' },
  { id: 'tron', label: 'Tron' },
]

interface Props {
  onAnalyze: (address: string, chain: string, noHop2: boolean) => void
  loading: boolean
}

export default function AddressInput({ onAnalyze, loading }: Props) {
  const [address, setAddress] = useState('')
  const [chain, setChain] = useState('')
  const [noHop2, setNoHop2] = useState(true)

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (address.trim()) onAnalyze(address.trim(), chain, noHop2)
  }

  return (
    <form className="input-form" onSubmit={submit}>
      <input
        className="address-input"
        placeholder="输入钱包地址（0x... 或 Tron T...）"
        value={address}
        onChange={e => setAddress(e.target.value)}
        disabled={loading}
      />
      <div className="input-row">
        <select value={chain} onChange={e => setChain(e.target.value)} disabled={loading}>
          {CHAINS.map(c => <option key={c.id} value={c.id}>{c.label}</option>)}
        </select>
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={noHop2}
            onChange={e => setNoHop2(e.target.checked)}
            disabled={loading}
          />
          快速模式（禁用 2-hop）
        </label>
        <button type="submit" disabled={loading || !address.trim()}>
          {loading ? '分析中...' : '分析'}
        </button>
      </div>
    </form>
  )
}
