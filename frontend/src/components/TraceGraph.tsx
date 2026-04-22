import { useMemo } from 'react'
import {
  ReactFlow, Background, Controls, MiniMap,
  type Node, type Edge,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import type { RiskReport } from '../types'

const CATEGORY_COLOR: Record<string, string> = {
  blacklist:       '#ef4444',
  ofac_sanctioned: '#7f1d1d',
  mixer:           '#f97316',
  opaque_bridge:   '#f59e0b',
  high_risk_exchange: '#eab308',
  transparent_bridge_with_bl: '#84cc16',
  transparent_bridge: '#22c55e',
}

const LEVEL_COLOR: Record<string, string> = {
  LOW:      '#22c55e',
  MEDIUM:   '#f59e0b',
  HIGH:     '#ef4444',
  CRITICAL: '#a855f7',
}

function short(addr: string) {
  return addr.slice(0, 6) + '...' + addr.slice(-4)
}

interface Props { report: RiskReport }

export default function TraceGraph({ report }: Props) {
  const { nodes, edges } = useMemo(() => {
    const nodes: Node[] = []
    const edges: Edge[] = []
    const seen = new Set<string>()

    const centerColor = LEVEL_COLOR[report.risk_level] ?? '#888'

    // 中心节点
    nodes.push({
      id: report.address,
      position: { x: 0, y: 0 },
      data: { label: short(report.address) },
      style: {
        background: centerColor, color: '#fff',
        border: `3px solid ${centerColor}`,
        borderRadius: 8, fontWeight: 700, fontSize: 12,
        padding: '8px 14px',
      },
    })
    seen.add(report.address)

    const inds = report.indicators.filter(i => i.amount_usdt > 0)
    const hop1 = inds.filter(i => i.hop === 1)
    const hop2 = inds.filter(i => i.hop === 2)
    const hop3 = inds.filter(i => i.hop === 3)

    // 1-hop 节点（扇形分布）
    hop1.forEach((ind, idx) => {
      const angle = (idx / Math.max(hop1.length, 1)) * 2 * Math.PI
      const r = 280
      const x = Math.cos(angle) * r
      const y = Math.sin(angle) * r
      const bg = CATEGORY_COLOR[ind.category] ?? '#6b7280'
      const cp = ind.counterparty

      if (!seen.has(cp)) {
        nodes.push({
          id: cp,
          position: { x, y },
          data: { label: short(cp) },
          style: {
            background: bg, color: '#fff',
            border: `2px solid ${bg}`,
            borderRadius: 8, fontSize: 11,
            padding: '6px 10px',
          },
        })
        seen.add(cp)
      }

      const amt = ind.amount_usdt.toLocaleString('en-US', { maximumFractionDigits: 0 })
      edges.push({
        id: `e-${cp}-${ind.direction}`,
        source: ind.direction === 'IN' ? cp : report.address,
        target: ind.direction === 'IN' ? report.address : cp,
        label: `$${amt}`,
        animated: true,
        style: { stroke: bg },
        labelStyle: { fill: '#e2e8f0', fontSize: 10 },
        labelBgStyle: { fill: '#1e293b' },
      })
    })

    // 2-hop 节点（外圈）
    hop2.forEach((ind, idx) => {
      const angle = (idx / Math.max(hop2.length, 1)) * 2 * Math.PI
      const r = 520
      const x = Math.cos(angle) * r
      const y = Math.sin(angle) * r
      const bg = CATEGORY_COLOR[ind.category] ?? '#6b7280'
      const cp = ind.counterparty
      const via = ind.via_address

      if (!seen.has(cp)) {
        nodes.push({
          id: cp,
          position: { x, y },
          data: { label: short(cp) },
          style: {
            background: bg, color: '#fff',
            border: `2px dashed ${bg}`,
            borderRadius: 8, fontSize: 11,
            padding: '6px 10px', opacity: 0.85,
          },
        })
        seen.add(cp)
      }

      // via → center edge（虚线）
      if (via && seen.has(via)) {
        edges.push({
          id: `e2-${cp}-${via}`,
          source: cp,
          target: via,
          style: { stroke: bg, strokeDasharray: '5,4' },
          animated: false,
        })
      }
    })

    // 3-hop 节点（最外圈 r=760，透明度更低）
    hop3.forEach((ind, idx) => {
      const angle = (idx / Math.max(hop3.length, 1)) * 2 * Math.PI
      const r = 760
      const x = Math.cos(angle) * r
      const y = Math.sin(angle) * r
      const bg = CATEGORY_COLOR[ind.category] ?? '#6b7280'
      const cp = ind.counterparty
      const via = ind.via_address

      if (!seen.has(cp)) {
        nodes.push({
          id: cp,
          position: { x, y },
          data: { label: short(cp) },
          style: {
            background: bg, color: '#fff',
            border: `1px dashed ${bg}`,
            borderRadius: 8, fontSize: 10,
            padding: '4px 8px', opacity: 0.6,
          },
        })
        seen.add(cp)
      }

      if (via && seen.has(via)) {
        edges.push({
          id: `e3-${cp}-${via}`,
          source: cp,
          target: via,
          style: { stroke: bg, strokeDasharray: '3,6', opacity: 0.5 },
          animated: false,
        })
      }
    })

    return { nodes, edges }
  }, [report])

  return (
    <div style={{ height: 480 }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        colorMode="dark"
        proOptions={{ hideAttribution: true }}
      >
        <Background />
        <Controls />
        <MiniMap nodeColor={n => (n.style?.background as string) ?? '#444'} />
      </ReactFlow>
    </div>
  )
}
