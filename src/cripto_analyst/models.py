#!/usr/bin/env python3
"""数据模型：RiskIndicator（单条可审计风险证据）与 RiskReport（完整分析结果）。"""

from dataclasses import dataclass, field
from typing import Dict, List

# ==================== 数据类 ====================

@dataclass
class RiskIndicator:
    """
    单条风险证据——评分的最小单元。
    每条 indicator 对应一个可审计的链上事实：
    具体是哪笔交易、涉及多少 USDT、来自哪类风险实体、发生在哪条链上。
    """
    indicator_type: str      # blacklist_received / blacklist_sent / mixer / opaque_bridge / ...
    category: str
    category_weight: float
    counterparty: str
    direction: str           # IN / OUT
    amount_usdt: float
    hop: int                 # 1 = 1-hop 直接交互，2 = 2-hop 间接关联
    hop_decay: float
    tx_hashes: List[str]
    timestamps: List[str]
    chain: str = ""          # 发生在哪条链（ethereum / bsc / polygon / ...）
    via_address: str = ""    # 2-hop 时的中间节点地址
    token: str = ""          # 具体稳定币（USDT / USDC / DAI ...），空=未知
    note: str = ""
    native_amounts: dict = field(default_factory=dict)  # {sym: amount}，非稳定币原始数量


@dataclass
class RiskReport:
    address: str
    chain: str               # 主链（或 "multi-evm"）
    tron_address: str = ""
    is_blacklisted: bool = False
    blacklist_time: str = ""

    # 评分结果
    risk_score: float = 0.0
    risk_level: str = "LOW"
    taint_ratio: float = 0.0
    received_exposure: float = 0.0
    sent_exposure: float = 0.0

    # 基础统计（跨链合计）
    account_info: dict = field(default_factory=dict)
    total_inflow_usdt: float = 0.0   # 仅稳定币，用于污染评分分母
    total_outflow_usdt: float = 0.0  # 仅稳定币，用于污染评分分母
    total_eth_usd_in: float = 0.0    # ETH 折 USD，仅用于展示 % of Flow
    total_eth_usd_out: float = 0.0   # ETH 折 USD，仅用于展示 % of Flow
    total_counterparties: int = 0
    total_transactions: int = 0

    # 多链明细
    chains_analyzed: List[str] = field(default_factory=list)
    per_chain_inflow: Dict[str, float] = field(default_factory=dict)
    per_chain_outflow: Dict[str, float] = field(default_factory=dict)
    analysis_windows: Dict[str, Dict] = field(default_factory=dict)

    # 风险证据列表（评分的完整依据）
    indicators: List[RiskIndicator] = field(default_factory=list)

    # 评分分解（可解释性）
    score_breakdown: dict = field(default_factory=dict)

    # 展示用原始记录（不参与评分）
    top_counterparties: List[dict] = field(default_factory=list)
    bridge_interactions: List[dict] = field(default_factory=list)
    opaque_bridge_interactions: List[dict] = field(default_factory=list)
    mixer_interactions: List[dict] = field(default_factory=list)
    high_risk_exchanges: List[dict] = field(default_factory=list)
    cross_chain_findings: List[dict] = field(default_factory=list)
    contract_interactions: List[dict] = field(default_factory=list)

    # 每种稳定币的独立分析结果
    # {sym: {chain, flow_in, flow_out, balance, taint_ratio, risk_score, is_fast_transit}}
    per_asset: Dict[str, Dict] = field(default_factory=dict)

    balance_info: dict = field(default_factory=dict)   # 整体余额一致性（快速中转信号）
    warnings: List[str] = field(default_factory=list)

    # 全量稳定币流水（--full 时打印，JSON 报告始终写入）
    # 每条: {ts, direction, amount, sym, chain, counterparty, tx_hash, risk_label}
    transactions: List[dict] = field(default_factory=list)

    # 对手方聚合表（按地址+方向汇总）
    # 每条: {address, direction, total_usd, by_sym, risk_tags, taint_pct}
    counterparty_table: List[dict] = field(default_factory=list)

