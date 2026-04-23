#!/usr/bin/env python3
"""
Travis — TRAceable Verification Intelligence System
链上 AML 风险分析引擎：黑名单关联检测 + 比例污染传播 + 多链跨链追踪
支持链：Ethereum / BSC / Polygon / Arbitrum / Optimism / Avalanche / Base / Tron
"""

import csv
import json
import time
import hashlib
import argparse
import sys
from typing import Optional, Set, Dict, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import os

import requests
from dotenv import load_dotenv
from threat_intel import (
    MIXER_CONTRACTS, BRIDGE_REGISTRY, ALL_BRIDGE_ADDRS, OPAQUE_BRIDGE_ADDRS,
    EXCHANGE_HOT_WALLETS, HIGH_RISK_EXCHANGES, HIGH_RISK_EXCHANGES_FLAT,
    EXCHANGE_HOT_WALLETS_FLAT, ALL_EXCHANGE_ADDRS, DEPOSIT_DETECTION_PARAMS,
)

load_dotenv()

# ==================== 配置 ====================
BLACKLIST_CSV = "usdt_blacklist.csv"
REQUEST_DELAY = 0.25   # 每次 API 请求后的等待时间（秒），Etherscan 免费档限速 5 req/s
PAGE_SIZE = 500        # 每页拉取条数（Etherscan 最大支持 10000，但越大单次越慢）
MAX_PAGES = 5          # 最多翻多少页（PAGE_SIZE × MAX_PAGES = 最大历史深度）
                       # 默认 5 页 × 500 = 2500 条，覆盖普通活跃地址的完整历史
                       # 对交易所热钱包等超活跃地址，依赖时间窗口（--days）截断
HOP2_ENABLED = True    # 是否启用 2-hop 分析（较慢，快速模式下禁用）

# 向后兼容
MAX_TX_FETCH = PAGE_SIZE

# ==================== 风险类别权重（参考 FATF 风险等级）====================
CATEGORY_WEIGHTS: Dict[str, float] = {
    "ofac_sanctioned":            1.0,
    "ransomware":                 0.9,
    "theft_hack":                 0.9,
    "darknet":                    0.8,
    "blacklist":                  0.8,   # USDT 黑名单（未分类）
    "mixer":                      0.7,
    "opaque_bridge":              0.6,
    "high_risk_exchange":         0.4,
    "transparent_bridge_with_bl": 0.3,
    "transparent_bridge":         0.1,
}

# Hop 距离衰减（直接交互 1.0，二跳 0.3）
HOP_DECAY: Dict[int, float] = {1: 1.0, 2: 0.3}

# BRIDGE_REGISTRY / ALL_BRIDGE_ADDRS / OPAQUE_BRIDGE_ADDRS 从 threat_intel 导入

# ==================== 链注册表 ====================
# 新增链：只需在此处加一条记录，其余业务代码无需修改。
# api_key 留空则走无 key 公开端点（速率更严格）。
# backup_url: 无 key 备用端点（Blockscout 系，无 OFAC 屏蔽）。
# usdt_contract: 该链上 USDT 的合约地址（用于过滤 tokentx）。
# native_token: 原生代币符号（展示用）。

@dataclass
class ChainConfig:
    name: str
    api_url: str
    api_key: str
    usdt_contract: str
    native_token: str
    backup_url: str = ""
    explorer_url: str = ""

EVM_CHAIN_REGISTRY: Dict[str, ChainConfig] = {
    "ethereum": ChainConfig(
        name="Ethereum", native_token="ETH",
        api_url="https://api.etherscan.io/api",
        api_key=os.getenv("ETHERSCAN_API_KEY", ""),
        backup_url="https://eth.blockscout.com/api",
        usdt_contract="0xdac17f958d2ee523a2206206994597c13d831ec7",
        explorer_url="https://etherscan.io",
    ),
    "bsc": ChainConfig(
        name="BSC", native_token="BNB",
        api_url="https://api.bscscan.com/api",
        api_key=os.getenv("BSCSCAN_API_KEY", ""),
        backup_url="https://bsc.blockscout.com/api",
        usdt_contract="0x55d398326f99059ff775485246999027b3197955",
        explorer_url="https://bscscan.com",
    ),
    "polygon": ChainConfig(
        name="Polygon", native_token="MATIC",
        api_url="https://api.polygonscan.com/api",
        api_key=os.getenv("POLYGONSCAN_API_KEY", ""),
        backup_url="https://polygon.blockscout.com/api",
        usdt_contract="0xc2132d05d31c914a87c6611c10748aeb04b58e8f",
        explorer_url="https://polygonscan.com",
    ),
    "arbitrum": ChainConfig(
        name="Arbitrum", native_token="ETH",
        api_url="https://api.arbiscan.io/api",
        api_key=os.getenv("ARBISCAN_API_KEY", ""),
        backup_url="https://arbitrum.blockscout.com/api",
        usdt_contract="0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",
        explorer_url="https://arbiscan.io",
    ),
    "optimism": ChainConfig(
        name="Optimism", native_token="ETH",
        api_url="https://api-optimistic.etherscan.io/api",
        api_key=os.getenv("OPTIMISM_API_KEY", ""),
        backup_url="https://optimism.blockscout.com/api",
        usdt_contract="0x94b008aa00579c1307b0ef2c499ad98a8ce58e58",
        explorer_url="https://optimistic.etherscan.io",
    ),
    "avalanche": ChainConfig(
        name="Avalanche", native_token="AVAX",
        api_url="https://api.snowtrace.io/api",
        api_key=os.getenv("SNOWTRACE_API_KEY", ""),
        backup_url="https://avalanche.blockscout.com/api",
        usdt_contract="0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7",
        explorer_url="https://snowtrace.io",
    ),
    "base": ChainConfig(
        name="Base", native_token="ETH",
        api_url="https://api.basescan.org/api",
        api_key=os.getenv("BASESCAN_API_KEY", ""),
        backup_url="https://base.blockscout.com/api",
        usdt_contract="0xfde4c96c8593536e31f229ea8f37b2ada2699bb2",
        explorer_url="https://basescan.org",
    ),
}

# 跨链追踪时查询目标链用（供 BridgeTracer 使用）
CHAIN_SCANNERS: Dict[str, Dict] = {
    name: {"api": cfg.api_url, "key": cfg.api_key}
    for name, cfg in EVM_CHAIN_REGISTRY.items()
}

# LayerZero 链 ID → 链名称（v1 + v2 endpoint IDs）
LZ_CHAIN_MAP: Dict[int, str] = {
    101: "ethereum",  110: "arbitrum",  111: "optimism",
    109: "polygon",   102: "bsc",       106: "avalanche",  184: "base",
    30101: "ethereum", 30110: "arbitrum", 30111: "optimism",
    30109: "polygon",  30102: "bsc",      30106: "avalanche", 30184: "base",
}

BRIDGE_TRACE_ENABLED = True

# 混币器、桥、交易所数据从 threat_intel/ 目录加载（见该目录的 JSON 文件）
# 需要新增地址时，直接编辑对应的 JSON 文件，无需改动本文件。

# ==================== 已知 DEX Router（排除用，非风险信号）====================
KNOWN_DEX_ADDRS: Set[str] = {
    a.lower().strip() for a in [
        "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",  # Uniswap V2 Router
        "0xe592427a0aece92de3edee1f18e0157c05861564",  # Uniswap V3 Router
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",  # Uniswap Universal Router
        "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad",  # Uniswap Universal Router 3
        "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f",  # SushiSwap Router
        "0x1111111254eeb25477b68fb85ed929f73a960582",  # 1inch v5
        "0xdef1c0ded9bec7f1a1670819833240f027b25eff",  # 0x Exchange Proxy
    ]
}

# ==================== Tron 已知跨链桥合约 ====================
TRON_BRIDGE_CONTRACTS_HEX = {
    "0x1df721d242e0783f8fcad4592a068bc6a50c4bce": "Multichain Tron",
    "0x0000000000000000000000000000000000000000": "Placeholder",
}

# ==================== Base58 工具 ====================
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    count = 0
    for byte in data:
        if byte == 0:
            count += 1
        else:
            break
    num = int.from_bytes(data, "big")
    result = []
    while num > 0:
        num, rem = divmod(num, 58)
        result.append(_B58_ALPHABET[rem : rem + 1])
    result.extend([_B58_ALPHABET[0:1]] * count)
    return b"".join(reversed(result)).decode()


def hex_to_tron_base58(hex_addr: str) -> str:
    """将 0x 开头的 hex 地址转换为 Tron Base58Check 地址（T 开头）"""
    clean = hex_addr.lower().replace("0x", "")
    raw = bytes.fromhex("41" + clean)
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    return _b58encode(raw + checksum)


def normalize(addr: str) -> str:
    return addr.lower().strip()


# ==================== 黑名单加载 ====================
def load_blacklist(csv_path: str) -> Dict[str, Dict]:
    """加载黑名单，返回 {normalize(address): {chain, time}} 字典"""
    bl: Dict[str, Dict] = {}
    try:
        with open(csv_path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                addr = normalize(row["address"])
                bl[addr] = {"chain": row.get("chain", ""), "time": row.get("time", "")}
    except FileNotFoundError:
        print(f"[ERROR] 找不到黑名单文件: {csv_path}", file=sys.stderr)
        sys.exit(1)
    return bl


# ==================== 链类型判断 ====================
def detect_chain(address: str, blacklist: Dict[str, Dict]) -> str:
    # Tron 地址以 T 开头，Base58 编码，34位
    if not address.startswith("0x"):
        return "tron"
    addr_norm = normalize(address)
    # 黑名单里有明确链记录时使用（避免多链同地址歧义）
    if addr_norm in blacklist:
        chain = blacklist[addr_norm].get("chain", "")
        if chain and chain in EVM_CHAIN_REGISTRY:
            return chain
    return "ethereum"


# ==================== 通用 EVM 链查询客户端 ====================
# 兼容 Etherscan API 格式（BscScan / PolygonScan / Arbiscan 等使用相同接口）
# 策略：优先用主端点（付费 key），若无结果自动切换 Blockscout 备用端点

class EVMClient:
    """通用 EVM 链查询客户端，接受 ChainConfig 配置。"""

    def __init__(self, cfg: ChainConfig):
        self.cfg = cfg
        self.primary_url = cfg.api_url
        self.backup_url = cfg.backup_url or ""
        self.key = cfg.api_key
        # 保持旧属性名兼容（_get_usdt_logs 等内部方法使用）
        self.ETHERSCAN_BASE  = cfg.api_url
        self.BLOCKSCOUT_BASE = cfg.backup_url or ""

    def _get(self, params: dict, base: str = None) -> Optional[dict]:
        url = base or self.primary_url
        p = dict(params)
        # 只在主端点加 apikey（Blockscout 公开端点不需要）
        if self.key and url == self.primary_url:
            p["apikey"] = self.key
        try:
            r = requests.get(url, params=p, timeout=15)
            data = r.json()
            return data
        except Exception as e:
            print(f"  [WARN] 请求失败 ({url[:50]}): {e}", file=sys.stderr)
            return None

    def _fetch_one_page(self, params: dict) -> List[dict]:
        """查一页，主端点失败时尝试备用端点。"""
        urls = [u for u in [self.primary_url, self.backup_url] if u]
        for base in urls:
            data = self._get(params, base=base)
            result = data.get("result", []) if data else []
            if isinstance(result, list) and len(result) > 0:
                if base == self.backup_url:
                    print(f"  [INFO] {self.cfg.name} 主端点无结果，已从备用端点获取数据")
                return result
            time.sleep(REQUEST_DELAY)
        return []

    def _fetch_txs_paged(self, base_params: dict,
                         page_size: int = MAX_TX_FETCH,
                         max_pages: int = 10,
                         time_cutoff: int = 0) -> Tuple[List[dict], bool]:
        """
        分页拉取交易，返回 (结果列表, 是否被截断)。

        早停条件（满足任一即停止翻页）：
          1. 当前页返回条数 < page_size → 已到末尾
          2. 当前页最后一条时间戳 < time_cutoff → 已超出时间窗口
          3. 已拉取 max_pages 页 → 主动截断，防止无限翻页

        page_size: 每页条数（Etherscan 最大 10000，建议 500-1000）
        max_pages: 最多拉取的页数
        time_cutoff: Unix 时间戳，早于此时间的记录不需要（0=不限制）
        """
        all_results: List[dict] = []
        truncated = False

        for page_num in range(1, max_pages + 1):
            params = dict(base_params)
            params["page"] = page_num
            params["offset"] = page_size
            time.sleep(REQUEST_DELAY)
            page = self._fetch_one_page(params)

            if not page:
                break  # 无数据，到头了

            all_results.extend(page)

            # 早停：时间窗口
            if time_cutoff > 0:
                oldest_ts = int(page[-1].get("timeStamp", 0))
                if oldest_ts < time_cutoff:
                    break  # 这页里最老的记录已超出窗口，后面的更老，不用拿了

            # 早停：未满页 = 没有下一页
            if len(page) < page_size:
                break

            # 已拉满 max_pages → 截断
            if page_num == max_pages:
                truncated = True
                print(f"  [INFO] {self.cfg.name} 已拉取 {max_pages} 页（{len(all_results)} 条），主动截断")

        return all_results, truncated

    def get_normal_txs(self, address: str,
                       limit: int = MAX_TX_FETCH,
                       max_pages: int = 1,
                       time_cutoff: int = 0) -> List[dict]:
        base = {
            "module": "account", "action": "txlist",
            "address": address, "startblock": 0, "endblock": 99999999,
            "sort": "desc",
        }
        results, _ = self._fetch_txs_paged(base, page_size=limit,
                                            max_pages=max_pages, time_cutoff=time_cutoff)
        return results

    def get_token_transfers(self, address: str,
                            limit: int = MAX_TX_FETCH,
                            max_pages: int = 1,
                            time_cutoff: int = 0) -> List[dict]:
        base = {
            "module": "account", "action": "tokentx",
            "address": address, "startblock": 0, "endblock": 99999999,
            "sort": "desc",
        }
        results, _ = self._fetch_txs_paged(base, page_size=limit,
                                            max_pages=max_pages, time_cutoff=time_cutoff)
        return results

    def get_account_info(self, address: str) -> dict:
        balance_data = self._get({"module": "account", "action": "balance",
                                  "address": address, "tag": "latest"})
        if not balance_data or not isinstance(balance_data.get("result"), str):
            if self.backup_url:
                balance_data = self._get({"module": "account", "action": "balance",
                                          "address": address, "tag": "latest"},
                                         base=self.backup_url)
        contract_data = self._get({"module": "contract", "action": "getabi", "address": address})
        is_contract = bool(contract_data and contract_data.get("status") == "1")
        balance_str = f"0.000000 {self.cfg.native_token}"
        if balance_data and isinstance(balance_data.get("result"), str):
            try:
                balance_str = f"{int(balance_data['result']) / 1e18:.6f} {self.cfg.native_token}"
            except Exception:
                pass
        return {"balance": balance_str, "is_contract": is_contract}


# 向后兼容别名
EtherscanClient = EVMClient


# ==================== TronScan 查询 ====================
class TronScanClient:
    BASE = "https://apilist.tronscanapi.com/api"

    def get_trc20_transfers(self, tron_addr: str, limit: int = MAX_TX_FETCH) -> List[dict]:
        try:
            url = f"{self.BASE}/token_trc20/transfers"
            r = requests.get(url, params={"relatedAddress": tron_addr, "limit": limit}, timeout=15)
            data = r.json()
            return data.get("token_transfers", [])
        except Exception as e:
            print(f"  [WARN] TronScan TRC20 查询失败: {e}", file=sys.stderr)
            return []

    def get_transactions(self, tron_addr: str, limit: int = MAX_TX_FETCH) -> List[dict]:
        try:
            url = f"{self.BASE}/transaction"
            r = requests.get(url, params={"address": tron_addr, "limit": limit}, timeout=15)
            data = r.json()
            return data.get("data", [])
        except Exception as e:
            print(f"  [WARN] TronScan 交易查询失败: {e}", file=sys.stderr)
            return []

    def get_account_info(self, tron_addr: str) -> dict:
        try:
            r = requests.get(f"{self.BASE}/account", params={"address": tron_addr}, timeout=15)
            data = r.json()
            balance = data.get("balance", 0) / 1_000_000
            return {"balance": f"{balance:.6f} TRX", "is_contract": data.get("accountType", 0) == 1}
        except Exception:
            return {"balance": "N/A", "is_contract": False}


# ==================== 跨链桥对端地址追踪器 ====================
class BridgeTracer:
    def resolve(self, tx_hash: str, method: str, src_address: str,
                dst_chains_hint: list) -> Optional[Dict]:
        if method == "layerzero_api":
            return self._resolve_layerzero(tx_hash, src_address)
        # 其余 method（hop_api/cbridge_api/across_api 等）均未实现，返回 None
        # bridges.json 中对应条目应标记 traceable=false，不会走到这里
        return None

    def _resolve_layerzero(self, tx_hash: str, src_address: str) -> Optional[Dict]:
        try:
            r = requests.get(f"https://api.layerzeroscan.com/tx/{tx_hash}", timeout=10)
            if r.status_code != 200:
                return None
            data = r.json()
            messages = data.get("messages") or data.get("data") or []
            if not messages:
                return None
            msg = messages[0]
            dst_chain_id = (
                msg.get("dstChainId")
                or msg.get("pathway", {}).get("dstEid")
                or (msg.get("destination") or {}).get("chainId")
            )
            dst_tx = (
                msg.get("dstTxHash")
                or (msg.get("destination") or {}).get("tx", {}).get("txHash")
                or ""
            )
            dst_chain = LZ_CHAIN_MAP.get(int(dst_chain_id)) if dst_chain_id else None
            if not dst_chain:
                return None
            dst_address = self._find_token_receiver(dst_tx, dst_chain) or src_address
            return {"dst_chain": dst_chain, "dst_address": dst_address, "dst_tx": dst_tx}
        except Exception as e:
            print(f"  [WARN] LZ Scan 查询失败: {e}", file=sys.stderr)
            return None

    def _find_token_receiver(self, tx_hash: str, chain: str) -> Optional[str]:
        if not tx_hash:
            return None
        cfg = CHAIN_SCANNERS.get(chain, {})
        api = cfg.get("api")
        key = cfg.get("key", "")
        if not api:
            return None
        try:
            params = {"module": "account", "action": "tokentx",
                      "txhash": tx_hash, "page": 1, "offset": 5}
            if key:
                params["apikey"] = key
            r = requests.get(api, params=params, timeout=10)
            txs = r.json().get("result", [])
            if isinstance(txs, list) and txs:
                return normalize(txs[0].get("to", ""))
        except Exception:
            pass
        return None


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
    note: str = ""


@dataclass
class RiskReport:
    address: str
    chain: str               # 主链（或 "multi-evm"）
    tron_address: str = ""
    is_blacklisted: bool = False
    blacklist_time: str = ""

    # 评分结果
    risk_score: int = 0
    risk_level: str = "LOW"
    taint_ratio: float = 0.0
    received_exposure: float = 0.0
    sent_exposure: float = 0.0

    # 基础统计（跨链合计）
    account_info: dict = field(default_factory=dict)
    total_inflow_usdt: float = 0.0
    total_outflow_usdt: float = 0.0
    total_counterparties: int = 0
    total_transactions: int = 0

    # 多链明细
    chains_analyzed: List[str] = field(default_factory=list)
    per_chain_inflow: Dict[str, float] = field(default_factory=dict)
    per_chain_outflow: Dict[str, float] = field(default_factory=dict)

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

    warnings: List[str] = field(default_factory=list)


# ==================== 核心分析引擎 ====================
class AMLAnalyzer:
    def __init__(self, blacklist: Dict[str, Dict],
                 evm_clients: Dict[str, EVMClient],
                 tronscan: TronScanClient,
                 tracer: BridgeTracer = None,
                 time_window_days: int = 0):
        self.blacklist = blacklist
        self.evm_clients = evm_clients   # {chain_name: EVMClient}
        self.tron = tronscan
        self.tracer = tracer or BridgeTracer()
        self.time_window_days = time_window_days

    # ---------- USDT 余额一致性校验 ----------
    def _check_balance_consistency(self, address: str, token_txs: List[dict],
                                   client: EVMClient, chain_cfg: ChainConfig) -> dict:
        """
        查链上实际 USDT 余额，与历史转账记录的收支差对比。
        差异过大说明存在未追踪的资金流动。
        仅在 MAX_TX_FETCH 未截断时结果可信。
        """
        addr_norm = normalize(address)
        balance_data = client._get({
            "module": "account", "action": "tokenbalance",
            "contractaddress": chain_cfg.usdt_contract,
            "address": address,
            "tag": "latest",
        })
        actual_balance = 0.0
        if balance_data and isinstance(balance_data.get("result"), str):
            try:
                actual_balance = int(balance_data["result"]) / 1e6
            except Exception:
                pass

        total_in = 0.0
        total_out = 0.0
        tx_count = 0
        for tx in token_txs:
            symbol = tx.get("tokenSymbol", "")
            if "USDT" not in symbol.upper():
                continue
            f = normalize(tx.get("from", ""))
            t = normalize(tx.get("to", "") or "")
            try:
                decimals = int(tx.get("tokenDecimal", "6") or "6")
                val = int(tx.get("value", "0") or "0") / (10 ** decimals)
            except Exception:
                val = 0.0
            if t == addr_norm:
                total_in += val
            elif f == addr_norm:
                total_out += val
            tx_count += 1

        expected = total_in - total_out
        discrepancy = actual_balance - expected
        discrepancy_pct = abs(discrepancy) / max(total_in, 1.0) * 100
        is_fast_transit = (
            total_in > 10_000
            and actual_balance < total_in * 0.05
            and total_out > total_in * 0.9
        )
        is_unexplained_gap = (
            abs(discrepancy) > 5_000
            and discrepancy_pct > 20
            and tx_count >= 5
        )
        return {
            "actual_usdt_balance": round(actual_balance, 2),
            "total_in": round(total_in, 2),
            "total_out": round(total_out, 2),
            "expected_balance": round(expected, 2),
            "discrepancy": round(discrepancy, 2),
            "discrepancy_pct": round(discrepancy_pct, 1),
            "is_fast_transit": is_fast_transit,
            "is_unexplained_gap": is_unexplained_gap,
            "tx_count_used": tx_count,
            "truncated": len(token_txs) >= MAX_TX_FETCH,
        }

    # ---------- 目标链 1 跳黑名单检测 ----------
    def _check_dst_hop1(self, address: str, chain: str) -> List[dict]:
        cfg = CHAIN_SCANNERS.get(chain, {})
        api = cfg.get("api")
        key = cfg.get("key", "")
        if not api:
            return []
        hits: List[dict] = []
        addr_norm = normalize(address)
        try:
            for action in ["txlist", "tokentx"]:
                params = {
                    "module": "account", "action": action,
                    "address": address, "sort": "desc", "offset": 50, "page": 1,
                }
                if key:
                    params["apikey"] = key
                time.sleep(REQUEST_DELAY)
                r = requests.get(api, params=params, timeout=10)
                txs = r.json().get("result", [])
                if not isinstance(txs, list):
                    continue
                for tx in txs:
                    f = normalize(tx.get("from", ""))
                    t = normalize(tx.get("to", "") or "")
                    if f == addr_norm:
                        other = t
                        direction = "OUT"
                    elif t == addr_norm:
                        other = f
                        direction = "IN"
                    else:
                        continue
                    if other and other != addr_norm and other in self.blacklist:
                        info = self.blacklist[other]
                        entry = {"address": other, "chain": info["chain"],
                                 "blacklist_time": info["time"], "direction": direction}
                        if entry not in hits:
                            hits.append(entry)
        except Exception as e:
            print(f"  [WARN] 目标链({chain})查询失败: {e}", file=sys.stderr)
        return hits[:5]

    # ---------- USDT getLogs 查询（捕获 transferFrom 类型转账）----------
    def _get_usdt_logs(self, address: str, client: EVMClient,
                       chain_cfg: ChainConfig) -> List[dict]:
        TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        addr_norm = normalize(address)
        padded = "0x" + "0" * 24 + addr_norm[2:]
        results = []
        backup = client.backup_url

        for role, topic_key in [("sender", "topic1"), ("receiver", "topic2")]:
            time.sleep(REQUEST_DELAY)
            params = {
                "module": "logs", "action": "getLogs",
                "address": chain_cfg.usdt_contract,
                "topic0": TRANSFER_TOPIC,
                topic_key: padded,
                "topic0_1_opr" if role == "sender" else "topic0_2_opr": "and",
                "fromBlock": 0, "toBlock": 99999999,
                "page": 1, "offset": MAX_TX_FETCH,
            }
            try:
                base = backup if backup else client.primary_url
                r = requests.get(base, params=params, timeout=15)
                logs = r.json().get("result", [])
                if isinstance(logs, list):
                    for log in logs:
                        log["_role"] = role
                    results.extend(logs)
            except Exception:
                pass

        return results

    # ---------- 单条 EVM 链分析（1-hop + 2-hop）----------
    def _analyze_evm_chain(self, address: str, report: RiskReport,
                           chain_cfg: ChainConfig, client: EVMClient,
                           chain_name: str):
        addr_norm = normalize(address)
        chain_label = chain_cfg.name

        # 时间窗口截止时间（0 = 不限制）
        time_cutoff = 0
        if self.time_window_days > 0:
            time_cutoff = int(time.time()) - self.time_window_days * 86400

        print(f"  [{chain_label}] 查询交易记录（最多 {MAX_PAGES} 页 × {PAGE_SIZE} 条）...")
        normal_txs = client.get_normal_txs(address, limit=PAGE_SIZE,
                                           max_pages=MAX_PAGES, time_cutoff=time_cutoff)
        token_txs  = client.get_token_transfers(address, limit=PAGE_SIZE,
                                                max_pages=MAX_PAGES, time_cutoff=time_cutoff)

        if len(normal_txs) >= PAGE_SIZE * MAX_PAGES:
            report.warnings.append(
                f"[{chain_label}] 普通交易达到上限 {PAGE_SIZE*MAX_PAGES} 条，历史可能不完整（可增大 MAX_PAGES）"
            )
        if len(token_txs) >= PAGE_SIZE * MAX_PAGES:
            report.warnings.append(
                f"[{chain_label}] Token转账达到上限 {PAGE_SIZE*MAX_PAGES} 条，历史可能不完整"
            )

        usdt_logs = []
        if len(normal_txs) == 0 and len(token_txs) == 0:
            print(f"  [{chain_label}] txlist/tokentx 无结果，尝试 USDT getLogs...")
            usdt_logs = self._get_usdt_logs(address, client, chain_cfg)
            if usdt_logs:
                print(f"  [{chain_label}] getLogs 获取到 {len(usdt_logs)} 条 USDT Transfer 事件")

        # 仅主链记录 account_info（避免多链重复）
        if not report.account_info:
            time.sleep(REQUEST_DELAY)
            report.account_info = client.get_account_info(address)

        # 去重
        _seen: Set[tuple] = set()
        all_txs = []
        for tx in normal_txs + token_txs:
            k = (tx.get("hash", ""),
                 normalize(tx.get("from", "")),
                 normalize(tx.get("to", "") or tx.get("contractAddress", "")))
            if k not in _seen:
                _seen.add(k)
                all_txs.append(tx)

        # 时间窗口已在分页拉取时处理（time_cutoff 早停），getLogs 结果单独过滤
        if time_cutoff > 0 and usdt_logs:
            before = len(usdt_logs)
            usdt_logs = [lg for lg in usdt_logs if int(lg.get("timeStamp", 0)) >= time_cutoff]
            if before != len(usdt_logs):
                print(f"  [{chain_label}] getLogs 时间过滤: {before}→{len(usdt_logs)}")

        report.total_transactions += len(all_txs) + len(usdt_logs)
        print(f"  [{chain_label}] {len(normal_txs)} 普通 + {len(token_txs)} Token"
              + (f" + {len(usdt_logs)} USDT事件" if usdt_logs else ""))

        PROTOCOL_CONTRACTS = {
            chain_cfg.usdt_contract,
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC ETH
            "0x0000000000000000000000000000000000000000",
        }

        counterparties: Set[str] = set()
        counterparty_dir_stats: Dict[str, Dict[str, int]] = {}
        counterparty_stats: Dict[str, Dict] = {}

        # 风险积累器：key = (counterparty, risk_type, via_address)
        risky_accum: Dict[tuple, dict] = {}

        def _add_risk(cp: str, risk_type: str, category: str, weight: float,
                      direction: str, usdt_amt: float, tx_hash: str, ts: str,
                      hop: int = 1, via: str = ""):
            key = (cp, risk_type, via)
            if key not in risky_accum:
                risky_accum[key] = {
                    "category": category, "category_weight": weight,
                    "counterparty": cp, "in_usdt": 0.0, "out_usdt": 0.0,
                    "tx_hashes": [], "timestamps": [], "hop": hop, "via_address": via,
                }
            if direction == "IN":
                risky_accum[key]["in_usdt"] += usdt_amt
            else:
                risky_accum[key]["out_usdt"] += usdt_amt
            if tx_hash and len(risky_accum[key]["tx_hashes"]) < 5:
                risky_accum[key]["tx_hashes"].append(tx_hash)
                risky_accum[key]["timestamps"].append(ts)

        # ── 遍历所有交易 ──────────────────────────────────────────────
        chain_inflow = 0.0
        chain_outflow = 0.0

        for tx in all_txs:
            frm = normalize(tx.get("from", ""))
            to  = normalize(tx.get("to", "") or tx.get("contractAddress", ""))
            if frm == addr_norm:
                other, direction = to, "OUT"
            elif to == addr_norm:
                other, direction = frm, "IN"
            else:
                continue
            if not other or other == addr_norm or other in PROTOCOL_CONTRACTS:
                continue

            sym = tx.get("tokenSymbol", "ETH").upper()
            is_usdt = "USDT" in sym
            try:
                dec = int(tx.get("tokenDecimal", "18") or "18")
                amt = int(tx.get("value", "0") or "0") / (10 ** dec)
            except Exception:
                amt = 0.0
            usdt_amt = amt if is_usdt else 0.0

            if is_usdt:
                if direction == "IN":
                    chain_inflow += amt
                    report.total_inflow_usdt += amt
                else:
                    chain_outflow += amt
                    report.total_outflow_usdt += amt

            counterparties.add(other)
            counterparty_dir_stats.setdefault(other, {"IN": 0, "OUT": 0})[direction] += 1
            s = counterparty_stats.setdefault(other, {"count": 0, "total_value": 0.0, "max_value": 0.0})
            s["count"] += 1
            if is_usdt:
                s["total_value"] += amt
                s["max_value"] = max(s["max_value"], amt)

            tx_hash = tx.get("hash", "")
            ts = tx.get("timeStamp", "")

            for chk, chk_dir in [(to, "OUT" if frm == addr_norm else "IN"),
                                  (frm, "IN"  if frm != addr_norm else "OUT")]:
                if not chk or chk == addr_norm or chk in PROTOCOL_CONTRACTS:
                    continue

                if chk in self.blacklist:
                    _add_risk(chk, "blacklist", "blacklist",
                              CATEGORY_WEIGHTS["blacklist"], chk_dir, usdt_amt, tx_hash, ts)

                if chk in MIXER_CONTRACTS:
                    report.mixer_interactions.append({
                        "mixer": MIXER_CONTRACTS[chk], "contract": chk,
                        "tx": tx_hash, "direction": chk_dir, "chain": chain_name,
                    })
                    _add_risk(chk, "mixer", "mixer",
                              CATEGORY_WEIGHTS["mixer"], chk_dir, usdt_amt, tx_hash, ts)

                bridge_info = BRIDGE_REGISTRY.get(chk)
                if bridge_info:
                    entry = {
                        "bridge": bridge_info["name"], "contract": chk,
                        "tx": tx_hash, "direction": chk_dir,
                        "token": sym, "traceable": bridge_info["traceable"],
                        "method": bridge_info["method"], "dst_chains": bridge_info["dst_chains"],
                        "chain": chain_name,
                    }
                    if bridge_info["traceable"]:
                        report.bridge_interactions.append(entry)
                    else:
                        report.opaque_bridge_interactions.append(entry)
                        _add_risk(chk, "opaque_bridge", "opaque_bridge",
                                  CATEGORY_WEIGHTS["opaque_bridge"], chk_dir, usdt_amt, tx_hash, ts)

                if chk in HIGH_RISK_EXCHANGES:
                    report.high_risk_exchanges.append({
                        "exchange": HIGH_RISK_EXCHANGES_FLAT[chk], "contract": chk,
                        "tx": tx_hash, "direction": chk_dir, "chain": chain_name,
                    })
                    _add_risk(chk, "high_risk_exchange", "high_risk_exchange",
                              CATEGORY_WEIGHTS["high_risk_exchange"], chk_dir, usdt_amt, tx_hash, ts)

        # USDT getLogs 补充对手方
        for log in usdt_logs:
            topics = log.get("topics", [])
            if len(topics) < 3:
                continue
            log_from = "0x" + topics[1][-40:]
            log_to   = "0x" + topics[2][-40:]
            role = log.get("_role", "")
            other = log_to if role == "sender" else log_from
            direction = "OUT" if role == "sender" else "IN"
            if other and other != addr_norm:
                counterparties.add(other)
                counterparty_dir_stats.setdefault(other, {"IN": 0, "OUT": 0})[direction] += 1
                counterparty_stats.setdefault(other, {"count": 0, "total_value": 0.0, "max_value": 0.0})["count"] += 1

        report.total_counterparties += len(counterparties)
        report.per_chain_inflow[chain_name] = round(chain_inflow, 2)
        report.per_chain_outflow[chain_name] = round(chain_outflow, 2)
        print(f"  [{chain_label}] 1-hop 共 {len(counterparties)} 个对手方 | "
              f"USDT 流入 {chain_inflow:,.2f} / 流出 {chain_outflow:,.2f}")

        # ── 风险积累器 → RiskIndicator（1-hop）────────────────────────
        for (cp, risk_type, via), data in risky_accum.items():
            hop_d = HOP_DECAY[data["hop"]]
            for d, amt in [("IN", data["in_usdt"]), ("OUT", data["out_usdt"])]:
                if amt > 0:
                    report.indicators.append(RiskIndicator(
                        indicator_type=f"{risk_type}_{'received' if d == 'IN' else 'sent'}",
                        category=data["category"],
                        category_weight=data["category_weight"],
                        counterparty=cp, direction=d, amount_usdt=amt,
                        hop=data["hop"], hop_decay=hop_d,
                        tx_hashes=data["tx_hashes"], timestamps=data["timestamps"],
                        via_address=data["via_address"],
                        chain=chain_name,
                    ))
            if data["in_usdt"] == 0.0 and data["out_usdt"] == 0.0:
                report.indicators.append(RiskIndicator(
                    indicator_type=f"{risk_type}_no_usdt",
                    category=data["category"],
                    category_weight=data["category_weight"],
                    counterparty=cp, direction="UNKNOWN", amount_usdt=0.0,
                    hop=data["hop"], hop_decay=hop_d,
                    tx_hashes=data["tx_hashes"], timestamps=data["timestamps"],
                    via_address=data["via_address"],
                    chain=chain_name,
                    note="无 USDT 金额，仅记录关联关系",
                ))

        # ── top_counterparties（展示用，只取当前链）──────────────────────
        _excl = (PROTOCOL_CONTRACTS | ALL_BRIDGE_ADDRS
                 | set(MIXER_CONTRACTS) | set(HIGH_RISK_EXCHANGES) | KNOWN_DEX_ADDRS)
        scored = [(a, s, s["max_value"]*0.6 + s["total_value"]*0.3 + s["count"]*0.1)
                  for a, s in counterparty_stats.items()
                  if a not in _excl and a not in self.blacklist]
        scored.sort(key=lambda x: x[2], reverse=True)
        for a, s, _ in scored[:10]:
            report.top_counterparties.append({
                "address": a, "tx_count": s["count"],
                "total_value": round(s["total_value"], 4), "max_value": round(s["max_value"], 4),
                "in_count": counterparty_dir_stats.get(a, {}).get("IN", 0),
                "out_count": counterparty_dir_stats.get(a, {}).get("OUT", 0),
                "chain": chain_name,
            })

        # ── 2-hop 分析 ───────────────────────────────────────────────
        # 遍历目标地址的普通对手方（非已知协议地址），检测它们是否
        # 直接与黑名单/混币器/不透明桥/高风险交易所交互。
        # 衰减：hop1=1.0, hop2=0.3（每多一跳，证据强度显著下降）
        _protocol_excl = (set(self.blacklist) | ALL_BRIDGE_ADDRS
                          | set(MIXER_CONTRACTS) | set(HIGH_RISK_EXCHANGES) | KNOWN_DEX_ADDRS)

        def _check_txs_for_risk(txs, src_addr, hop, via1, via2=""):
            """遍历 txs，将命中风险类别的对手方写入 risky_accum。"""
            for tx in txs:
                t = normalize(tx.get("to", "") or "")
                f = normalize(tx.get("from", "") or "")
                if f == src_addr and t and t != src_addr:
                    other, d = t, "OUT"
                elif t == src_addr and f and f != src_addr:
                    other, d = f, "IN"
                else:
                    continue
                if not other or other == addr_norm or other in PROTOCOL_CONTRACTS:
                    continue
                sym = tx.get("tokenSymbol", "").upper()
                try:
                    dec = int(tx.get("tokenDecimal", "18") or "18")
                    amt = int(tx.get("value", "0") or "0") / (10 ** dec)
                except Exception:
                    amt = 0.0
                usdt = amt if "USDT" in sym else 0.0
                h = tx.get("hash", "")
                ts = tx.get("timeStamp", "")
                via = via2 if via2 else via1

                if other in self.blacklist:
                    _add_risk(other, "blacklist", "blacklist",
                              CATEGORY_WEIGHTS["blacklist"], d, usdt, h, ts, hop=hop, via=via)
                if other in MIXER_CONTRACTS:
                    _add_risk(other, "mixer", "mixer",
                              CATEGORY_WEIGHTS["mixer"], d, usdt, h, ts, hop=hop, via=via)
                if other in OPAQUE_BRIDGE_ADDRS:
                    _add_risk(other, "opaque_bridge", "opaque_bridge",
                              CATEGORY_WEIGHTS["opaque_bridge"], d, usdt, h, ts, hop=hop, via=via)
                if other in ALL_BRIDGE_ADDRS and other not in OPAQUE_BRIDGE_ADDRS:
                    _add_risk(other, "transparent_bridge", "transparent_bridge",
                              CATEGORY_WEIGHTS["transparent_bridge"], d, usdt, h, ts, hop=hop, via=via)
                if other in HIGH_RISK_EXCHANGES_FLAT:
                    _add_risk(other, "high_risk_exchange", "high_risk_exchange",
                              CATEGORY_WEIGHTS["high_risk_exchange"], d, usdt, h, ts, hop=hop, via=via)

        if HOP2_ENABLED and counterparties:
            # 2-hop 中间节点：排除已知高风险地址（它们已在 1-hop 检测到）
            hop2_nodes = [cp for cp in counterparties if cp not in _protocol_excl][:5]
            if hop2_nodes:
                print(f"  [{chain_label}] 2-hop 分析 {len(hop2_nodes)} 个中间节点...")

            for cp in hop2_nodes:
                time.sleep(REQUEST_DELAY)
                cp_txs = client.get_normal_txs(cp, limit=50)
                cp_tok = client.get_token_transfers(cp, limit=50)
                _check_txs_for_risk(cp_txs + cp_tok, cp, hop=2, via1=cp)

        # 将 risky_accum 中 hop>=2 的记录转为 RiskIndicator
        for (cp, risk_type, via), data in risky_accum.items():
            if data["hop"] < 2:
                continue
            if cp == addr_norm:  # 不应出现，防御性过滤
                continue
            hop_d = HOP_DECAY[data["hop"]]
            added = False
            for d, amt in [("IN", data["in_usdt"]), ("OUT", data["out_usdt"])]:
                if amt > 0 and not added:
                    report.indicators.append(RiskIndicator(
                        indicator_type=f"{risk_type}_hop{data['hop']+1}",
                        category=data["category"],
                        category_weight=data["category_weight"],
                        counterparty=cp, direction=d, amount_usdt=amt,
                        hop=data["hop"], hop_decay=hop_d,
                        tx_hashes=data["tx_hashes"], timestamps=data["timestamps"],
                        via_address=via, chain=chain_name,
                    ))
                    added = True
            if not added:
                report.indicators.append(RiskIndicator(
                    indicator_type=f"{risk_type}_hop{data['hop']+1}_no_usdt",
                    category=data["category"],
                    category_weight=data["category_weight"],
                    counterparty=cp, direction="UNKNOWN", amount_usdt=0.0,
                    hop=data["hop"], hop_decay=hop_d,
                    tx_hashes=data["tx_hashes"], timestamps=data["timestamps"],
                    via_address=via, chain=chain_name, note="无 USDT 金额",
                ))

        # ── 透明桥跨链追踪 ─────────────────────────────────────────────
        if BRIDGE_TRACE_ENABLED and report.bridge_interactions:
            out_bridges = [b for b in report.bridge_interactions
                           if b.get("direction") == "OUT" and b.get("chain") == chain_name]
            seen_tx: Set[str] = set()
            if out_bridges:
                print(f"  [{chain_label}] 透明桥跨链追踪（{min(len(out_bridges), 5)} 笔）...")
            for b in out_bridges[:5]:
                tx_hash = b.get("tx", "")
                if not tx_hash or tx_hash in seen_tx:
                    continue
                seen_tx.add(tx_hash)
                time.sleep(REQUEST_DELAY)
                result = self.tracer.resolve(
                    tx_hash=tx_hash, method=b.get("method", ""),
                    src_address=addr_norm, dst_chains_hint=b.get("dst_chains", []),
                )
                if not result:
                    print(f"  [{chain_label}]   {b['bridge']}: 无法解析对端地址")
                    continue
                dst_addr  = normalize(result.get("dst_address", ""))
                dst_chain = result.get("dst_chain", "")
                finding = {
                    "bridge": b["bridge"], "src_tx": tx_hash,
                    "dst_chain": dst_chain, "dst_address": dst_addr,
                    "dst_tx": result.get("dst_tx", ""),
                    "blacklisted": False, "blacklist_info": {}, "hop1_blacklisted": [],
                    "src_chain": chain_name,
                }
                if dst_addr and dst_addr in self.blacklist:
                    finding["blacklisted"] = True
                    finding["blacklist_info"] = self.blacklist[dst_addr]
                    print(f"  [!!!] 桥接目标命中黑名单: {dst_addr} ({dst_chain})")
                    report.indicators.append(RiskIndicator(
                        indicator_type="cross_chain_blacklist",
                        category="blacklist",
                        category_weight=CATEGORY_WEIGHTS["blacklist"],
                        counterparty=dst_addr, direction="OUT", amount_usdt=0.0,
                        hop=1, hop_decay=HOP_DECAY[1],
                        tx_hashes=[tx_hash], timestamps=[],
                        chain=chain_name,
                        note=f"跨链对端黑名单 ({dst_chain})",
                    ))
                elif dst_addr and dst_chain and dst_chain != chain_name:
                    hop1 = self._check_dst_hop1(dst_addr, dst_chain)
                    if hop1:
                        finding["hop1_blacklisted"] = hop1
                        print(f"  [!] 桥对端 {dst_chain}:{dst_addr[:16]}... 1跳有 {len(hop1)} 个黑名单")
                        report.indicators.append(RiskIndicator(
                            indicator_type="cross_chain_hop1_blacklist",
                            category="transparent_bridge_with_bl",
                            category_weight=CATEGORY_WEIGHTS["transparent_bridge_with_bl"],
                            counterparty=dst_addr, direction="OUT", amount_usdt=0.0,
                            hop=2, hop_decay=HOP_DECAY[2],
                            tx_hashes=[tx_hash], timestamps=[],
                            chain=chain_name,
                            note=f"跨链对端1跳黑名单 ({dst_chain})",
                        ))
                    else:
                        report.indicators.append(RiskIndicator(
                            indicator_type="transparent_bridge",
                            category="transparent_bridge",
                            category_weight=CATEGORY_WEIGHTS["transparent_bridge"],
                            counterparty=dst_addr, direction="OUT", amount_usdt=0.0,
                            hop=1, hop_decay=HOP_DECAY[1],
                            tx_hashes=[tx_hash], timestamps=[],
                            chain=chain_name,
                            note=f"透明桥无黑名单 ({dst_chain})",
                        ))
                report.cross_chain_findings.append(finding)

    # ---------- Tron 分析 ----------
    def _analyze_tron(self, address: str, report: RiskReport):
        tron_b58 = hex_to_tron_base58(address)
        report.tron_address = tron_b58
        print(f"  [TRON] 地址转换: {address} → {tron_b58}")
        trc20_txs = self.tron.get_trc20_transfers(tron_b58)
        trx_txs   = self.tron.get_transactions(tron_b58)
        report.account_info = self.tron.get_account_info(tron_b58)
        report.total_transactions = len(trc20_txs) + len(trx_txs)
        print(f"  [TRON] {len(trc20_txs)} TRC20 + {len(trx_txs)} TRX")

        counterparties: Set[str] = set()
        addr_b58_lower = tron_b58.lower()
        for tx in trc20_txs:
            f = (tx.get("from_address") or tx.get("transferFromAddress") or "").lower()
            t = (tx.get("to_address")   or tx.get("transferToAddress")   or "").lower()
            for a in [f, t]:
                if a and a != addr_b58_lower:
                    counterparties.add(a)
        for tx in trx_txs:
            for a in [(tx.get("ownerAddress") or "").lower(), (tx.get("toAddress") or "").lower()]:
                if a and a != addr_b58_lower:
                    counterparties.add(a)

        report.total_counterparties = len(counterparties)
        print(f"  [TRON] {len(counterparties)} 个对手方")

        bl_tron = {a: info for a, info in self.blacklist.items() if info.get("chain") == "tron"}
        for cp_b58 in counterparties:
            try:
                cp_hex = _tron_b58_to_hex(cp_b58)
                if cp_hex and cp_hex in bl_tron:
                    info = bl_tron[cp_hex]
                    report.indicators.append(RiskIndicator(
                        indicator_type="blacklist_received",
                        category="blacklist",
                        category_weight=CATEGORY_WEIGHTS["blacklist"],
                        counterparty=cp_b58, direction="IN", amount_usdt=0.0,
                        hop=1, hop_decay=HOP_DECAY[1],
                        tx_hashes=[], timestamps=[],
                        chain="tron",
                        note=f"Tron 黑名单，封禁: {info['time']}",
                    ))
            except Exception:
                pass

    # ---------- 风险评分（污染比例模型）----------
    def _calculate_risk(self, report: RiskReport):
        if report.is_blacklisted:
            report.risk_score = 100
            report.risk_level = "CRITICAL"
            report.taint_ratio = 1.0
            report.received_exposure = 1.0
            report.sent_exposure = 1.0
            return

        total_in  = report.total_inflow_usdt
        total_out = report.total_outflow_usdt
        total_flow = total_in + total_out

        received_taint = 0.0
        sent_taint     = 0.0
        presence_only: List[RiskIndicator] = []

        for ind in report.indicators:
            if ind.amount_usdt == 0.0:
                presence_only.append(ind)
                continue
            effective = ind.amount_usdt * ind.category_weight * ind.hop_decay
            if ind.direction == "IN" and total_in > 0:
                received_taint += effective / total_in
            elif ind.direction == "OUT" and total_out > 0:
                sent_taint += effective / total_out

        received_taint = min(received_taint, 1.0)
        sent_taint     = min(sent_taint, 1.0)

        # ── 步骤1：基础污染比例（Haircut Model）──────────────────────────
        # 取收入侧和转出侧的较高者作为主污染率
        base_taint = max(received_taint, sent_taint)

        # ── 步骤2：双向污染加成 ───────────────────────────────────────────
        # 两侧都有污染 → 资金进出都经过风险方 → 该地址在洗钱链路中间
        bilateral_bonus_raw = min(received_taint, sent_taint) * 0.4
        taint_ratio = min(base_taint + bilateral_bonus_raw, 1.0)

        if total_flow == 0 and presence_only:
            taint_ratio = min(
                sum(ind.category_weight * ind.hop_decay * 0.5 for ind in presence_only), 1.0
            )
            report.warnings.append("无 USDT 交易记录，评分基于关联关系而非污染比例，准确度受限")
        elif presence_only and taint_ratio == 0.0:
            taint_ratio = min(
                sum(ind.category_weight * ind.hop_decay * 0.3 for ind in presence_only), 0.5
            )

        report.received_exposure = round(received_taint, 4)
        report.sent_exposure     = round(sent_taint, 4)
        report.taint_ratio       = round(taint_ratio, 4)
        base_score = min(int(taint_ratio * 100), 100)

        # ── 步骤3：类别最低分保障（floor）────────────────────────────────
        # 行为本身是风险信号，不论金额大小
        hop1_cats = {ind.category for ind in report.indicators if ind.hop == 1 and ind.amount_usdt > 0}
        hop2_cats = {ind.category for ind in report.indicators if ind.hop == 2 and ind.amount_usdt > 0}
        pres1_cats = {ind.category for ind in presence_only if ind.hop == 1}

        floor = 0
        floor_reason = ""
        if "blacklist"         in hop1_cats: floor, floor_reason = max(floor, 55), "1-hop 直接收发黑名单 USDT"
        if "mixer"             in hop1_cats: floor, floor_reason = max(floor, 50), "1-hop 直接使用混币器"
        if "opaque_bridge"     in hop1_cats: floor, floor_reason = max(floor, 35), "1-hop 使用不透明桥"
        if "high_risk_exchange" in hop1_cats: floor, floor_reason = max(floor, 20), "1-hop 高风险交易所"
        if "blacklist" in hop2_cats or "mixer" in hop2_cats:
            if floor < 20: floor, floor_reason = 20, "2-hop 间接关联黑名单/混币器"
        if "blacklist" in pres1_cats or "mixer" in pres1_cats:
            if floor < 15: floor, floor_reason = 15, "1-hop 关联黑名单/混币器（无USDT金额）"

        # ── 步骤4：多类别信号加分 ─────────────────────────────────────────
        # 同时命中多种类别说明资金路径刻意设计（混币+桥+黑名单并用）
        all_hop1_cats = {ind.category for ind in report.indicators if ind.hop == 1}
        multi_cat_bonus = max(0, len(all_hop1_cats) - 1) * 5

        final_score = min(max(base_score, floor) + multi_cat_bonus, 100)
        report.risk_score = final_score

        if report.risk_score >= 80:
            report.risk_level = "CRITICAL"
        elif report.risk_score >= 45:
            report.risk_level = "HIGH"
        elif report.risk_score >= 20:
            report.risk_level = "MEDIUM"
        else:
            report.risk_level = "LOW"

        # ── 评分分解（供报告展示）────────────────────────────────────────
        report.score_breakdown = {
            "received_taint_pct": round(received_taint * 100, 1),
            "sent_taint_pct":     round(sent_taint * 100, 1),
            "bilateral_bonus":    round(bilateral_bonus_raw * 100, 1),
            "base_score":         base_score,
            "floor":              floor,
            "floor_reason":       floor_reason,
            "multi_cat_bonus":    multi_cat_bonus,
            "final_score":        final_score,
            "hop1_categories":    sorted(all_hop1_cats),
            "hop2_categories":    sorted(hop2_cats),
        }

    # ---------- 主入口 ----------
    def analyze(self, address: str, chain: Optional[str] = None,
                chains: Optional[List[str]] = None) -> RiskReport:
        """
        chain  : 指定单链（"ethereum"/"bsc"/... 或 "tron"），None = 自动
        chains : 指定多链列表（优先级高于 chain），None = 自动
        """
        addr_norm = normalize(address)

        # 判断链类型
        if chain == "tron":
            run_tron = True
            evm_chains_to_run = []
        elif chains:
            run_tron = False
            evm_chains_to_run = [c for c in chains if c in EVM_CHAIN_REGISTRY]
        elif chain and chain in EVM_CHAIN_REGISTRY:
            run_tron = False
            evm_chains_to_run = [chain]
        elif chain is None:
            # 自动检测：黑名单中标记为 tron，或地址不以 0x 开头
            bl_chain = self.blacklist.get(addr_norm, {}).get("chain", "")
            if bl_chain == "tron" or not address.startswith("0x"):
                run_tron = True
                evm_chains_to_run = []
            else:
                run_tron = False
                # 默认：只跑有 API key 的链（避免因无 key 而无效请求）
                evm_chains_to_run = [
                    n for n, cfg in EVM_CHAIN_REGISTRY.items()
                    if cfg.api_key or cfg.backup_url
                ]
                # 至少跑 ethereum
                if not evm_chains_to_run:
                    evm_chains_to_run = ["ethereum"]
        else:
            run_tron = False
            evm_chains_to_run = ["ethereum"]

        # 决定 report 的主链标签
        if run_tron:
            primary_chain = "tron"
        elif len(evm_chains_to_run) == 1:
            primary_chain = evm_chains_to_run[0]
        else:
            primary_chain = "multi-evm"

        report = RiskReport(address=addr_norm, chain=primary_chain)

        print(f"\n{'='*60}")
        print(f"分析地址: {addr_norm}")
        print(f"链类型:   {primary_chain}")
        print(f"{'='*60}")

        if addr_norm in self.blacklist:
            info = self.blacklist[addr_norm]
            report.is_blacklisted = True
            report.blacklist_time = info["time"]
            report.warnings.append(f"[!] 该地址已在 USDT 黑名单（封禁时间: {info['time']}）")
            print(f"  [!!!] 直接命中黑名单！封禁时间: {info['time']}")

        if run_tron:
            self._analyze_tron(addr_norm, report)
            report.chains_analyzed = ["tron"]
        else:
            for chain_name in evm_chains_to_run:
                client = self.evm_clients.get(chain_name)
                cfg = EVM_CHAIN_REGISTRY.get(chain_name)
                if client is None or cfg is None:
                    print(f"  [WARN] 链 {chain_name} 未配置，跳过")
                    continue
                self._analyze_evm_chain(addr_norm, report, cfg, client, chain_name)
                report.chains_analyzed.append(chain_name)

        self._calculate_risk(report)
        return report


# ==================== Tron Base58 转 Hex ====================
_B58_MAP = {chr(_B58_ALPHABET[i]): i for i in range(58)}

def _tron_b58_to_hex(b58_addr: str) -> Optional[str]:
    try:
        num = 0
        for c in b58_addr:
            num = num * 58 + _B58_MAP[c]
        raw = num.to_bytes(25, "big")
        payload = raw[:21]
        checksum = raw[21:]
        expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        if checksum != expected:
            return None
        return "0x" + payload[1:].hex()
    except Exception:
        return None


# ==================== 报告输出 ====================
LEVEL_COLORS = {
    "LOW":      "\033[92m",
    "MEDIUM":   "\033[93m",
    "HIGH":     "\033[91m",
    "CRITICAL": "\033[95m",
    "RESET":    "\033[0m",
}


def print_report(report: RiskReport, use_color: bool = True):
    c  = LEVEL_COLORS if use_color else {k: "" for k in LEVEL_COLORS}
    lc = c.get(report.risk_level, "")
    rc = c["RESET"]

    print(f"\n{'='*60}")
    print(f"  AML 风险分析报告")
    print(f"{'='*60}")
    print(f"  地址:     {report.address}")
    if report.tron_address:
        print(f"  Tron地址: {report.tron_address}")
    print(f"  链:       {report.chain}")
    if len(report.chains_analyzed) > 1:
        print(f"  已分析链: {', '.join(report.chains_analyzed)}")
    print(f"  余额:     {report.account_info.get('balance', 'N/A')}")
    print(f"  是否合约: {'是' if report.account_info.get('is_contract') else '否'}")
    print(f"  交易数量: {report.total_transactions}  |  对手方: {report.total_counterparties}")
    print(f"  USDT 流入: {report.total_inflow_usdt:>12,.2f}  |  流出: {report.total_outflow_usdt:>12,.2f}")

    # 多链分链明细
    if len(report.chains_analyzed) > 1:
        print(f"  {'─'*54}")
        print(f"  各链 USDT 流量:")
        for cn in report.chains_analyzed:
            inf = report.per_chain_inflow.get(cn, 0.0)
            out = report.per_chain_outflow.get(cn, 0.0)
            cfg = EVM_CHAIN_REGISTRY.get(cn)
            label = cfg.name if cfg else cn
            print(f"    {label:<12} 流入 {inf:>10,.2f}  流出 {out:>10,.2f}")

    print()
    print(f"  {'─'*54}")
    print(f"  风险等级:   {lc}{report.risk_level}{rc}")
    print(f"  风险分数:   {lc}{report.risk_score}/100{rc}")
    print(f"  {'─'*54}")

    # 评分分解（可解释性）
    bd = report.score_breakdown
    if bd:
        print(f"  【评分分解】")
        print(f"    收入侧污染:   {bd['received_taint_pct']:>5.1f}%  "
              f"(收到来自风险地址的 USDT 占总流入的比例 × 类别权重)")
        print(f"    转出侧污染:   {bd['sent_taint_pct']:>5.1f}%  "
              f"(转入风险地址的 USDT 占总流出的比例 × 类别权重)")
        if bd['bilateral_bonus'] > 0:
            print(f"    双向加成:    +{bd['bilateral_bonus']:>5.1f}   "
                  f"(进出两侧均有污染，叠加惩罚 min×0.4)")
        print(f"    基础分:       {bd['base_score']:>5}   (污染比例 × 100)")
        if bd['floor'] > bd['base_score']:
            print(f"    类别下限:    >{bd['floor']:>4}   ({bd['floor_reason']})")
        if bd['multi_cat_bonus'] > 0:
            cats = ', '.join(bd['hop1_categories'])
            print(f"    多类别加分:  +{bd['multi_cat_bonus']:>4}   "
                  f"(1-hop 命中 {len(bd['hop1_categories'])} 类: {cats})")
        print(f"    最终得分:     {lc}{bd['final_score']}/100{rc}")
        print(f"  {'─'*54}")

    if report.is_blacklisted:
        print(f"\n  {lc}[!!!] 该地址已被 USDT 直接封禁{rc}")
        print(f"        封禁时间: {report.blacklist_time}")

    if report.warnings:
        print(f"\n  警告:")
        for w in report.warnings:
            print(f"    ⚠ {w}")

    # ── 风险证据明细 ────────────────────────────────────────────────────
    if report.indicators:
        sorted_inds = sorted(report.indicators, key=lambda x: (x.hop, -x.amount_usdt))
        hop1_inds = [i for i in sorted_inds if i.hop == 1 and i.amount_usdt > 0]
        hop2_inds = [i for i in sorted_inds if i.hop == 2 and i.amount_usdt > 0]
        pres_inds = [i for i in sorted_inds if i.amount_usdt == 0]

        total_in  = report.total_inflow_usdt
        total_out = report.total_outflow_usdt

        # 地址缩写辅助函数
        def _short(addr: str, n: int = 10) -> str:
            return addr[:6] + "..." + addr[-4:] if len(addr) > n else addr

        x = _short(report.address)

        if hop1_inds:
            print(f"\n  {'─'*54}")
            print(f"  1-Hop 风险证据（直接交互，衰减系数 1.0）")
            print(f"  {'─'*54}")
            for ind in hop1_inds:
                basis   = total_in if ind.direction == "IN" else total_out
                contrib = (ind.amount_usdt * ind.category_weight / basis * 100) if basis > 0 else 0
                chain_tag = f"[{ind.chain}] " if ind.chain else ""
                cp = _short(ind.counterparty)
                # 路径：资金流向箭头从来源指向目的地
                if ind.direction == "IN":
                    path = f"{cp} --{ind.amount_usdt:,.0f} USDT--> {x}"
                else:
                    path = f"{x} --{ind.amount_usdt:,.0f} USDT--> {cp}"
                print(f"    {chain_tag}[{ind.category}]  {ind.amount_usdt:>12,.2f} USDT  "
                      f"污染贡献 {contrib:.2f}%")
                print(f"      路径: {path}")
                print(f"      完整地址: {ind.counterparty}")
                if ind.tx_hashes:
                    txs_str = ind.tx_hashes[0][:20] + "..."
                    if len(ind.tx_hashes) > 1:
                        txs_str += f" 等{len(ind.tx_hashes)}笔"
                    print(f"      证据tx:   {txs_str}")

        if hop2_inds:
            print(f"\n  {'─'*54}")
            print(f"  2-Hop 风险证据（间接关联，衰减系数 0.3）")
            print(f"  {'─'*54}")
            for ind in hop2_inds:
                basis   = total_in if ind.direction == "IN" else total_out
                contrib = (ind.amount_usdt * ind.category_weight * 0.3 / basis * 100) if basis > 0 else 0
                chain_tag = f"[{ind.chain}] " if ind.chain else ""
                cp  = _short(ind.counterparty)
                via = _short(ind.via_address) if ind.via_address else "?"
                if ind.direction == "IN":
                    path = f"{cp} --> {via} --> {x}"
                else:
                    path = f"{x} --> {via} --> {cp}"
                print(f"    {chain_tag}[{ind.category}]  {ind.amount_usdt:>12,.2f} USDT  "
                      f"污染贡献 {contrib:.2f}%（×0.3衰减）")
                print(f"      路径: {path}")
                print(f"      中间节点: {ind.via_address}")
                print(f"      风险终点: {ind.counterparty}")
                if ind.tx_hashes:
                    print(f"      证据tx:   {ind.tx_hashes[0][:20]}...")

        if pres_inds:
            print(f"\n  {'─'*54}")
            print(f"  关联关系（无 USDT 金额，不参与污染计算）")
            print(f"  {'─'*54}")
            for ind in pres_inds:
                chain_tag = f"[{ind.chain}] " if ind.chain else ""
                cp = _short(ind.counterparty)
                if ind.hop == 1:
                    path = (f"{cp} --> {x}" if ind.direction == "IN"
                            else f"{x} --> {cp}" if ind.direction == "OUT"
                            else f"{x} ↔ {cp}")
                elif ind.hop == 2:
                    via = _short(ind.via_address) if ind.via_address else "?"
                    path = (f"{cp} --> {via} --> {x}" if ind.direction == "IN"
                            else f"{x} --> {via} --> {cp}" if ind.direction == "OUT"
                            else f"{x} ↔ {via} ↔ {cp}")
                else:
                    via = _short(ind.via_address) if ind.via_address else "?"
                    path = (f"{cp} --> {via} --> … --> {x}" if ind.direction == "IN"
                            else f"{x} --> … --> {via} --> {cp}" if ind.direction == "OUT"
                            else f"{x} ↔ … ↔ {via} ↔ {cp}")
                note = f"  {ind.note}" if ind.note else ""
                print(f"    {chain_tag}[{ind.hop}-hop][{ind.category}]  {path}{note}")

    # ── 桥交互 ────────────────────────────────────────────────────────
    if report.bridge_interactions:
        print(f"\n  透明跨链桥（{len(report.bridge_interactions)} 笔，资金可追踪）:")
        shown: Dict[str, dict] = {}
        for b in report.bridge_interactions:
            shown.setdefault(b["bridge"], {"count": 0, "dirs": set(), "tokens": set(),
                                           "dst_chains": b.get("dst_chains", []),
                                           "method": b.get("method", ""), "contract": b["contract"]})
            shown[b["bridge"]]["count"] += 1
            shown[b["bridge"]]["dirs"].add(b.get("direction", "?"))
            shown[b["bridge"]]["tokens"].add(b.get("token", "?"))
        for name, info in shown.items():
            dirs   = "/".join(sorted(info["dirs"]))
            tokens = "/".join(sorted(info["tokens"]))
            dst    = "/".join(info["dst_chains"]) if info["dst_chains"] else "多链"
            print(f"    - {name}  [{dirs}]  {tokens}  {info['count']}笔  → {dst}")

    if report.opaque_bridge_interactions:
        print(f"\n  {lc}不透明桥（{len(report.opaque_bridge_interactions)} 笔，资金不可追踪）:{rc}")
        shown_op: Dict[str, dict] = {}
        for b in report.opaque_bridge_interactions:
            shown_op.setdefault(b["bridge"], {"count": 0, "dirs": set()})
            shown_op[b["bridge"]]["count"] += 1
            shown_op[b["bridge"]]["dirs"].add(b.get("direction", "?"))
        for name, info in shown_op.items():
            dirs = "/".join(sorted(info["dirs"]))
            print(f"    - {name}  [{dirs}]  {info['count']}笔")

    if report.mixer_interactions:
        print(f"\n  {lc}混币器（{len(report.mixer_interactions)} 笔）:{rc}")
        for m in report.mixer_interactions[:5]:
            chain_tag = f"[{m.get('chain', '')}] " if m.get('chain') else ""
            print(f"    - {chain_tag}{m['mixer']}  [{m['direction']}]  tx:{m['tx'][:20]}...")

    if report.high_risk_exchanges:
        print(f"\n  高风险交易所:")
        for e in report.high_risk_exchanges[:5]:
            chain_tag = f"[{e.get('chain', '')}] " if e.get('chain') else ""
            print(f"    - {chain_tag}{e['exchange']}  [{e['direction']}]")

    if report.cross_chain_findings:
        print(f"\n  跨链追踪（{len(report.cross_chain_findings)} 条）:")
        for f in report.cross_chain_findings:
            dst = f.get("dst_address", "?")
            ch  = f.get("dst_chain", "?")
            br  = f.get("bridge", "")
            src = f.get("src_chain", "")
            src_tag = f"[{src}→{ch}] " if src else f"[→{ch}] "
            if f.get("blacklisted"):
                bl_time = f.get("blacklist_info", {}).get("time", "")[:10]
                print(f"  {lc}  {src_tag}{br}: {dst}  [黑名单 {bl_time}]{rc}")
            elif f.get("hop1_blacklisted"):
                n = len(f["hop1_blacklisted"])
                print(f"    {src_tag}{br}: {dst[:18]}...  [1跳内 {n} 个黑名单]")
            else:
                print(f"    {src_tag}{br}: {dst[:18]}...  [无直接黑名单]")

    print(f"\n{'='*60}\n")


def export_json(report: RiskReport, path: str):
    import dataclasses
    with open(path, "w") as f:
        json.dump(dataclasses.asdict(report), f, ensure_ascii=False, indent=2)
    print(f"[INFO] JSON 报告已保存: {path}")


# ==================== CLI ====================
def main():
    parser = argparse.ArgumentParser(
        description="Travis — TRAceable Verification Intelligence System",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("address", nargs="?", help="要分析的地址（0x 格式）")
    parser.add_argument("--chain", help="强制指定链（ethereum/bsc/polygon/arbitrum/optimism/avalanche/base/tron）")
    parser.add_argument("--chains", help="分析多条链，逗号分隔（如 ethereum,bsc,polygon）")
    parser.add_argument("--blacklist", default=BLACKLIST_CSV, help=f"黑名单 CSV 路径（默认: {BLACKLIST_CSV}）")
    parser.add_argument("--no-hop2",  action="store_true", help="禁用 2 跳分析（加快速度）")
    parser.add_argument("--no-trace", action="store_true", help="禁用透明桥跨链追踪（加快速度）")
    parser.add_argument("--json", metavar="FILE", help="同时导出 JSON 报告到指定文件")
    parser.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    parser.add_argument("--batch", metavar="FILE", help="批量分析：从文件逐行读取地址")
    args = parser.parse_args()

    global HOP2_ENABLED, BRIDGE_TRACE_ENABLED
    if args.no_hop2:
        HOP2_ENABLED = False
    if args.no_trace:
        BRIDGE_TRACE_ENABLED = False

    # 解析 --chains
    chains_list = None
    if args.chains:
        chains_list = [c.strip() for c in args.chains.split(",") if c.strip()]

    print("[*] 加载黑名单...")
    blacklist = load_blacklist(args.blacklist)
    print(f"[*] 已加载 {len(blacklist)} 个黑名单地址")

    # 为每条 EVM 链创建独立客户端
    evm_clients = {name: EVMClient(cfg) for name, cfg in EVM_CHAIN_REGISTRY.items()}
    tronscan  = TronScanClient()
    tracer    = BridgeTracer()
    analyzer  = AMLAnalyzer(blacklist, evm_clients, tronscan, tracer)

    if args.batch:
        with open(args.batch) as f:
            addresses = [line.strip() for line in f if line.strip()]
        print(f"[*] 批量模式：共 {len(addresses)} 个地址")
        reports = []
        for i, addr in enumerate(addresses, 1):
            print(f"\n[{i}/{len(addresses)}] 处理: {addr}")
            report = analyzer.analyze(addr, chain=args.chain, chains=chains_list)
            print_report(report, use_color=not args.no_color)
            reports.append(report)
            time.sleep(0.5)
        print(f"\n{'='*60}")
        print(f"批量分析汇总")
        print(f"{'='*60}")
        for r in reports:
            lc_c = LEVEL_COLORS.get(r.risk_level, "") if not args.no_color else ""
            rc_c = LEVEL_COLORS["RESET"] if not args.no_color else ""
            bl_cnt = sum(1 for ind in r.indicators if "blacklist" in ind.category and ind.hop == 1)
            bridges = len(r.bridge_interactions)
            print(f"  {r.address[:20]}...  {lc_c}{r.risk_level:8s}{rc_c}  "
                  f"分数:{r.risk_score:3d}  直接黑名单:{bl_cnt}  桥:{bridges}")
        if args.json:
            import dataclasses
            with open(args.json, "w") as f:
                json.dump([dataclasses.asdict(r) for r in reports], f, ensure_ascii=False, indent=2)
            print(f"[INFO] 批量 JSON 已保存: {args.json}")

    elif args.address:
        report = analyzer.analyze(args.address, chain=args.chain, chains=chains_list)
        print_report(report, use_color=not args.no_color)
        if args.json:
            export_json(report, args.json)

    else:
        print("\n[*] 进入交互模式（输入 q 退出）")
        while True:
            try:
                addr = input("\n请输入地址: ").strip()
                if addr.lower() in ("q", "quit", "exit"):
                    break
                if not addr:
                    continue
                chain_input = input(
                    f"链类型 [{'/'.join(list(EVM_CHAIN_REGISTRY.keys()) + ['tron', 'auto'])}]: "
                ).strip().lower()
                chain_arg = chain_input if chain_input not in ("auto", "") else None
                report = analyzer.analyze(addr, chain=chain_arg)
                print_report(report, use_color=not args.no_color)
            except KeyboardInterrupt:
                break
        print("\n[*] 退出")


if __name__ == "__main__":
    main()
