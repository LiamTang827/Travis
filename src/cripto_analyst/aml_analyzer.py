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
from pathlib import Path
from typing import Optional, Set, Dict, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import os

import requests
from dotenv import load_dotenv

try:
    from .threat_intel import (
        MIXER_CONTRACTS, BRIDGE_REGISTRY, ALL_BRIDGE_ADDRS, OPAQUE_BRIDGE_ADDRS,
        EXCHANGE_HOT_WALLETS, HIGH_RISK_EXCHANGES, HIGH_RISK_EXCHANGES_FLAT,
        EXCHANGE_HOT_WALLETS_FLAT, ALL_EXCHANGE_ADDRS, DEPOSIT_DETECTION_PARAMS,
        OFAC_SANCTIONED, OFAC_SANCTIONED_ADDRS,
    )
except ImportError:
    from threat_intel import (
        MIXER_CONTRACTS, BRIDGE_REGISTRY, ALL_BRIDGE_ADDRS, OPAQUE_BRIDGE_ADDRS,
        EXCHANGE_HOT_WALLETS, HIGH_RISK_EXCHANGES, HIGH_RISK_EXCHANGES_FLAT,
        EXCHANGE_HOT_WALLETS_FLAT, ALL_EXCHANGE_ADDRS, DEPOSIT_DETECTION_PARAMS,
        OFAC_SANCTIONED, OFAC_SANCTIONED_ADDRS,
    )

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

# ==================== 配置 ====================
BLACKLIST_CSV = str(PROJECT_ROOT / "data" / "blacklists" / "usdt_blacklist.csv")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
REQUEST_DELAY = 0.25   # 每次 API 请求后的等待时间（秒），Etherscan 免费档限速 5 req/s
PAGE_SIZE = 10000      # 每页拉取条数（Etherscan 最大 10000）
MAX_PAGES = 10         # 最多翻多少页 → 最大 100000 条，覆盖绝大多数地址完整历史
                       # 对超活跃地址（交易所热钱包），用 --days 截断时间窗口
HOP2_ENABLED = True    # 是否启用 2-hop 分析（较慢，快速模式下禁用）

# 向后兼容
MAX_TX_FETCH = PAGE_SIZE

# ==================== 风险类别权重（参考 FATF 风险等级）====================
CATEGORY_WEIGHTS: Dict[str, float] = {
    "ofac_sanctioned":            1.0,
    "ransomware":                 1.0,
    "theft_hack":                 1.0,
    "darknet":                    1.0,
    "blacklist":                  1.0,   # USDT 黑名单（未分类）
    "mixer":                      0.5,
    "opaque_bridge":              0.5,
    "high_risk_exchange":         0.5,
    "transparent_bridge_with_bl": 0.5,   # 透明桥但对端有黑名单，污染等级同混币器
    "transparent_bridge":         0.3,
}

# hop_decay 不再承担"距离惩罚"，统一为 1.0
# 2-hop 的风险已通过 cp 的真实污染比例（taint_ratio）体现，不需要额外折扣
HOP_DECAY: Dict[int, float] = {1: 1.0, 2: 1.0}

# BRIDGE_REGISTRY / ALL_BRIDGE_ADDRS / OPAQUE_BRIDGE_ADDRS 从 threat_intel 导入

# 纳入污染计算的稳定币符号集合（大写匹配）
# USDC.E / USDCE 是 Polygon/Arbitrum 上的桥接版 USDC，等值 1 USD
STABLECOIN_SYMBOLS: Set[str] = {"USDT", "USDC", "DAI", "BUSD", "USDC.E", "USDCE", "USDB", "DOLA"}

# ==================== 常用 4-byte 选择器解码 ====================
# Etherscan tokentx 接口返回的 methodId 是"外壳交易"的函数选择器，
# 当 functionName 为空时（大多 multicall / proxy / safe.exec 情况），
# 用户只能看到一串 hex。这里做一份白名单解码，方便人读。
# 来源：https://www.4byte.directory/ 高频条目。
KNOWN_METHOD_SELECTORS: Dict[str, str] = {
    # ERC20 / ERC721 基础
    "0xa9059cbb": "transfer",
    "0x23b872dd": "transferFrom",
    "0x095ea7b3": "approve",
    "0x42842e0e": "safeTransferFrom",
    "0x40c10f19": "mint",
    "0x6a627842": "mint",
    "0xb88d4fde": "safeTransferFrom",
    # WETH
    "0xd0e30db0": "deposit",
    "0x2e1a7d4d": "withdraw",
    # Uniswap V2 router
    "0x38ed1739": "swapExactTokensForTokens",
    "0x18cbafe5": "swapExactTokensForETH",
    "0x7ff36ab5": "swapExactETHForTokens",
    "0xfb3bdb41": "swapETHForExactTokens",
    "0x4a25d94a": "swapTokensForExactETH",
    "0x8803dbee": "swapTokensForExactTokens",
    "0x791ac947": "swapExactTokensForETHSupportingFeeOnTransferTokens",
    "0xb6f9de95": "swapExactETHForTokensSupportingFeeOnTransferTokens",
    "0x5c11d795": "swapExactTokensForTokensSupportingFeeOnTransferTokens",
    # Uniswap V3 / Universal Router
    "0x414bf389": "exactInputSingle",
    "0xc04b8d59": "exactInput",
    "0xdb3e2198": "exactOutputSingle",
    "0xf28c0498": "exactOutput",
    "0x3593564c": "execute",                  # Universal Router
    "0x24856bc3": "execute",
    "0xac9650d8": "multicall",
    "0x5ae401dc": "multicall",
    "0x1f0464d1": "multicall",
    # 1inch / 0x / aggregators
    "0x12aa3caf": "swap",                     # 1inch v5
    "0x84bd6d29": "swap",
    "0xe449022e": "uniswapV3Swap",
    "0x415565b0": "transformERC20",           # 0x
    # Safe / Gnosis
    "0x6a761202": "execTransaction",
    "0x468721a7": "execTransactionFromModule",
    # 常见 wrapping / bridge
    "0x40d097c3": "bridge",
    "0xc7012626": "outboundTransfer",
    "0x36abc4dd": "claim",
    # 钱包合约 / proxy
    "0x1cff79cd": "execute(address,bytes)",
    "0xb61d27f6": "execute(address,uint256,bytes)",
    "0xbc197c81": "onERC1155BatchReceived",
    "0xf23a6e61": "onERC1155Received",
    "0x150b7a02": "onERC721Received",
}


def decode_method(method_id: str, function_name: str = "") -> str:
    """优先使用 Etherscan 给的 functionName；为空时查白名单；都没有就回退到 selector 本身。

    特殊情况：methodId == "0x" 表示 input data 为空（裸转账），按"未知/无"处理。
    """
    fn = (function_name or "").strip()
    if fn:
        # functionName 形如 "transfer(address _to, uint256 _value)" → 取函数名
        return fn.split("(")[0] if "(" in fn else fn
    mid = (method_id or "").lower().strip()
    if not mid or mid == "0x":
        return ""
    if mid in KNOWN_METHOD_SELECTORS:
        return KNOWN_METHOD_SELECTORS[mid]
    # 标准 selector 长度应是 0x + 8 hex = 10 字符；非此长度多半是脏数据
    if len(mid) != 10:
        return ""
    return f"unknown({mid})"


# ==================== 链注册表 ====================
# 新增链：只需在此处加一条记录，其余业务代码无需修改。
# api_key 留空则走无 key 公开端点（速率更严格）。
# backup_url: 无 key 备用端点（Blockscout 系，无 OFAC 屏蔽）。
# usdt_contract: 该链上 USDT 的合约地址（余额查询 / getLogs 回退）。
# stablecoin_contracts: {symbol: address} 全部稳定币合约，用于余额汇总和 getLogs 回退。
# stablecoin_decimals: {symbol: decimals} 每个稳定币的实际精度，避免把 DAI/USDB 等误按 6 位处理。
# native_token: 原生代币符号（展示用）。

@dataclass
class ChainConfig:
    name: str
    api_url: str
    api_key: str
    usdt_contract: str
    native_token: str
    chain_id: int = 0          # Etherscan V2 chainid（非零时自动注入 chainid 参数）
    backup_url: str = ""
    explorer_url: str = ""
    stablecoin_contracts: Dict[str, str] = field(default_factory=dict)  # symbol → address
    stablecoin_decimals: Dict[str, int] = field(default_factory=dict)    # symbol → decimals

    def token_decimals(self, symbol: str, fallback: int = 6) -> int:
        return self.stablecoin_decimals.get(symbol.upper(), fallback)

# Etherscan V2 统一端点（一个 Key 覆盖所有链）
_ETH_V2 = "https://api.etherscan.io/v2/api"
_ETH_KEY = ETHERSCAN_API_KEY

EVM_CHAIN_REGISTRY: Dict[str, ChainConfig] = {
    "ethereum": ChainConfig(
        name="Ethereum", native_token="ETH",
        api_url=_ETH_V2, api_key=_ETH_KEY, chain_id=1,
        backup_url="",
        usdt_contract="0xdac17f958d2ee523a2206206994597c13d831ec7",
        explorer_url="https://etherscan.io",
        stablecoin_contracts={
            "USDT": "0xdac17f958d2ee523a2206206994597c13d831ec7",
            "USDC": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "DAI":  "0x6b175474e89094c44da98b954eedeac495271d0f",
            "BUSD": "0x4fabb145d64652a948d72533023f6e7a623c7c53",
        },
        stablecoin_decimals={"USDT": 6, "USDC": 6, "DAI": 18, "BUSD": 18},
    ),
    "bsc": ChainConfig(
        name="BSC", native_token="BNB",
        api_url=_ETH_V2, api_key=_ETH_KEY, chain_id=56,
        backup_url="",
        usdt_contract="0x55d398326f99059ff775485246999027b3197955",
        explorer_url="https://bscscan.com",
        stablecoin_contracts={
            "USDT": "0x55d398326f99059ff775485246999027b3197955",
            "USDC": "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
            "DAI":  "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3",
            "BUSD": "0xe9e7cea3dedca5984780bafc599bd69add087d56",
        },
        stablecoin_decimals={"USDT": 18, "USDC": 18, "DAI": 18, "BUSD": 18},
    ),
    "polygon": ChainConfig(
        name="Polygon", native_token="MATIC",
        api_url=_ETH_V2, api_key=_ETH_KEY, chain_id=137,
        backup_url="",
        usdt_contract="0xc2132d05d31c914a87c6611c10748aeb04b58e8f",
        explorer_url="https://polygonscan.com",
        stablecoin_contracts={
            "USDT":   "0xc2132d05d31c914a87c6611c10748aeb04b58e8f",
            "USDC":   "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
            "USDC.E": "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
            "DAI":    "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063",
        },
        stablecoin_decimals={"USDT": 6, "USDC": 6, "USDC.E": 6, "DAI": 18},
    ),
    "arbitrum": ChainConfig(
        name="Arbitrum", native_token="ETH",
        api_url=_ETH_V2, api_key=_ETH_KEY, chain_id=42161,
        backup_url="",
        usdt_contract="0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",
        explorer_url="https://arbiscan.io",
        stablecoin_contracts={
            "USDT":   "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",
            "USDC":   "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
            "USDC.E": "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8",
            "DAI":    "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1",
        },
        stablecoin_decimals={"USDT": 6, "USDC": 6, "USDC.E": 6, "DAI": 18},
    ),
    "optimism": ChainConfig(
        name="Optimism", native_token="ETH",
        api_url=_ETH_V2, api_key=_ETH_KEY, chain_id=10,
        backup_url="",
        usdt_contract="0x94b008aa00579c1307b0ef2c499ad98a8ce58e58",
        explorer_url="https://optimistic.etherscan.io",
        stablecoin_contracts={
            "USDT":   "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58",
            "USDC":   "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
            "USDC.E": "0x7f5c764cbc14f9669b88837ca1490cca17c31607",
            "DAI":    "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1",
        },
        stablecoin_decimals={"USDT": 6, "USDC": 6, "USDC.E": 6, "DAI": 18},
    ),
    "avalanche": ChainConfig(
        name="Avalanche", native_token="AVAX",
        api_url=_ETH_V2, api_key=_ETH_KEY, chain_id=43114,
        backup_url="",
        usdt_contract="0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7",
        explorer_url="https://snowtrace.io",
        stablecoin_contracts={
            "USDT": "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7",
            "USDC": "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e",
            "DAI":  "0xd586e7f844cea2f87f50152665bcbc2c279d8d70",
        },
        stablecoin_decimals={"USDT": 6, "USDC": 6, "DAI": 18},
    ),
    "base": ChainConfig(
        name="Base", native_token="ETH",
        api_url=_ETH_V2, api_key=_ETH_KEY, chain_id=8453,
        backup_url="",
        usdt_contract="0xfde4c96c8593536e31f229ea8f37b2ada2699bb2",
        explorer_url="https://basescan.org",
        stablecoin_contracts={
            "USDT": "0xfde4c96c8593536e31f229ea8f37b2ada2699bb2",
            "USDC": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "DAI":  "0x50c5725949a6f0c72e6c4a641f24049a917db0cb",
        },
        stablecoin_decimals={"USDT": 6, "USDC": 6, "DAI": 18},
    ),
}

# 跨链追踪时查询目标链用（供 BridgeTracer 使用）
CHAIN_SCANNERS: Dict[str, Dict] = {
    name: {"api": cfg.api_url, "key": cfg.api_key, "chain_id": cfg.chain_id}
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
        # 只在主端点加 apikey 和 chainid（Blockscout 备用端点不需要）
        if url == self.primary_url:
            if self.key:
                p["apikey"] = self.key
            if self.cfg.chain_id:
                p["chainid"] = self.cfg.chain_id
        try:
            r = requests.get(url, params=p, timeout=30)
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
                if max_pages > 1:  # 只在主地址扫描时打印（2-hop 用 max_pages=1，不打扰输出）
                    print(f"  [INFO] {self.cfg.name} 已拉取 {max_pages} 页（{len(all_results)} 条），主动截断")

        return all_results, truncated

    def get_block_by_time(self, timestamp: int, closest: str = "before") -> int:
        """Convert a Unix timestamp to a chain block number via explorer API."""
        data = self._get({
            "module": "block",
            "action": "getblocknobytime",
            "timestamp": timestamp,
            "closest": closest,
        })
        result = data.get("result") if data else None
        try:
            return int(result)
        except Exception:
            return 0

    def get_normal_txs(self, address: str,
                       limit: int = MAX_TX_FETCH,
                       max_pages: int = 1,
                       time_cutoff: int = 0,
                       from_block: int = 0,
                       to_block: int = 99999999) -> List[dict]:
        base = {
            "module": "account", "action": "txlist",
            "address": address, "startblock": from_block, "endblock": to_block,
            "sort": "desc",
        }
        results, _ = self._fetch_txs_paged(base, page_size=limit,
                                            max_pages=max_pages, time_cutoff=time_cutoff)
        return results

    def get_token_transfers(self, address: str,
                            contract: str = "",
                            limit: int = MAX_TX_FETCH,
                            max_pages: int = 1,
                            time_cutoff: int = 0,
                            from_block: int = 0,
                            to_block: int = 99999999) -> List[dict]:
        base = {
            "module": "account", "action": "tokentx",
            "address": address, "startblock": from_block, "endblock": to_block,
            "sort": "desc",
        }
        if contract:
            base["contractaddress"] = contract
        results, _ = self._fetch_txs_paged(base, page_size=limit,
                                            max_pages=max_pages, time_cutoff=time_cutoff)
        return results

    def get_token_balance(self, address: str, contract: str, decimals: int = 6) -> float:
        data = self._get({
            "module": "account", "action": "tokenbalance",
            "contractaddress": contract, "address": address, "tag": "latest",
        })
        if data and isinstance(data.get("result"), str):
            try:
                return int(data["result"]) / (10 ** decimals)
            except Exception:
                pass
        return 0.0

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
        self.eth_price_usd = self._fetch_eth_price()

    def _fetch_eth_price(self) -> float:
        try:
            eth_client = self.evm_clients.get("ethereum")
            if eth_client:
                d = eth_client._get({"module": "stats", "action": "ethprice"})
                if d and isinstance(d.get("result"), dict):
                    price = float(d["result"].get("ethusd", 0))
                    if price > 0:
                        print(f"  ETH price: ${price:,.2f}")
                        return price
        except Exception:
            pass
        print("  ETH price: fallback $2,500.00")
        return 2500.0

    def _classify_contract_action(self, method: str, native_value: float, token_effects: List[dict]) -> str:
        method_l = (method or "").lower()
        stable_effects = [e for e in token_effects if e.get("is_stablecoin")]
        nonzero_effects = [e for e in token_effects if e.get("amount", 0) > 0]
        dirs = {e.get("direction") for e in stable_effects}

        if "approve" in method_l:
            return "Approval"
        if "swap" in method_l or ("multicall" in method_l and "IN" in dirs and "OUT" in dirs):
            return "Swap / Router Call"
        if "bridge" in method_l or "deposit" in method_l or "withdraw" in method_l:
            return "Bridge / Deposit / Withdraw"
        if stable_effects:
            return "Stablecoin Transfer" if len(stable_effects) == 1 else "Stablecoin Movement"
        if nonzero_effects:
            return "Other ERC20 Movement"
        if native_value > 0:
            return "Native ETH Transfer"
        return "Contract Call / No Asset Effect"

    def _build_contract_interactions(self, report: RiskReport, normal_txs: List[dict],
                                     token_txs: List[dict], chain_cfg: ChainConfig,
                                     chain_name: str, address: str) -> None:
        """Aggregate outer calls and inner ERC20 Transfer effects by tx hash."""
        addr_norm = normalize(address)
        configured_stables = {
            sym.upper(): normalize(contract)
            for sym, contract in (chain_cfg.stablecoin_contracts or {}).items()
        }
        effects_by_hash: Dict[str, List[dict]] = {}

        for tx in token_txs:
            tx_hash = tx.get("hash") or tx.get("transactionHash")
            if not tx_hash:
                continue
            sym = (tx.get("_sym") or tx.get("tokenSymbol") or "").upper().strip()
            contract = normalize(tx.get("contractAddress", ""))
            try:
                dec = int(tx.get("tokenDecimal", "") or chain_cfg.token_decimals(sym))
            except Exception:
                dec = chain_cfg.token_decimals(sym)
            try:
                amount = int(tx.get("value", "0") or "0") / (10 ** dec)
            except Exception:
                amount = 0.0
            if amount <= 0:
                continue

            frm = normalize(tx.get("from", ""))
            to = normalize(tx.get("to", "") or "")
            if to == addr_norm:
                direction, counterparty = "IN", frm
            elif frm == addr_norm:
                direction, counterparty = "OUT", to
            else:
                direction, counterparty = "OTHER", ""

            is_stable = sym in configured_stables and contract == configured_stables[sym]
            method_id_raw = tx.get("methodId", "") or ""
            function_name_raw = tx.get("functionName", "") or ""
            if method_id_raw.lower().strip() == "0x":
                method_id_raw = ""
            effects_by_hash.setdefault(tx_hash, []).append({
                "direction": direction,
                "counterparty": counterparty,
                # 显式带出 from / to，避免下游只能看到 direction 推回
                "from": frm,
                "to": to,
                "amount": round(amount, 6),
                "sym": sym,
                "token_contract": contract,
                "token_decimals": dec,
                # method_id / method 是 Etherscan tokentx 返回的"外壳交易"信息
                # 这里继续保留原值，并加一份 decoded label 供展示
                "method_id": method_id_raw,
                "method": function_name_raw or method_id_raw,
                "method_label": decode_method(method_id_raw, function_name_raw),
                "ts": tx.get("timeStamp", ""),
                "is_stablecoin": is_stable,
                "token_status": "configured_stablecoin_contract" if is_stable else "other_erc20",
            })

        interactions = []
        seen_hashes = set()
        for tx in normal_txs:
            tx_hash = tx.get("hash", "")
            if not tx_hash:
                continue
            seen_hashes.add(tx_hash)
            frm = normalize(tx.get("from", ""))
            to = normalize(tx.get("to", "") or "")
            try:
                native_value = int(tx.get("value", "0") or "0") / 1e18
            except Exception:
                native_value = 0.0
            if to == addr_norm:
                direction, counterparty = "IN", frm
            elif frm == addr_norm:
                direction, counterparty = "OUT", to
            else:
                direction, counterparty = "OTHER", to or frm

            input_data = tx.get("input", "") or ""
            method_id_raw = tx.get("methodId", "") or ""
            function_name_raw = tx.get("functionName", "") or ""
            # methodId 偶尔会被 Etherscan 设成 "0x"（input 为空时的占位），归一为空
            if method_id_raw.lower().strip() == "0x":
                method_id_raw = ""
            method_raw = function_name_raw or method_id_raw
            method_label = decode_method(method_id_raw, function_name_raw)
            if not method_label and input_data in ("", "0x"):
                method_label = "Transfer"      # 没 input data 就是裸转账
            token_effects = effects_by_hash.get(tx_hash, [])
            interactions.append({
                "tx_hash": tx_hash,
                "ts": tx.get("timeStamp", ""),
                "chain": chain_name,
                "from": frm,
                "to": to,
                "direction": direction,
                "counterparty": counterparty,
                "native_value": round(native_value, 12),
                "method_id": method_id_raw,
                "method": method_raw or ("Transfer" if input_data in ("", "0x") else "unknown"),
                "method_label": method_label,
                "input_present": bool(input_data and input_data != "0x"),
                "is_contract_call": bool(input_data and input_data != "0x"),
                "status": "success" if tx.get("isError", "0") == "0" else "failed",
                "token_effects": token_effects,
                "action_type": self._classify_contract_action(method_raw, native_value, token_effects),
            })

        for tx_hash, token_effects in effects_by_hash.items():
            if tx_hash in seen_hashes:
                continue
            # TOKEN_ONLY：normal_txs 里没匹到外壳（地址不是 tx.from 也不是 tx.to，
            # 比如 Safe 多签代付 / 路由器内部 inner call）。此时把 token transfer 自己
            # 携带的 methodId/functionName 作为这条交互的 method。
            first_effect = token_effects[0] if token_effects else {}
            method_id_raw = first_effect.get("method_id", "") or ""
            # first_effect["method"] 已经是 functionName-or-methodId，复原 functionName
            method_raw = first_effect.get("method", "") or ""
            function_name_raw = method_raw if method_raw and method_raw != method_id_raw else ""
            method_label = decode_method(method_id_raw, function_name_raw) or "not captured"
            interactions.append({
                "tx_hash": tx_hash,
                "ts": first_effect.get("ts", ""),
                "chain": chain_name,
                "from": "",
                "to": "",
                "direction": "TOKEN_ONLY",
                "counterparty": "",
                "native_value": 0.0,
                "method_id": method_id_raw,
                "method": method_raw or "not captured",
                "method_label": method_label,
                "input_present": False,
                "is_contract_call": True,
                "status": "unknown",
                "token_effects": token_effects,
                "action_type": self._classify_contract_action(method_raw, 0.0, token_effects),
            })

        report.contract_interactions.extend(
            sorted(interactions, key=lambda x: x.get("ts", ""), reverse=True)
        )

    # ---------- 稳定币余额一致性校验 ----------
    def _check_balance_consistency(self, address: str, token_txs: List[dict],
                                   client: EVMClient, chain_cfg: ChainConfig) -> dict:
        """
        汇总链上所有稳定币实际余额，与历史转账记录的收支差对比。
        差异过大说明存在未追踪的资金流动。
        仅在 MAX_TX_FETCH 未截断时结果可信。
        """
        addr_norm = normalize(address)

        # 查所有稳定币余额并汇总（decimals 统一按链配置处理）
        stable_contracts = chain_cfg.stablecoin_contracts or {"USDT": chain_cfg.usdt_contract}
        actual_balance = 0.0
        for sym, contract in stable_contracts.items():
            balance_data = client._get({
                "module": "account", "action": "tokenbalance",
                "contractaddress": contract,
                "address": address,
                "tag": "latest",
            })
            if balance_data and isinstance(balance_data.get("result"), str):
                try:
                    decimals = chain_cfg.token_decimals(sym)
                    actual_balance += int(balance_data["result"]) / (10 ** decimals)
                except Exception:
                    pass
            time.sleep(REQUEST_DELAY)

        total_in = 0.0
        total_out = 0.0
        tx_count = 0
        for tx in token_txs:
            symbol = (tx.get("tokenSymbol") or "").upper()
            if symbol not in STABLECOIN_SYMBOLS:
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
                       chain_cfg: ChainConfig,
                       from_block: int = 0,
                       to_block: int = 99999999) -> List[dict]:
        """getLogs 回退：为所有稳定币合约各查一次 Transfer 事件"""
        TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        addr_norm = normalize(address)
        padded = "0x" + "0" * 24 + addr_norm[2:]
        results = []
        backup = client.backup_url
        base = backup if backup else client.primary_url

        stable_contracts = chain_cfg.stablecoin_contracts or {"USDT": chain_cfg.usdt_contract}
        for sym, contract in stable_contracts.items():
            for role, topic_key in [("sender", "topic1"), ("receiver", "topic2")]:
                time.sleep(REQUEST_DELAY)
                params = {
                    "module": "logs", "action": "getLogs",
                    "address": contract,
                    "topic0": TRANSFER_TOPIC,
                    topic_key: padded,
                    "topic0_1_opr" if role == "sender" else "topic0_2_opr": "and",
                    "fromBlock": from_block, "toBlock": to_block,
                    "page": 1, "offset": MAX_TX_FETCH,
                }
                try:
                    r = requests.get(base, params=params, timeout=15)
                    logs = r.json().get("result", [])
                    if isinstance(logs, list):
                        for log in logs:
                            log["_role"] = role
                            log["_sym"] = sym
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
        from_block = 0
        to_block = 99999999
        if self.time_window_days > 0:
            time_cutoff = int(time.time()) - self.time_window_days * 86400
            from_block = client.get_block_by_time(time_cutoff, closest="after")
            latest_block = client.get_block_by_time(int(time.time()), closest="before")
            if from_block > 0:
                to_block = latest_block or to_block
                print(f"  [{chain_label}] 时间窗口 {self.time_window_days} 天 ≈ blocks {from_block:,} → {to_block:,}")
        report.analysis_windows[chain_name] = {
            "days": self.time_window_days,
            "from_timestamp": time_cutoff,
            "to_timestamp": int(time.time()),
            "from_block": from_block,
            "to_block": to_block,
        }

        print(f"  [{chain_label}] 查询普通交易（最多 {MAX_PAGES} 页 × {PAGE_SIZE} 条）...")
        normal_txs = client.get_normal_txs(address, limit=PAGE_SIZE,
                                           max_pages=MAX_PAGES, time_cutoff=time_cutoff,
                                           from_block=from_block, to_block=to_block)
        if len(normal_txs) >= PAGE_SIZE * MAX_PAGES:
            report.warnings.append(
                f"[{chain_label}] Normal tx cap reached ({PAGE_SIZE*MAX_PAGES}), history may be incomplete"
            )

        # ── 按稳定币逐一拉取 Token 转账 + 余额 ────────────────────────
        stable_contracts = chain_cfg.stablecoin_contracts or {"USDT": chain_cfg.usdt_contract}
        # 汇总所有稳定币 txs 供后续对手方发现
        token_txs: List[dict] = []
        for sym, contract in stable_contracts.items():
            decimals = chain_cfg.token_decimals(sym)
            time.sleep(REQUEST_DELAY)
            stxs = client.get_token_transfers(address, contract=contract,
                                              limit=PAGE_SIZE, max_pages=MAX_PAGES,
                                              time_cutoff=time_cutoff,
                                              from_block=from_block, to_block=to_block)
            # 实际余额（API 直接查）
            time.sleep(REQUEST_DELAY)
            balance = client.get_token_balance(address, contract, decimals)

            # 计算该资产流入/流出，同时收集全量流水
            asset_in, asset_out = 0.0, 0.0
            for tx in stxs:
                f = normalize(tx.get("from", ""))
                t = normalize(tx.get("to", "") or "")
                try:
                    val = int(tx.get("value", "0") or "0") / (10 ** decimals)
                except Exception:
                    val = 0.0
                direction = ""
                counterparty = ""
                if t == addr_norm:
                    asset_in += val
                    direction, counterparty = "IN", f
                elif f == addr_norm:
                    asset_out += val
                    direction, counterparty = "OUT", t
                if direction and val > 0:
                    report.transactions.append({
                        "ts":           tx.get("timeStamp", ""),
                        "direction":    direction,
                        "amount":       round(val, 6),
                        "sym":          sym,
                        "token_contract": normalize(contract),
                        "token_decimals": decimals,
                        "method_id":     tx.get("methodId", ""),
                        "method":        tx.get("functionName", "") or tx.get("methodId", ""),
                        "action_type":   "Stablecoin Transfer",
                        "chain":        chain_name,
                        "counterparty": counterparty,
                        "tx_hash":      tx.get("hash", ""),
                    })

            # 快速中转检测（per asset）
            is_fast_transit = (
                asset_in > 10_000
                and balance < asset_in * 0.05
                and asset_out > asset_in * 0.9
            )
            if is_fast_transit:
                report.warnings.append(
                    f"[{chain_label}][{sym}] Fast transit: inflow ${asset_in:,.0f} / "
                    f"outflow ${asset_out:,.0f} / balance ${balance:,.2f}"
                )

            if stxs or balance > 0:
                # 窗口前隐含余额：balance + outflow - inflow
                # 若为正，说明地址在分析窗口之前就持有该资产
                # 若为负，说明转账记录不完整（API 分页上限触发）
                pre_window_balance = round(balance + asset_out - asset_in, 2)
                truncated = len(stxs) >= PAGE_SIZE * MAX_PAGES

                key = f"{sym}@{chain_name}"
                report.per_asset[key] = {
                    "sym": sym, "chain": chain_name,
                    "decimals": decimals,
                    "start_block": from_block,
                    "end_block": to_block,
                    "start_balance": pre_window_balance,
                    "end_balance": round(balance, 2),
                    "start_balance_source": "reconstructed: end_balance + outflow - inflow",
                    "end_balance_source": "tokenbalance latest",
                    "historical_balance_verified": False,
                    "balance_source": "end=tokenbalance latest; start=reconstructed from window flows",
                    "flow_in": round(asset_in, 2),
                    "flow_out": round(asset_out, 2),
                    "balance": round(balance, 2),
                    "pre_window_balance": pre_window_balance,
                    "truncated": truncated,
                    "tx_count": len(stxs),
                    "is_fast_transit": is_fast_transit,
                    "taint_in": 0.0, "taint_out": 0.0,
                }

            # 为 tx 打上 token 标签，归入总池供后续 1-hop/2-hop 使用
            for tx in stxs:
                tx["_sym"] = sym
            token_txs.extend(stxs)

            # 汇总到 report 总流量（评分用）
            report.total_inflow_usdt  += asset_in
            report.total_outflow_usdt += asset_out
            if asset_in or asset_out:
                truncated_flag = " [截断!]" if len(stxs) >= PAGE_SIZE * MAX_PAGES else ""
                print(f"  [{chain_label}] {sym}: 流入 {asset_in:,.2f} / 流出 {asset_out:,.2f} / "
                      f"余额 {balance:,.2f} / 窗口前余额 {balance+asset_out-asset_in:,.2f}{truncated_flag}")

            if len(stxs) >= PAGE_SIZE * MAX_PAGES:
                report.warnings.append(
                    f"[{chain_label}][{sym}] Transfer cap reached ({PAGE_SIZE*MAX_PAGES}), "
                    f"history incomplete — inflow/outflow understated, pre-window balance may be negative"
                )

        # ── 全量 ERC20 token 转账（非稳定币）────────────────────────────
        # 目的：捕获 LINK/WBTC/UNI 等与风险地址的往来，用于 CP 表展示
        # 限 1 页（≤1000 条），不影响评分分母，只补充 by_sym 可见性
        time.sleep(REQUEST_DELAY)
        all_token_txs = client.get_token_transfers(address, limit=1000, max_pages=1,
                                                   time_cutoff=time_cutoff,
                                                   from_block=from_block, to_block=to_block)
        _stable_set = set(STABLECOIN_SYMBOLS)
        # 用合约地址过滤稳定币（tokenSymbol 不可靠，如 "USD TETHER"、乱码等变体）
        _stable_contracts = {normalize(a) for a in (chain_cfg.stablecoin_contracts or {}).values()
                             if a}
        _stable_contracts.add(normalize(chain_cfg.usdt_contract or ""))
        for tx in all_token_txs:
            sym_t    = (tx.get("tokenSymbol") or "").upper().strip()
            contract = normalize(tx.get("contractAddress", ""))
            if contract in _stable_contracts:
                continue   # 按合约地址过滤，避免 "USD TETHER" 等变体漏网
            if not sym_t or sym_t in _stable_set:
                continue
            try:
                dec = int(tx.get("tokenDecimal", "18") or "18")
                val = int(tx.get("value", "0") or "0") / (10 ** dec)
            except Exception:
                val = 0.0
            if val <= 0:
                continue
            tx["_sym"] = sym_t
            token_txs.append(tx)

            # 同步写入 report.transactions，让 CP 表能展示所有 token（不只是风险 CP）
            frm_t = normalize(tx.get("from", ""))
            to_t  = normalize(tx.get("to", "") or "")
            if to_t == addr_norm:
                direction_t, cp_t = "IN", frm_t
            elif frm_t == addr_norm:
                direction_t, cp_t = "OUT", to_t
            else:
                continue
            if cp_t and cp_t != addr_norm:
                report.transactions.append({
                    "ts":          tx.get("timeStamp", ""),
                    "direction":   direction_t,
                    "amount":      round(val, 6),
                    "sym":         sym_t,
                    "token_contract": contract,
                    "token_decimals": dec,
                    "method_id":     tx.get("methodId", ""),
                    "method":        tx.get("functionName", "") or tx.get("methodId", ""),
                    "action_type":   "Other ERC20 Transfer",
                    "chain":       chain_name,
                    "counterparty": cp_t,
                    "tx_hash":     tx.get("hash", ""),
                })

        # ── ETH 原生代币 per-asset 追踪 ───────────────────────────────────
        eth_in = eth_out = 0.0
        eth_tx_count = 0
        for tx in normal_txs:
            frm = normalize(tx.get("from", ""))
            t   = normalize(tx.get("to", "") or "")
            try:
                val = int(tx.get("value", "0") or "0") / 1e18
            except Exception:
                val = 0.0
            if val <= 0:
                continue
            eth_tx_count += 1
            if t == addr_norm:
                eth_in += val
            elif frm == addr_norm:
                eth_out += val

        # 仅主链记录 account_info
        if not report.account_info:
            time.sleep(REQUEST_DELAY)
            report.account_info = client.get_account_info(address)

        # ETH 余额从 account_info 解析
            eth_balance = 0.0
        if report.account_info:
            try:
                eth_balance = float(report.account_info.get("balance", "0").split()[0])
            except Exception:
                pass

        if eth_in > 0 or eth_out > 0 or eth_balance > 0:
            ep = self.eth_price_usd
            eth_in_usd  = round(eth_in  * ep, 2)
            eth_out_usd = round(eth_out * ep, 2)
            eth_bal_usd = round(eth_balance * ep, 2)
            key = f"ETH@{chain_name}"
            report.per_asset[key] = {
                "sym": chain_cfg.native_token, "chain": chain_name,
                "start_block": from_block,
                "end_block": to_block,
                "start_balance": round(eth_bal_usd + eth_out_usd - eth_in_usd, 2),
                "end_balance": eth_bal_usd,
                "start_native_balance": round(eth_balance + eth_out - eth_in, 6),
                "end_native_balance": round(eth_balance, 6),
                "start_balance_source": "reconstructed: end_native_balance + native_outflow - native_inflow",
                "end_balance_source": "native balance latest",
                "historical_balance_verified": False,
                "balance_source": "end=native balance latest; start=reconstructed from window flows",
                "flow_in":          eth_in_usd,
                "flow_out":         eth_out_usd,
                "balance":          eth_bal_usd,
                "pre_window_balance": round(eth_bal_usd + eth_out_usd - eth_in_usd, 2),
                "truncated":        len(normal_txs) >= PAGE_SIZE * MAX_PAGES,
                "tx_count":         eth_tx_count,
                "is_fast_transit":  (eth_in_usd > 10_000 and eth_bal_usd < eth_in_usd * 0.05
                                     and eth_out_usd > eth_in_usd * 0.9),
                "taint_in": 0.0, "taint_out": 0.0,
                "eth_amount_in":  round(eth_in, 6),
                "eth_amount_out": round(eth_out, 6),
                "eth_balance":    round(eth_balance, 6),
            }
            # ETH 不计入稳定币评分分母，单独记录供 % of Flow 展示用
            report.total_eth_usd_in  += eth_in_usd
            report.total_eth_usd_out += eth_out_usd
            if eth_in_usd or eth_out_usd:
                print(f"  [{chain_label}] ETH: 流入 {eth_in:.4f} (${eth_in_usd:,.0f}) / "
                      f"流出 {eth_out:.4f} (${eth_out_usd:,.0f}) / 余额 {eth_balance:.4f}")
            is_eth_fast_transit = (
                eth_in_usd > 10_000
                and eth_bal_usd < eth_in_usd * 0.05
                and eth_out_usd > eth_in_usd * 0.9
            )
            if is_eth_fast_transit:
                report.warnings.append(
                    f"[{chain_label}][ETH] Fast transit: inflow {eth_in:.4f} ETH (${eth_in_usd:,.0f}) / "
                    f"outflow {eth_out:.4f} ETH (${eth_out_usd:,.0f}) / balance {eth_balance:.4f} ETH"
                )

        # ETH 交易加入 report.transactions，供 counterparty_table 使用（金额以 USD 计）
        _eth_proto = {"0x0000000000000000000000000000000000000000"}
        for tx in normal_txs:
            frm = normalize(tx.get("from", ""))
            t   = normalize(tx.get("to", "") or "")
            try:
                val = int(tx.get("value", "0") or "0") / 1e18
            except Exception:
                val = 0.0
            if val <= 0:
                continue
            direction = counterparty = ""
            if t == addr_norm:
                direction, counterparty = "IN", frm
            elif frm == addr_norm:
                direction, counterparty = "OUT", t
            if direction and counterparty and counterparty not in _eth_proto:
                report.transactions.append({
                    "ts":           tx.get("timeStamp", ""),
                    "direction":    direction,
                    "amount":       round(val, 6),          # 原始 ETH，不转 USD
                    "amount_usd":   round(val * self.eth_price_usd, 2),  # 仅供 total_usd 计算
                    "sym":          chain_cfg.native_token,
                    "method_id":     tx.get("methodId", ""),
                    "method":        tx.get("functionName", "") or tx.get("methodId", "") or "Transfer",
                    "action_type":   "Native Transfer",
                    "chain":        chain_name,
                    "counterparty": counterparty.lower(),
                    "tx_hash":      tx.get("hash", ""),
                })

        self._build_contract_interactions(
            report, normal_txs, token_txs, chain_cfg, chain_name, address
        )

        usdt_logs = []
        if len(normal_txs) == 0 and len(token_txs) == 0:
            print(f"  [{chain_label}] txlist/tokentx 无结果，尝试稳定币 getLogs...")
            usdt_logs = self._get_usdt_logs(address, client, chain_cfg,
                                            from_block=from_block, to_block=to_block)
            if usdt_logs:
                print(f"  [{chain_label}] getLogs 获取到 {len(usdt_logs)} 条稳定币 Transfer 事件")

        # 去重合并
        _seen: Set[tuple] = set()
        all_txs = []
        for tx in normal_txs + token_txs:
            k = (tx.get("hash", ""),
                 normalize(tx.get("from", "")),
                 normalize(tx.get("to", "") or tx.get("contractAddress", "")))
            if k not in _seen:
                _seen.add(k)
                all_txs.append(tx)

        if time_cutoff > 0 and usdt_logs:
            before = len(usdt_logs)
            usdt_logs = [lg for lg in usdt_logs if int(lg.get("timeStamp", 0)) >= time_cutoff]
            if before != len(usdt_logs):
                print(f"  [{chain_label}] getLogs 时间过滤: {before}→{len(usdt_logs)}")

        report.total_transactions += len(all_txs) + len(usdt_logs)
        print(f"  [{chain_label}] {len(normal_txs)} 普通 + {len(token_txs)} 稳定币Token"
              + (f" + {len(usdt_logs)} getLogs事件" if usdt_logs else ""))

        PROTOCOL_CONTRACTS = {
            chain_cfg.usdt_contract,
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC ETH
            "0x0000000000000000000000000000000000000000",
        }

        counterparties: Set[str] = set()
        counterparty_dir_stats: Dict[str, Dict[str, int]] = {}
        counterparty_stats: Dict[str, Dict] = {}
        # 记录被分析地址与每个对手方的实际 USDT 往来（用于 2-hop 金额）
        cp_usdt_flow: Dict[str, Dict[str, float]] = {}  # cp -> {"IN": x, "OUT": y}

        # 风险积累器：key = (counterparty, risk_type, via_address)
        risky_accum: Dict[tuple, dict] = {}

        def _add_risk(cp: str, risk_type: str, category: str, weight: float,
                      direction: str, usdt_amt: float, tx_hash: str, ts: str,
                      hop: int = 1, via: str = "", token: str = "",
                      native_amt: float = 0.0):
            key = (cp, risk_type, via)
            if key not in risky_accum:
                risky_accum[key] = {
                    "category": category, "category_weight": weight,
                    "counterparty": cp, "in_usdt": 0.0, "out_usdt": 0.0,
                    "tx_hashes": [], "timestamps": [], "hop": hop, "via_address": via,
                    "token": token,
                    # 非稳定币转账的原始金额（按方向累加）
                    "native_in": {},   # {sym: amount}
                    "native_out": {},  # {sym: amount}
                }
            entry = risky_accum[key]
            if direction == "IN":
                entry["in_usdt"] += usdt_amt
                if native_amt > 0 and token:
                    entry["native_in"][token] = entry["native_in"].get(token, 0.0) + native_amt
            else:
                entry["out_usdt"] += usdt_amt
                if native_amt > 0 and token:
                    entry["native_out"][token] = entry["native_out"].get(token, 0.0) + native_amt
            if tx_hash and len(entry["tx_hashes"]) < 5:
                entry["tx_hashes"].append(tx_hash)
                entry["timestamps"].append(ts)

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

            sym = (tx.get("_sym") or tx.get("tokenSymbol") or "ETH").upper()
            is_stable = sym in STABLECOIN_SYMBOLS
            is_eth = (sym == "ETH")
            try:
                dec = int(tx.get("tokenDecimal", "18") or "18")
                if sym == "DAI": dec = 18
                amt = int(tx.get("value", "0") or "0") / (10 ** dec)
            except Exception:
                amt = 0.0
            # 污染评分：稳定币用面值，ETH 用折 USD（其他代币不参与评分）
            usdt_amt = amt if is_stable else (amt * self.eth_price_usd if is_eth else 0.0)

            # 流量已在 per-asset 循环里累加，这里只做 chain 分链记录
            if is_stable:
                if direction == "IN":
                    chain_inflow += amt
                else:
                    chain_outflow += amt

            counterparties.add(other)
            counterparty_dir_stats.setdefault(other, {"IN": 0, "OUT": 0})[direction] += 1
            s = counterparty_stats.setdefault(other, {"count": 0, "total_value": 0.0, "max_value": 0.0})
            s["count"] += 1
            if is_stable:
                s["total_value"] += amt
                s["max_value"] = max(s["max_value"], amt)
                # 记录实际稳定币边金额，供 2-hop 评分使用
                flow = cp_usdt_flow.setdefault(other, {"IN": 0.0, "OUT": 0.0})
                flow[direction] += amt

            tx_hash = tx.get("hash", "")
            ts = tx.get("timeStamp", "")

            for chk, chk_dir in [(to, "OUT" if frm == addr_norm else "IN"),
                                  (frm, "IN"  if frm != addr_norm else "OUT")]:
                if not chk or chk == addr_norm or chk in PROTOCOL_CONTRACTS:
                    continue

                # native_amt 只给非稳定币 ERC20（ETH 已折 USD 进 usdt_amt，不需要再走 native）
                _native_amt = amt if (not is_stable and not is_eth) else 0.0

                if chk in self.blacklist:
                    _add_risk(chk, "blacklist", "blacklist",
                              CATEGORY_WEIGHTS["blacklist"], chk_dir, usdt_amt, tx_hash, ts,
                              token=sym, native_amt=_native_amt)

                if chk in OFAC_SANCTIONED_ADDRS:
                    ofac_info = OFAC_SANCTIONED[chk]
                    _add_risk(chk, "ofac_sanctioned", "ofac_sanctioned",
                              CATEGORY_WEIGHTS["ofac_sanctioned"], chk_dir, usdt_amt, tx_hash, ts,
                              via=ofac_info.get("entity", ""),
                              token=sym, native_amt=_native_amt)

                if chk in MIXER_CONTRACTS:
                    report.mixer_interactions.append({
                        "mixer": MIXER_CONTRACTS[chk], "contract": chk,
                        "tx": tx_hash, "direction": chk_dir, "chain": chain_name,
                    })
                    _add_risk(chk, "mixer", "mixer",
                              CATEGORY_WEIGHTS["mixer"], chk_dir, usdt_amt, tx_hash, ts,
                              token=sym, native_amt=_native_amt)

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
                                  CATEGORY_WEIGHTS["opaque_bridge"], chk_dir, usdt_amt, tx_hash, ts,
                                  token=sym, native_amt=_native_amt)

                if chk in HIGH_RISK_EXCHANGES:
                    report.high_risk_exchanges.append({
                        "exchange": HIGH_RISK_EXCHANGES_FLAT[chk], "contract": chk,
                        "tx": tx_hash, "direction": chk_dir, "chain": chain_name,
                    })
                    _add_risk(chk, "high_risk_exchange", "high_risk_exchange",
                              CATEGORY_WEIGHTS["high_risk_exchange"], chk_dir, usdt_amt, tx_hash, ts,
                              token=sym, native_amt=_native_amt)

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
              f"稳定币流入 {chain_inflow:,.2f} / 流出 {chain_outflow:,.2f}")

        # ── 风险积累器 → RiskIndicator（1-hop）────────────────────────
        for (cp, risk_type, via), data in risky_accum.items():
            hop_d = HOP_DECAY[data["hop"]]
            # 合并所有方向的原始非稳定币数量，供 counterparty_table 补 by_sym 用
            all_native = {}
            for sym_k, v in data.get("native_in",  {}).items():
                all_native[sym_k] = all_native.get(sym_k, 0.0) + v
            for sym_k, v in data.get("native_out", {}).items():
                all_native[sym_k] = all_native.get(sym_k, 0.0) + v

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
                        token=data.get("token", ""),
                        native_amounts=all_native,
                    ))
            if data["in_usdt"] == 0.0 and data["out_usdt"] == 0.0:
                # 构造实际转账说明（非稳定币）
                native_parts = []
                for sym_k, v in data.get("native_in", {}).items():
                    native_parts.append(f"received {v:,.4f} {sym_k}")
                for sym_k, v in data.get("native_out", {}).items():
                    native_parts.append(f"sent {v:,.4f} {sym_k}")
                if native_parts:
                    native_note = ", ".join(native_parts)
                else:
                    token_name = data.get("token", "")
                    tx_count = len(data['tx_hashes'])
                    if token_name and token_name != "ETH":
                        native_note = f"{tx_count} contract call(s) to {token_name}, no token transfer (possibly approve/allowance)"
                    else:
                        native_note = f"{tx_count} contract call(s), no ETH/token transfer (possibly approve or other contract interaction)"
                report.indicators.append(RiskIndicator(
                    indicator_type=f"{risk_type}_no_stable",
                    category=data["category"],
                    category_weight=data["category_weight"],
                    counterparty=cp, direction="UNKNOWN", amount_usdt=0.0,
                    hop=data["hop"], hop_decay=hop_d,
                    tx_hashes=data["tx_hashes"], timestamps=data["timestamps"],
                    via_address=data["via_address"],
                    chain=chain_name,
                    note=native_note,
                    native_amounts=all_native,
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

        def _score_cp_node(txs, cp_addr) -> Dict[str, tuple]:
            """计算 cp 的真实污染比例（taint_ratio）。

            公式：taint_ratio = Σ(风险往来金额 × 类别权重) / cp 该方向 USDT 总流量

            返回 {direction: (taint_ratio, best_category, best_risky_entity, tx_hash, ts)}
            - taint_ratio: 0~1，cp 在该方向上有多少比例的资金与风险实体相关
            - best_category: 权重最高的风险类别（用于展示和 floor 判断）
            - best_risky_entity: 对应的风险地址（溯源证据）
            后续可在此函数内加入洗钱手法识别（peel chain、structuring 等）。
            """
            in_total  = 0.0   # cp 的 USDT 总流入（样本）
            out_total = 0.0   # cp 的 USDT 总流出（样本）
            in_risky_weighted  = 0.0  # Σ(risky_usdt × weight)，IN 方向
            out_risky_weighted = 0.0  # Σ(risky_usdt × weight)，OUT 方向
            best_in  = None   # (cat, weight, risky_addr, hash, ts)
            best_out = None

            for tx in txs:
                t = normalize(tx.get("to", "") or "")
                f = normalize(tx.get("from", "") or "")
                if f == cp_addr and t and t != cp_addr:
                    other, d = t, "OUT"
                elif t == cp_addr and f and f != cp_addr:
                    other, d = f, "IN"
                else:
                    continue
                if not other or other == addr_norm or other in PROTOCOL_CONTRACTS:
                    continue

                sym = (tx.get("tokenSymbol") or "").upper()
                try:
                    dec = int(tx.get("tokenDecimal", "18") or "18")
                    amt = int(tx.get("value", "0") or "0") / (10 ** dec)
                except Exception:
                    amt = 0.0
                usdt = amt if sym in STABLECOIN_SYMBOLS else 0.0

                h  = tx.get("hash", "")
                ts = tx.get("timeStamp", "")

                # 累计 cp 的总稳定币流量（分子分母都需要）
                if d == "IN":
                    in_total += usdt
                else:
                    out_total += usdt

                # 识别 other 的风险类别（取最高权重）
                risk_cat, risk_w = None, 0.0
                if other in self.blacklist and CATEGORY_WEIGHTS["blacklist"] > risk_w:
                    risk_cat, risk_w = "blacklist", CATEGORY_WEIGHTS["blacklist"]
                if other in MIXER_CONTRACTS and CATEGORY_WEIGHTS["mixer"] > risk_w:
                    risk_cat, risk_w = "mixer", CATEGORY_WEIGHTS["mixer"]
                if other in OPAQUE_BRIDGE_ADDRS and CATEGORY_WEIGHTS["opaque_bridge"] > risk_w:
                    risk_cat, risk_w = "opaque_bridge", CATEGORY_WEIGHTS["opaque_bridge"]
                if other in HIGH_RISK_EXCHANGES_FLAT and CATEGORY_WEIGHTS["high_risk_exchange"] > risk_w:
                    risk_cat, risk_w = "high_risk_exchange", CATEGORY_WEIGHTS["high_risk_exchange"]
                if other in ALL_BRIDGE_ADDRS and other not in OPAQUE_BRIDGE_ADDRS \
                        and CATEGORY_WEIGHTS["transparent_bridge"] > risk_w:
                    risk_cat, risk_w = "transparent_bridge", CATEGORY_WEIGHTS["transparent_bridge"]

                if risk_cat:
                    if d == "IN":
                        in_risky_weighted += usdt * risk_w
                        if best_in is None or risk_w > best_in[1]:
                            best_in = (risk_cat, risk_w, other, h, ts)
                    else:
                        out_risky_weighted += usdt * risk_w
                        if best_out is None or risk_w > best_out[1]:
                            best_out = (risk_cat, risk_w, other, h, ts)

            result: Dict[str, tuple] = {}
            if best_in is not None:
                taint = min(in_risky_weighted / in_total, 1.0) if in_total > 0 else 0.0
                result["IN"] = (taint, best_in[0], best_in[2], best_in[3], best_in[4])
            if best_out is not None:
                taint = min(out_risky_weighted / out_total, 1.0) if out_total > 0 else 0.0
                result["OUT"] = (taint, best_out[0], best_out[2], best_out[3], best_out[4])
            return result

        if HOP2_ENABLED and counterparties:
            # 2-hop 中间节点：排除已知高风险地址（它们已在 1-hop 检测到）
            # 优先分析有实际稳定币/ETH 往来的对手方，最多 3 个（控制 API 调用量）
            hop2_candidates = sorted(
                [cp for cp in counterparties if cp not in _protocol_excl],
                key=lambda cp: cp_usdt_flow.get(cp, {}).get("IN", 0) + cp_usdt_flow.get(cp, {}).get("OUT", 0),
                reverse=True,
            )[:5]
            hop2_nodes = hop2_candidates
            if hop2_nodes:
                print(f"  [{chain_label}] 2-hop 分析 {len(hop2_nodes)} 个中间节点...")

            hop_d = HOP_DECAY[2]
            for cp in hop2_nodes:
                time.sleep(REQUEST_DELAY)
                cp_txs = client.get_normal_txs(cp, limit=100)
                cp_tok = client.get_token_transfers(cp, limit=100)
                cp_risk = _score_cp_node(cp_txs + cp_tok, cp)
                if not cp_risk:
                    continue

                # cp 是被评分的节点：counterparty=cp, via_address=cp 接触的风险实体
                # d 是 CP 相对于风险实体的方向，≠ 被分析地址相对于 CP 的方向。
                # 修正：对每个被分析地址↔CP 的实际稳定币边（IN/OUT），取 cp_risk 最高污染比例。
                edge = cp_usdt_flow.get(cp, {})
                # 为每个 analyzed_dir 取 cp_risk 中最高的 taint_ratio
                best: Dict[str, tuple] = {}  # analyzed_dir -> (taint_ratio, cat, risky_entity, h, ts)
                for d, (taint_ratio, cat, risky_entity, h, ts) in cp_risk.items():
                    if taint_ratio == 0:
                        continue
                    for analyzed_dir in ("IN", "OUT"):
                        if edge.get(analyzed_dir, 0.0) <= 0:
                            continue
                        if analyzed_dir not in best or taint_ratio > best[analyzed_dir][0]:
                            best[analyzed_dir] = (taint_ratio, cat, risky_entity, h, ts)
                for analyzed_dir, (taint_ratio, cat, risky_entity, h, ts) in best.items():
                    report.indicators.append(RiskIndicator(
                        indicator_type=f"cp_node_{cat}",
                        category=cat,
                        category_weight=taint_ratio,  # cp 的真实污染比例，非类别权重常量
                        counterparty=cp,
                        direction=analyzed_dir,
                        amount_usdt=edge.get(analyzed_dir, 0.0),
                        hop=2,
                        hop_decay=hop_d,
                        tx_hashes=[h] if h else [],
                        timestamps=[ts] if ts else [],
                        via_address=risky_entity,
                        chain=chain_name,
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

        # 分母：稳定币 + ETH 折 USD，与分子保持一致（分子已含 ETH usdt_amt）
        total_in  = report.total_inflow_usdt  + report.total_eth_usd_in
        total_out = report.total_outflow_usdt + report.total_eth_usd_out
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

        taint_ratio = max(received_taint, sent_taint)

        if total_flow == 0 and presence_only:
            report.warnings.append("No stablecoin or ETH transactions found. Score based on association only — accuracy limited.")

        # Presence-only: interactions with risk entities but no stablecoin/ETH transfer
        # Does not affect score, surfaced for manual review.
        _category_en = {
            "blacklist":          "Blacklist",
            "ofac_sanctioned":    "OFAC Sanctioned",
            "mixer":              "Mixer",
            "opaque_bridge":      "Opaque Bridge",
            "high_risk_exchange": "High-Risk Exchange",
        }
        for ind in presence_only:
            label   = _category_en.get(ind.category, ind.category.replace("_", " ").title())
            hop_tag = f"{ind.hop}-hop " if ind.hop > 1 else ""
            via     = f" via {ind.via_address[:10]}..." if ind.via_address else ""
            if ind.native_amounts:
                parts  = [f"{v:,.4f} {s}" for s, v in ind.native_amounts.items()]
                detail = f"transferred: {', '.join(parts)}"
            elif ind.note:
                detail = ind.note
            else:
                detail = "no fund transfer detected"
            report.warnings.append(
                f"[Non-financial contact] {hop_tag}{label}: {ind.counterparty}{via}"
                f" — {detail} (not scored)"
            )

        report.received_exposure = round(received_taint, 4)
        report.sent_exposure     = round(sent_taint, 4)
        report.taint_ratio       = round(taint_ratio, 4)
        final_score = round(min(taint_ratio * 100, 100), 2)
        report.risk_score = final_score

        hop2_cats = {ind.category for ind in report.indicators if ind.hop == 2 and ind.amount_usdt > 0}

        if report.risk_score >= 80:
            report.risk_level = "CRITICAL"
        elif report.risk_score >= 45:
            report.risk_level = "HIGH"
        elif report.risk_score >= 20:
            report.risk_level = "MEDIUM"
        else:
            report.risk_level = "LOW"

        report.score_breakdown = {
            "received_taint_pct": round(received_taint * 100, 2),
            "sent_taint_pct":     round(sent_taint * 100, 2),
            "final_score":        final_score,
            "hop2_categories":    sorted(hop2_cats),
        }

        # ── 对手方聚合表 ────────────────────────────────────────────────
        self._build_counterparty_table(report)

    def _build_counterparty_table(self, report: RiskReport):
        """按 (地址, 方向) 聚合所有稳定币流水，附加风险标签和污染贡献。"""
        from collections import defaultdict

        # 聚合: key=(counterparty, direction) → {sym: amount}
        # 稳定币 amount = USD 面值；原生代币(ETH/BNB等) amount = 原始数量
        agg: Dict[tuple, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        # total_usd = 稳定币 + 原生代币折 USD，用于排序
        agg_usd: Dict[tuple, float] = defaultdict(float)
        # stable_usd = 仅稳定币 USD，用于稳定币表"Total"列和 % of Flow
        agg_stable_usd: Dict[tuple, float] = defaultdict(float)
        # native_usd = 仅原生代币折 USD（有 amount_usd 字段的），用于 ETH 表 % of Flow
        agg_native_usd: Dict[tuple, float] = defaultdict(float)
        for tx in report.transactions:
            key = (tx["counterparty"].lower(), tx["direction"])
            agg[key][tx["sym"]] += tx["amount"]
            # amount_usd 只有原生代币(ETH/BNB)才有，稳定币用 amount，其他 ERC20 用 0
            native_usd_val = tx.get("amount_usd", 0.0)
            if tx["sym"] in STABLECOIN_SYMBOLS:
                agg_stable_usd[key] += tx["amount"]
                agg_usd[key] += tx["amount"]
            elif native_usd_val:          # 原生代币（有 amount_usd）
                agg_native_usd[key] += native_usd_val
                agg_usd[key] += native_usd_val
            # 其他 ERC20：不计入 agg_usd（无可靠 USD 价格）

        # 从 indicators 取各对手方的污染贡献（分母与评分保持一致：稳定币 + ETH）
        total_in  = report.total_inflow_usdt  + report.total_eth_usd_in
        total_out = report.total_outflow_usdt + report.total_eth_usd_out
        taint_by_cp: Dict[str, float] = {}   # counterparty.lower() → taint_pct
        for ind in report.indicators:
            if ind.amount_usdt == 0.0:
                continue
            basis = total_in if ind.direction == "IN" else total_out
            if basis > 0:
                pct = ind.amount_usdt * ind.category_weight * ind.hop_decay / basis * 100
                cp_key = ind.counterparty.lower()
                taint_by_cp[cp_key] = taint_by_cp.get(cp_key, 0.0) + pct

        # 数据库查询：对手方风险标签
        def _get_tags(addr: str) -> List[str]:
            tags = []
            a = addr.lower()
            if a in self.blacklist:
                tags.append("blacklist")
            if a in OFAC_SANCTIONED_ADDRS:
                tags.append("ofac_sanctioned")
            if a in {c.lower() for c in MIXER_CONTRACTS}:
                tags.append("mixer")
            if a in {c.lower() for c in OPAQUE_BRIDGE_ADDRS}:
                tags.append("opaque_bridge")
            if a in {c.lower() for c in HIGH_RISK_EXCHANGES_FLAT}:
                tags.append("high_risk_exchange")
            return tags

        rows = []
        existing_cps: Set[tuple] = set()
        for (cp, direction), by_sym in agg.items():
            total_usd = agg_usd[(cp, direction)]
            existing_cps.add((cp, direction))
            rows.append({
                "address":         cp,
                "direction":       direction,
                "total_usd":       round(total_usd, 2),
                "stable_usd":      round(agg_stable_usd[(cp, direction)], 2),
                "native_usd":      round(agg_native_usd[(cp, direction)], 2),
                "by_sym":          {sym: round(v, 6 if sym not in STABLECOIN_SYMBOLS else 2)
                                    for sym, v in sorted(by_sym.items())},
                "risk_tags":       _get_tags(cp),
                "taint_pct":       round(taint_by_cp.get(cp, 0.0), 2),
                "contract_only":   False,
            })

        # 合约交互（presence_only）：value=0 的黑名单/mixer 联系，不在 transactions 里
        # 补入 CP 表格，让它们在 Entity 列显示风险标签，direction 用 CONTACT
        seen_contact: Set[str] = set()
        for ind in report.indicators:
            if ind.amount_usdt != 0.0:
                continue
            cp = ind.counterparty.lower()
            if cp in seen_contact:
                continue
            seen_contact.add(cp)
            # 如果该 CP 已有实际转账行，在那行的 risk_tags 里补上标签即可，不重复加行
            matched = [r for r in rows if r["address"] == cp]
            if matched:
                for r in matched:
                    for tag in _get_tags(cp):
                        if tag not in r["risk_tags"]:
                            r["risk_tags"].append(tag)
            else:
                # 完全没有资金往来的合约交互，单独加一行
                rows.append({
                    "address":       cp,
                    "direction":     ind.direction if ind.direction != "UNKNOWN" else "CONTACT",
                    "total_usd":     0.0,
                    "by_sym":        {},
                    "risk_tags":     _get_tags(cp),
                    "taint_pct":     0.0,
                    "contract_only": True,
                    "contact_note":  ind.note or "contract interaction",
                })

        # 把 indicator 里记录的非稳定币原始数量补进对应 CP 行的 by_sym
        # 这样风险对手方（黑名单/Mixer/OFAC）涉及的 LINK/BNB 等也能在 token 表里显示
        for ind in report.indicators:
            if not ind.native_amounts:
                continue
            cp = ind.counterparty.lower()
            for row in rows:
                if row["address"] == cp:
                    for sym, amt in ind.native_amounts.items():
                        if sym not in row["by_sym"]:
                            row["by_sym"][sym] = 0.0
                        row["by_sym"][sym] = round(row["by_sym"][sym] + amt, 6)

        # 排序：有资金往来的按金额降序，纯合约交互排最后
        rows.sort(key=lambda r: (r.get("contract_only", False),
                                 r["direction"] == "OUT",
                                 -r["total_usd"]))
        report.counterparty_table = rows

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
                # 默认只跑 Ethereum；跨链活动由 BridgeTracer 在链内追踪
                # 需要多链分析时用 --chains ethereum,bsc,polygon 显式指定
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
            report.warnings.append(f"[!] Address is on the USDT blacklist (banned: {info['time']})")
            print(f"  [!!!] 直接命中黑名单！封禁时间: {info['time']}")

        if addr_norm in OFAC_SANCTIONED_ADDRS:
            ofac = OFAC_SANCTIONED[addr_norm]
            report.is_blacklisted = True
            report.blacklist_time = "OFAC制裁"
            entity = ofac.get("entity", "Unknown")
            currency = ofac.get("currency", "")
            report.warnings.append(f"[!] Address is on the OFAC SDN sanctions list (entity: {entity}, currency: {currency})")
            print(f"  [!!!] 直接命中 OFAC 制裁名单！实体: {entity}")

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


def print_transactions(report: RiskReport, show_all: bool = False) -> None:
    """打印完整稳定币流水表格（--full 时调用）。"""
    txs = sorted(report.transactions, key=lambda x: x.get("ts", ""), reverse=True)
    if not txs:
        print("  （无稳定币流水记录）")
        return

    # 构建风险地址集合用于标注
    risk_cps = {ind.counterparty: ind.category for ind in report.indicators if ind.amount_usdt > 0}

    limit = len(txs) if show_all else min(len(txs), 200)
    print(f"\n{'='*90}")
    print(f"  完整稳定币流水（共 {len(txs)} 笔，显示 {limit} 笔）")
    print(f"{'='*90}")
    # 把方向直接写出来：IN ← / OUT →，比单纯 ±/箭头直观
    print(f"  {'时间(UTC)':<20} {'方向':<6} {'金额':>14} {'资产':<6} {'链':<10} {'对手方地址':<44} {'风险标签'}")
    print(f"  {'─'*88}")

    for tx in txs[:limit]:
        ts = tx.get("ts", "")
        try:
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            dt = ts
        direction = tx.get("direction", "")
        amount    = tx.get("amount", 0.0)
        sym       = tx.get("sym", "")
        chain     = tx.get("chain", "")
        cp        = tx.get("counterparty", "")
        label     = risk_cps.get(cp, "")
        # IN/OUT 直接写出来，arrow 当辅助记号
        if direction == "IN":
            dir_str = "IN ←"
        elif direction == "OUT":
            dir_str = "OUT→"
        else:
            dir_str = direction or "─"
        print(f"  {dt:<20} {dir_str:<6} {amount:>14,.4f} {sym:<6} {chain:<10} {cp:<44} {label}")

    if limit < len(txs):
        print(f"  ... 还有 {len(txs)-limit} 笔，加 --full 显示全部")


def _short_addr(addr: str, head: int = 8, tail: int = 6) -> str:
    if not addr:
        return "—"
    if len(addr) <= head + tail + 3:
        return addr
    return f"{addr[:head]}…{addr[-tail:]}"


def print_contract_interactions(report: RiskReport, limit: int = 30) -> None:
    """打印合约交互明细：每条 tx 一行外层 + 每条 token effect 一条子行，
    显式标注 IN/OUT + from/to，方便排查 TOKEN_ONLY 类异常。"""
    inters = report.contract_interactions or []
    if not inters:
        return

    total = len(inters)
    shown = min(limit, total)
    print(f"\n{'='*100}")
    print(f"  合约交互明细（共 {total} 笔，显示 {shown} 笔；TOKEN_ONLY = 没匹到外壳交易）")
    print(f"{'='*100}")

    for it in inters[:shown]:
        ts = it.get("ts", "")
        try:
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if ts else "—"
        except Exception:
            dt = str(ts)
        direction = it.get("direction", "")
        action    = it.get("action_type", "")
        method_lb_raw = it.get("method_label") or it.get("method") or ""
        # 兼容旧数据：methodId 可能是 "0x"（input data 占位），不当作 selector 显示
        if method_lb_raw.strip().lower() in ("", "0x"):
            method_lb_raw = "Transfer" if it.get("native_value", 0) >= 0 and not it.get("input_present") else "—"
        method_lb = method_lb_raw
        method_id = it.get("method_id", "")
        if method_id.strip().lower() == "0x":
            method_id = ""
        tx_hash   = it.get("tx_hash", "")
        status    = it.get("status", "")
        chain     = it.get("chain", "")

        # 外层方向：TOKEN_ONLY 时单独标识
        if direction == "IN":
            dir_str = "IN ←"
        elif direction == "OUT":
            dir_str = "OUT→"
        elif direction == "TOKEN_ONLY":
            dir_str = "TOKEN"   # 没匹到外壳，资金动作全部看下方 effects
        else:
            dir_str = direction or "—"

        # method_label 已是可读名；如果还是 unknown(0x..) 顺带带出 action_type 帮助理解
        method_show = method_lb
        if method_id and method_id.lower() not in method_show.lower() and method_show.startswith("unknown"):
            pass   # 已包含 selector
        elif method_id and method_id.lower() not in method_show.lower():
            method_show = f"{method_lb} ({method_id})"

        print(f"\n  [{dt}] {dir_str:<6} {action:<32}  method: {method_show}")
        print(f"     tx:    {tx_hash}  chain={chain}  status={status}")

        # token effects：每条单独打印，显式 from / to
        effects = it.get("token_effects", []) or []
        if not effects and direction in ("IN", "OUT") and it.get("native_value", 0) > 0:
            nv = it["native_value"]
            print(f"     └─ {dir_str:<5} {nv:>14,.6f} ETH   (native value)")
        for eff in effects:
            e_dir = eff.get("direction", "")
            if e_dir == "IN":
                edir_str = "IN ←"
            elif e_dir == "OUT":
                edir_str = "OUT→"
            else:
                edir_str = e_dir or "OTHER"
            amt   = eff.get("amount", 0.0)
            sym   = eff.get("sym", "")
            frm_a = eff.get("from", "") or "—"
            to_a  = eff.get("to", "") or "—"
            stable_mark = " ★stable" if eff.get("is_stablecoin") else ""
            inner_mid = eff.get("method_id", "")
            inner_lbl = eff.get("method_label", "") or ""
            inner_show = f"  inner-method: {inner_lbl}" if inner_lbl and inner_lbl != method_show else ""
            print(f"     └─ {edir_str:<5} {amt:>14,.6f} {sym:<8}{stable_mark}  "
                  f"from {_short_addr(frm_a)}  →  to {_short_addr(to_a)}{inner_show}")

    if shown < total:
        print(f"\n  ... 还有 {total - shown} 笔未显示")


def print_report(report: RiskReport, use_color: bool = True, output_dir: str = ""):
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
    print(f"  稳定币流入: {report.total_inflow_usdt:>12,.2f}  |  流出: {report.total_outflow_usdt:>12,.2f}")
    # 每种稳定币明细
    if report.per_asset:
        print(f"  {'─'*66}")
        print(f"  {'资产':<10} {'流入(窗口内)':>14} {'流出(窗口内)':>14} {'当前余额':>12} {'窗口前余额':>12} {'笔数':>6}")
        for key in sorted(report.per_asset):
            a = report.per_asset[key]
            transit = " ⚡" if a.get("is_fast_transit") else ""
            trunc   = " !" if a.get("truncated") else ""
            pre = a.get("pre_window_balance", 0.0)
            pre_str = f"{pre:>12,.2f}" + (" [?]" if pre < -1 else "")
            sym_label = f"{a['sym']}@{a['chain']}"
            print(f"  {sym_label:<10} {a['flow_in']:>14,.2f} {a['flow_out']:>14,.2f} "
                  f"{a['balance']:>12,.2f} {pre_str} {a.get('tx_count',0):>6}{transit}{trunc}")

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
        print(f"    收入侧污染:   {bd['received_taint_pct']:>6.2f}%  "
              f"(收到来自风险地址的稳定币占总流入的比例 × 类别权重)")
        print(f"    转出侧污染:   {bd['sent_taint_pct']:>6.2f}%  "
              f"(转入风险地址的稳定币占总流出的比例 × 类别权重)")
        print(f"    最终得分:     {lc}{bd['final_score']}/100{rc}")
        print(f"  {'─'*54}")

    if report.is_blacklisted:
        print(f"\n  {lc}[!!!] 该地址已被 USDT 直接封禁{rc}")
        print(f"        封禁时间: {report.blacklist_time}")

    if report.warnings:
        print(f"\n  警告:")
        for w in report.warnings:
            print(f"    ⚠ {w}")

    # ── 对手方风险明细表 ─────────────────────────────────────────────────
    if report.counterparty_table:
        rows = report.counterparty_table
        # 收集出现过的币种，固定顺序
        sym_order = ["USDT", "USDC", "DAI", "BUSD", "USDC.E", "USDCE", "USDB", "DOLA"]
        active_syms = [s for s in sym_order
                       if any(s in r["by_sym"] for r in rows)]
        # 如果有未在 sym_order 里的币种，追加
        extra = sorted({s for r in rows for s in r["by_sym"]} - set(sym_order))
        active_syms += extra

        total_in_all  = report.total_inflow_usdt
        total_out_all = report.total_outflow_usdt

        tag_label = {
            "blacklist":          "黑名单",
            "ofac_sanctioned":    "OFAC制裁",
            "mixer":              "混币器",
            "opaque_bridge":      "不透明桥",
            "high_risk_exchange": "高风险所",
        }
        tag_color = {
            "blacklist":          "\033[91m",
            "ofac_sanctioned":    "\033[91m",
            "mixer":              "\033[93m",
            "opaque_bridge":      "\033[93m",
            "high_risk_exchange": "\033[33m",
        } if use_color else {}
        RESET = "\033[0m" if use_color else ""

        # 动态计算地址列宽（最长地址 vs 列头 "地址"）
        max_addr_len = max((len(r["address"]) for r in rows), default=10)
        addr_w = max(max_addr_len, 10)

        # 币种列宽
        sym_w = {s: max(len(s), 10) for s in active_syms}

        # 表头：方向直接写 IN/OUT，比 ←/→ 直观
        header_parts = [
            f"{'方向':<6}",
            f"{'地址':<{addr_w}}",
            f"{'USD总额':>12}",
            f"{'占总流量':>8}",
        ]
        for s in active_syms:
            header_parts.append(f"{s:>{sym_w[s]}}")
        header_parts += ["  风险标签", "  → 污染贡献"]
        header = "  " + "  ".join(header_parts)

        sep_len = len(header) + 4
        print(f"\n  【对手方风险明细】")
        print(f"  {'─' * (sep_len - 2)}")
        print(header)
        print(f"  {'─' * (sep_len - 2)}")

        # 尘埃过滤：金额 < $1 且无风险标签的行不显示，但在末尾汇总
        DUST_THRESHOLD = 1.0
        dust_rows = [r for r in rows if r["total_usd"] < DUST_THRESHOLD and not r["risk_tags"]]
        visible_rows = [r for r in rows if r["total_usd"] >= DUST_THRESHOLD or r["risk_tags"]]

        for r in visible_rows:
            direction = r["direction"]
            basis = total_in_all if direction == "IN" else total_out_all
            flow_pct = (r["total_usd"] / basis * 100) if basis > 0 else 0.0
            # 显式 IN/OUT，比 ←/→ 直观
            if direction == "IN":
                dir_arrow = "IN ←"
            elif direction == "OUT":
                dir_arrow = "OUT→"
            else:
                dir_arrow = direction or "—"

            # 风险标签字符串（带颜色）
            tag_str = ""
            if r["risk_tags"]:
                parts = []
                for t in r["risk_tags"]:
                    col = tag_color.get(t, "")
                    lbl = tag_label.get(t, t)
                    parts.append(f"{col}[{lbl}]{RESET}")
                tag_str = " ".join(parts)
            else:
                tag_str = "─"

            # 污染贡献
            taint_str = f"★{r['taint_pct']:.2f}%" if r["taint_pct"] > 0 else "─"
            if use_color and r["taint_pct"] > 0:
                taint_str = f"\033[91m★{r['taint_pct']:.2f}%{RESET}"

            row_parts = [
                f"{dir_arrow:<6}",
                f"{r['address']:<{addr_w}}",
                f"{r['total_usd']:>12,.2f}",
                f"{flow_pct:>7.1f}%",
            ]
            for s in active_syms:
                v = r["by_sym"].get(s, 0.0)
                cell = f"{v:>{sym_w[s]},.2f}" if v > 0 else f"{'─':>{sym_w[s]}}"
                row_parts.append(cell)
            row_parts += [f"  {tag_str}", f"  {taint_str}"]
            print("  " + "  ".join(row_parts))

        if dust_rows:
            dust_in  = sum(r["total_usd"] for r in dust_rows if r["direction"] == "IN")
            dust_out = sum(r["total_usd"] for r in dust_rows if r["direction"] == "OUT")
            dust_n   = len(dust_rows)
            print(f"  {'─' * (sep_len - 2)}")
            print(f"  （另有 {dust_n} 个尘埃地址已折叠，"
                  f"收入合计 ${dust_in:,.2f} / 支出合计 ${dust_out:,.2f}，均 < ${DUST_THRESHOLD:.0f}）")
        print(f"  {'─' * (sep_len - 2)}")

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
            print(f"  非稳定币关联（无 USDT/USDC/DAI 金额，不参与污染计算）")
            print(f"  {'─'*54}")
            for ind in pres_inds:
                chain_tag = f"[{ind.chain}] " if ind.chain else ""
                cp = _short(ind.counterparty)
                if ind.hop == 1:
                    path = (f"{cp} ──▶ {x}" if ind.direction == "IN"
                            else f"{x} ──▶ {cp}" if ind.direction == "OUT"
                            else f"{x} ↔ {cp}")
                elif ind.hop == 2:
                    via = _short(ind.via_address) if ind.via_address else "?"
                    path = (f"{cp} ──▶ {via} ──▶ {x}" if ind.direction == "IN"
                            else f"{x} ──▶ {via} ──▶ {cp}" if ind.direction == "OUT"
                            else f"{x} ↔ {via} ↔ {cp}")
                else:
                    via = _short(ind.via_address) if ind.via_address else "?"
                    path = (f"{cp} ──▶ … ──▶ {x}" if ind.direction == "IN"
                            else f"{x} ──▶ … ──▶ {cp}" if ind.direction == "OUT"
                            else f"{x} ↔ … ↔ {cp}")
                note_str = f"  [{ind.note}]" if ind.note else ""
                print(f"    {chain_tag}[{ind.hop}-hop][{ind.category}]  {path}{note_str}")
                if ind.tx_hashes:
                    print(f"      证据tx: {ind.tx_hashes[0][:20]}..."
                          + (f" 等{len(ind.tx_hashes)}笔" if len(ind.tx_hashes) > 1 else ""))
                print(f"      完整地址: {ind.counterparty}")

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

    # 合约交互明细（含 TOKEN_ONLY，方向/from/to 都显式）
    if report.contract_interactions:
        print_contract_interactions(report, limit=30)

    print(f"\n{'='*60}\n")

    # 保存到文件
    if output_dir:
        import io, os
        os.makedirs(output_dir, exist_ok=True)
        fname = os.path.join(output_dir, f"{report.address}.txt")
        buf = io.StringIO()
        import sys as _sys
        _orig = _sys.stdout
        _sys.stdout = buf
        print_report(report, use_color=False, output_dir="")   # 无色版写入文件
        _sys.stdout = _orig
        with open(fname, "w", encoding="utf-8") as fh:
            fh.write(buf.getvalue())
        print(f"  [已保存] {fname}")


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
    parser.add_argument("--days", type=int, default=365, metavar="N",
                        help="只分析最近 N 天的交易（默认 365，0 = 不限）")
    parser.add_argument("--no-hop2",  action="store_true", help="禁用 2 跳分析（加快速度）")
    parser.add_argument("--no-trace", action="store_true", help="禁用透明桥跨链追踪（加快速度）")
    parser.add_argument("--json", metavar="FILE", help="同时导出 JSON 报告到指定文件")
    parser.add_argument("--csv", metavar="FILE", help="批量模式下导出 CSV 汇总表（可用 Excel/Numbers 打开）")
    parser.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    parser.add_argument("--full",   action="store_true", help="打印完整稳定币流水（所有对手方地址和金额）")
    parser.add_argument("--batch", metavar="FILE", help="批量分析：从文件逐行读取地址")
    parser.add_argument("--output", metavar="DIR", help="将每个地址的报告保存为 <DIR>/<地址>.txt")
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
    analyzer  = AMLAnalyzer(blacklist, evm_clients, tronscan, tracer,
                            time_window_days=args.days)

    if args.batch:
        with open(args.batch) as f:
            addresses = [line.strip() for line in f if line.strip()]
        print(f"[*] 批量模式：共 {len(addresses)} 个地址")
        reports = []
        for i, addr in enumerate(addresses, 1):
            print(f"\n[{i}/{len(addresses)}] 处理: {addr}")
            report = analyzer.analyze(addr, chain=args.chain, chains=chains_list)
            print_report(report, use_color=not args.no_color, output_dir=args.output or "")
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
                  f"分数:{r.risk_score:6.2f}  直接黑名单:{bl_cnt}  桥:{bridges}")
        if args.json:
            import dataclasses
            with open(args.json, "w") as f:
                json.dump([dataclasses.asdict(r) for r in reports], f, ensure_ascii=False, indent=2)
            print(f"[INFO] 批量 JSON 已保存: {args.json}")

        if args.csv:
            import csv as _csv
            with open(args.csv, "w", newline="", encoding="utf-8-sig") as f:
                writer = _csv.writer(f)
                writer.writerow([
                    "地址", "链", "风险等级", "分数",
                    "稳定币流入", "稳定币流出", "稳定币余额合计",
                    "黑名单", "OFAC制裁", "快速中转",
                    "1hop类别", "2hop类别",
                    "直接黑名单笔数", "混币器笔数", "不透明桥笔数",
                    "各币种明细",
                    "警告信息",
                ])
                for r in reports:
                    hop1_cats = sorted({ind.category for ind in r.indicators if ind.hop == 1 and ind.amount_usdt > 0})
                    hop2_cats = sorted({ind.category for ind in r.indicators if ind.hop == 2 and ind.amount_usdt > 0})
                    bl_cnt  = sum(1 for ind in r.indicators if ind.category in ("blacklist", "ofac_sanctioned") and ind.hop == 1)
                    mix_cnt = sum(1 for ind in r.indicators if ind.category == "mixer" and ind.hop == 1)
                    ob_cnt  = sum(1 for ind in r.indicators if ind.category == "opaque_bridge" and ind.hop == 1)
                    is_transit = any(a.get("is_fast_transit") for a in r.per_asset.values())
                    total_balance = round(sum(a.get("balance", 0) for a in r.per_asset.values()), 2)
                    # 每种稳定币的流入/流出/余额（展平成多列）
                    asset_detail = "; ".join(
                        "{} 流入{:.0f}/流出{:.0f}/余额{:.2f}{}".format(
                            a["sym"], a["flow_in"], a["flow_out"], a["balance"],
                            "⚡" if a.get("is_fast_transit") else ""
                        )
                        for a in sorted(r.per_asset.values(), key=lambda x: x["sym"])
                        if a["flow_in"] > 0 or a["flow_out"] > 0 or a["balance"] > 0
                    )
                    writer.writerow([
                        r.address,
                        r.chain,
                        r.risk_level,
                        r.risk_score,
                        round(r.total_inflow_usdt, 2),
                        round(r.total_outflow_usdt, 2),
                        total_balance,
                        "是" if r.is_blacklisted else "否",
                        "是" if any(ind.category == "ofac_sanctioned" for ind in r.indicators) else "否",
                        "是" if is_transit else "否",
                        " | ".join(hop1_cats),
                        " | ".join(hop2_cats),
                        bl_cnt, mix_cnt, ob_cnt,
                        asset_detail,
                        " // ".join(r.warnings),
                    ])
            print(f"[INFO] 批量 CSV 已保存: {args.csv}")

    elif args.address:
        report = analyzer.analyze(args.address, chain=args.chain, chains=chains_list)
        print_report(report, use_color=not args.no_color, output_dir=args.output or "")
        if args.full:
            print_transactions(report, show_all=True)
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
