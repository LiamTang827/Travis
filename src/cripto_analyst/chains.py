#!/usr/bin/env python3
"""链注册表与查询客户端：ChainConfig、EVM/Tron 客户端、扫描器端点、LayerZero 链映射。"""

import sys
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set, Tuple

import requests

from .config import ETHERSCAN_API_KEY, REQUEST_DELAY, PAGE_SIZE, MAX_TX_FETCH

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


