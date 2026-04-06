#!/usr/bin/env python3
"""
AML 风险识别系统 - USDT黑名单关联地址分析
功能：跨链桥资金追踪 + 黑名单关联检测 + AML风险评分
支持链：Ethereum / Tron
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

load_dotenv()

# ==================== 配置 ====================
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
BLACKLIST_CSV = "usdt_blacklist.csv"
REQUEST_DELAY = 0.25   # 请求间隔（秒），避免限速
MAX_TX_FETCH = 500     # 每次查询最大交易数（旧值 100 导致活跃地址历史交易被截断）
HOP2_ENABLED = True    # 是否启用二跳分析（较慢）

# ==================== 跨链桥注册表 ====================
# traceable=True  : 可追踪对端地址（源链→目标链有明确对应关系）
# traceable=False : 不透明桥（资金流向不可追踪，风险等同混币器）
# method          : 未来实现追踪时使用的 API/解析方式
# dst_chains      : 已知目标链（rollup 类桥固定目标链）
BRIDGE_REGISTRY: Dict[str, Dict] = {
    # ---------- 透明桥（traceable=True）----------
    # Stargate Finance（LayerZero 驱动，可通过 LZ Scan API 追踪）
    "0x8731d54e9d02c286767d56ac03e8037c07e01e98": {
        "name": "Stargate Finance Router", "traceable": True,
        "method": "layerzero_api", "dst_chains": ["arbitrum", "optimism", "polygon", "bsc", "avalanche"],
    },
    "0x296f55f8fb28e498b858d0bcda06d955b2cb3f97": {
        "name": "Stargate Finance STG", "traceable": True,
        "method": "layerzero_api", "dst_chains": [],
    },
    # Hop Protocol（每笔转账有唯一 transferId，可关联两端）
    "0x3e4a3a4796d16c0cd582c382691998f7c06420b6": {
        "name": "Hop Protocol (USDT)", "traceable": True,
        "method": "hop_api", "dst_chains": ["arbitrum", "optimism", "polygon", "gnosis"],
    },
    "0x3666f603cc164936c1b87e207f36beba4ac5f18a": {
        "name": "Hop Protocol (USDC)", "traceable": True,
        "method": "hop_api", "dst_chains": ["arbitrum", "optimism", "polygon"],
    },
    "0xb8901acb165ed027e32754e0ffe830802919727f": {
        "name": "Hop Protocol (ETH Bridge)", "traceable": True,
        "method": "hop_api", "dst_chains": ["arbitrum", "optimism"],
    },
    "0x914f986a44acb623a277d6bd17368171fcbe4273": {
        "name": "Hop Protocol (USDC Bridge)", "traceable": True,
        "method": "hop_api", "dst_chains": ["arbitrum", "optimism"],
    },
    # Celer cBridge（有官方 API，可通过 transferId 关联）
    "0x5427fefa711eff984124bfbb1ab6fbf5e3da1820": {
        "name": "Celer cBridge v2", "traceable": True,
        "method": "cbridge_api", "dst_chains": [],
    },
    "0x9d39fc627a6d9d9f8c831c16995b209548cc3401": {
        "name": "Celer cBridge v1", "traceable": True,
        "method": "cbridge_api", "dst_chains": [],
    },
    # Across Protocol（官方 API，deposit/fill 可关联）
    "0x4d9079bb4165aeb4084c526a32695dcfd2f77381": {
        "name": "Across Protocol v2", "traceable": True,
        "method": "across_api", "dst_chains": [],
    },
    "0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5": {
        "name": "Across Protocol v3", "traceable": True,
        "method": "across_api", "dst_chains": [],
    },
    # Wormhole（VAA 序列号关联两端）
    "0x3ee18b2214aff97000d974cf647e7c347e8fa585": {
        "name": "Wormhole Token Bridge", "traceable": True,
        "method": "wormhole_api", "dst_chains": [],
    },
    "0x98f3c9e6e3face36baad05fe09d375ef1464288b": {
        "name": "Wormhole Core Bridge", "traceable": True,
        "method": "wormhole_api", "dst_chains": [],
    },
    # deBridge（有官方 API）
    "0x43de2d77bf8027e25dbd179b491e8d64f38398aa": {
        "name": "deBridge Gate", "traceable": True,
        "method": "debridge_api", "dst_chains": [],
    },
    # LayerZero（LZ Scan API 直接返回 src/dst tx 和地址）
    "0x66a71dcef29a0ffbdbe3c6a460a3b5bc225cd675": {
        "name": "LayerZero Endpoint v1", "traceable": True,
        "method": "layerzero_api", "dst_chains": [],
    },
    "0x1a44076050125825900e736c501f859c50fe728c": {
        "name": "LayerZero Endpoint v2", "traceable": True,
        "method": "layerzero_api", "dst_chains": [],
    },
    # Polygon 官方桥（Rollup，事件日志含目标地址）
    "0xa0c68c638235ee32657e8f720a23cec1bfc77c77": {
        "name": "Polygon PoS Bridge", "traceable": True,
        "method": "event_logs_rollup", "dst_chains": ["polygon"],
    },
    "0x40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf": {
        "name": "Polygon ERC20 Predicate", "traceable": True,
        "method": "event_logs_rollup", "dst_chains": ["polygon"],
    },
    # Arbitrum 官方桥（Rollup，事件日志含目标地址）
    "0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a": {
        "name": "Arbitrum Bridge", "traceable": True,
        "method": "event_logs_rollup", "dst_chains": ["arbitrum"],
    },
    "0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f": {
        "name": "Arbitrum Inbox", "traceable": True,
        "method": "event_logs_rollup", "dst_chains": ["arbitrum"],
    },
    # Optimism 官方桥（Rollup，事件日志含目标地址）
    "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1": {
        "name": "Optimism Gateway", "traceable": True,
        "method": "event_logs_rollup", "dst_chains": ["optimism"],
    },
    "0x25ace71c97b33cc4729cf772ae268934f7ab5fa1": {
        "name": "Optimism Messenger", "traceable": True,
        "method": "event_logs_rollup", "dst_chains": ["optimism"],
    },
    # SquidRouter (Axelar 协议，有 Axelarscan API)
    "0xce16f69375520ab01377ce7b88f5ba8c48f8d666": {
        "name": "SquidRouter v1", "traceable": True,
        "method": "axelar_api", "dst_chains": [],
    },
    "0xea749fd6ba492dbc14c24fe8a3d08769229b896c": {
        "name": "SquidRouter v2", "traceable": True,
        "method": "axelar_api", "dst_chains": [],
    },
    # Connext（有 Connext Explorer API）
    "0x8898b472c54c31894e3b9bb83cea802a5d0e63c6": {
        "name": "Connext Diamond", "traceable": True,
        "method": "connext_api", "dst_chains": [],
    },
    # Symbiosis
    "0xb8f275fbf7a959f4bce59999a2ef122a099e81a8": {
        "name": "Symbiosis", "traceable": True,
        "method": "symbiosis_api", "dst_chains": [],
    },

    # ---------- 不透明桥（traceable=False，风险等同混币器）----------
    # Multichain (Anyswap) - 2023年崩溃，资金池模式，进出无法对应
    "0xc564ee9f21ed8a2d8e7e76c085740d5e4c5fafbe": {
        "name": "Multichain Router v4", "traceable": False,
        "method": None, "dst_chains": [],
    },
    "0x765277eebeca2e31912c9946eae1021199b39c61": {
        "name": "Multichain Router v6", "traceable": False,
        "method": None, "dst_chains": [],
    },
    # Orbiter Finance - Maker 模式，你的资金先入 maker 地址，再由 maker 在目标链转出
    # 无法从链上数据直接关联收款人
    "0x80c67432656d59144ceff962e8faf8926599bcf8": {
        "name": "Orbiter Finance", "traceable": False,
        "method": None, "dst_chains": [],
    },
    # Synapse - 流动性池模式，多用户资金混入同一池后转出
    "0x2796317b0ff8538f253012862c06787adfb8ceb": {
        "name": "Synapse Bridge", "traceable": False,
        "method": None, "dst_chains": [],
    },
    "0x1116898dda4015ed8ddefb84b6e8bc24528af2d8": {
        "name": "Synapse Router", "traceable": False,
        "method": None, "dst_chains": [],
    },
    # Owlto Finance - Maker 模式（同 Orbiter）
    "0x5474f9c8f4a2c8a8e14de5c785c0b9d3e5b18d6d": {
        "name": "Owlto Finance", "traceable": False,
        "method": None, "dst_chains": [],
    },
}

# 派生查找表（供内部使用）
ALL_BRIDGE_ADDRS: Set[str] = set(BRIDGE_REGISTRY)
OPAQUE_BRIDGE_ADDRS: Set[str] = {a for a, v in BRIDGE_REGISTRY.items() if not v["traceable"]}

# ==================== 多链扫描器配置（用于跨链追踪）====================
# 无 API key 的链会走公开端点（有速率限制），可自行填入各链 key
CHAIN_SCANNERS: Dict[str, Dict] = {
    "ethereum":  {"api": "https://api.etherscan.io/api",             "key": ETHERSCAN_API_KEY},
    "arbitrum":  {"api": "https://api.arbiscan.io/api",              "key": ""},
    "optimism":  {"api": "https://api-optimistic.etherscan.io/api",  "key": ""},
    "polygon":   {"api": "https://api.polygonscan.com/api",          "key": ""},
    "bsc":       {"api": "https://api.bscscan.com/api",              "key": ""},
    "avalanche": {"api": "https://api.snowtrace.io/api",             "key": ""},
    "base":      {"api": "https://api.basescan.org/api",             "key": ""},
}

# LayerZero 链 ID → 链名称（v1 + v2 endpoint IDs）
LZ_CHAIN_MAP: Dict[int, str] = {
    101: "ethereum",  110: "arbitrum",  111: "optimism",
    109: "polygon",   102: "bsc",       106: "avalanche",  184: "base",
    30101: "ethereum", 30110: "arbitrum", 30111: "optimism",
    30109: "polygon",  30102: "bsc",      30106: "avalanche", 30184: "base",
}

BRIDGE_TRACE_ENABLED = True   # 是否对透明桥进行对端地址追踪（可用 --no-trace 关闭）

# ==================== 混币器合约 ====================
MIXER_CONTRACTS = {
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado Cash 0.1ETH",
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado Cash 1ETH",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash 10ETH",
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": "Tornado Cash 100ETH",
    "0xfd8610d20aa15b7b2e3be39b396a1bc3516c7144": "Tornado Cash 1000ETH",
    "0x07687e702b410fa43f4cb4af7fa097918ffd2730": "Tornado Cash USDC",
    "0x23773e65ed146a459667fd7b0fc7ebcddbebf32": "Tornado Cash DAI",
    "0x12d66f87a04a9e220c9d50f0a8c1f856591900aa": "Tornado Cash USDC 100",
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado Cash",
    "0xd691f27f38b395b1b196747234ba8e57c9162cf5": "eXch (混币交易所)",
}

# ==================== 高风险交易所（KYC不完善）====================
HIGH_RISK_EXCHANGES = {
    "0x6262998ced04146fa42253a5c0af90ca02dfd2a3": "Crypto.com Deposit",
    "0xd24400ae8bfebb18ca49be86258a3c749cf46853": "Gemini",
    "0xec031efe9930b50d70e82f43c94b0abdd59dcab5": "Bitfinex Hot",
    "0x876eabf441b2ee5b5b0554fd502a8e0600950cfa": "Bitfinex",
    # 以下为已知高风险或受限交易所
    "0x5e4e65926ba27467555eb562121fac00d24e9dd2": "Garantex",
    "0x45fdb1b92a649fb6a64ef1511d3ba5bf60044838": "Garantex v2",
}

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
    # Multichain Tron 端（近似地址）
    "0x1df721d242e0783f8fcad4592a068bc6a50c4bce": "Multichain Tron",
    # TronLink官方跨链
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
    """
    根据黑名单记录或地址特征判断链类型
    优先查黑名单，其次用地址格式（0x 开头 = eth 为主）
    """
    addr_norm = normalize(address)
    if addr_norm in blacklist:
        return blacklist[addr_norm]["chain"]
    # 启发式：所有 0x 地址当做 ethereum，但用户可通过 --chain 参数覆盖
    return "ethereum"


# ==================== Etherscan / Blockscout 查询 ====================
# Etherscan 对 OFAC 制裁地址有合规屏蔽，Blockscout 是开源替代，无此限制
# 策略：优先用 Etherscan，若返回空结果则自动切换 Blockscout 重试

class EtherscanClient:
    ETHERSCAN_BASE  = "https://api.etherscan.io/api"
    BLOCKSCOUT_BASE = "https://eth.blockscout.com/api"   # 兼容 Etherscan API 格式

    def __init__(self, api_key: str):
        self.key = api_key

    def _get(self, params: dict, base: str = None) -> Optional[dict]:
        url = base or self.ETHERSCAN_BASE
        p = dict(params)
        if url == self.ETHERSCAN_BASE:
            p["apikey"] = self.key
        try:
            r = requests.get(url, params=p, timeout=15)
            data = r.json()
            return data
        except Exception as e:
            print(f"  [WARN] 请求失败 ({url[:30]}...): {e}", file=sys.stderr)
            return None

    def _fetch_txs(self, params: dict) -> List[dict]:
        """先查 Etherscan，若无结果自动切换 Blockscout"""
        for base in [self.ETHERSCAN_BASE, self.BLOCKSCOUT_BASE]:
            data = self._get(params, base=base)
            result = data.get("result", []) if data else []
            if isinstance(result, list) and len(result) > 0:
                if base == self.BLOCKSCOUT_BASE:
                    print(f"  [INFO] Etherscan 无结果，已从 Blockscout 获取数据")
                return result
            time.sleep(REQUEST_DELAY)
        return []

    def get_normal_txs(self, address: str, limit: int = MAX_TX_FETCH) -> List[dict]:
        return self._fetch_txs({
            "module": "account", "action": "txlist",
            "address": address, "startblock": 0, "endblock": 99999999,
            "sort": "desc", "offset": limit, "page": 1,
        })

    def get_token_transfers(self, address: str, limit: int = MAX_TX_FETCH) -> List[dict]:
        return self._fetch_txs({
            "module": "account", "action": "tokentx",
            "address": address, "startblock": 0, "endblock": 99999999,
            "sort": "desc", "offset": limit, "page": 1,
        })

    def get_account_info(self, address: str) -> dict:
        # 余额：Blockscout 优先（无制裁屏蔽）
        balance_data = self._get({"module": "account", "action": "balance", "address": address, "tag": "latest"})
        if not balance_data or not isinstance(balance_data.get("result"), str):
            balance_data = self._get({"module": "account", "action": "balance", "address": address, "tag": "latest"}, base=self.BLOCKSCOUT_BASE)
        contract_data = self._get({"module": "contract", "action": "getabi", "address": address})
        is_contract = contract_data and contract_data.get("status") == "1"
        balance_eth = "0"
        if balance_data and isinstance(balance_data.get("result"), str):
            try:
                balance_eth = f"{int(balance_data['result']) / 1e18:.6f} ETH"
            except Exception:
                pass
        return {"balance": balance_eth, "is_contract": is_contract}


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
    """
    透明桥追踪器：给定一笔桥交易，找出目标链上的接收地址。
    支持：LayerZero 系（Stargate 等）、官方 Rollup 桥（Arbitrum/Optimism/Polygon）
    """

    def resolve(self, tx_hash: str, method: str, src_address: str,
                dst_chains_hint: list) -> Optional[Dict]:
        """
        返回: {"dst_chain": str, "dst_address": str, "dst_tx": str} 或 None
        """
        if method == "layerzero_api":
            return self._resolve_layerzero(tx_hash, src_address)
        elif method == "event_logs_rollup" and dst_chains_hint:
            # 官方 Rollup 桥：目标地址 = 来源地址（同一地址跨 L2）
            return {
                "dst_chain": dst_chains_hint[0],
                "dst_address": src_address,
                "dst_tx": "",
            }
        return None

    def _resolve_layerzero(self, tx_hash: str, src_address: str) -> Optional[Dict]:
        """调用 LayerZero Scan API 获取目标链 tx，再找 token 转账接收方"""
        try:
            r = requests.get(
                f"https://api.layerzeroscan.com/tx/{tx_hash}", timeout=10
            )
            if r.status_code != 200:
                return None
            data = r.json()
            # LZ Scan v2 响应格式：data.messages[] 或 data.data[]
            messages = data.get("messages") or data.get("data") or []
            if not messages:
                return None
            msg = messages[0]

            # 提取目标链 ID（兼容 v1/v2 不同字段名）
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

            # 在目标链上找 token 转账的实际接收地址
            dst_address = self._find_token_receiver(dst_tx, dst_chain) or src_address
            return {"dst_chain": dst_chain, "dst_address": dst_address, "dst_tx": dst_tx}

        except Exception as e:
            print(f"  [WARN] LZ Scan 查询失败: {e}", file=sys.stderr)
            return None

    def _find_token_receiver(self, tx_hash: str, chain: str) -> Optional[str]:
        """在目标链上查该 tx 的 token 转账接收方（第一笔 ERC20 Transfer 的 to）"""
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
class RiskReport:
    address: str
    chain: str
    tron_address: str = ""          # Tron base58 格式（如果是 tron 链）
    is_blacklisted: bool = False
    blacklist_time: str = ""

    risk_score: int = 0             # 0-100
    risk_level: str = "LOW"         # LOW / MEDIUM / HIGH / CRITICAL

    account_info: dict = field(default_factory=dict)
    total_counterparties: int = 0
    total_transactions: int = 0

    hop1_blacklisted: List[dict] = field(default_factory=list)  # 1跳黑名单
    hop2_blacklisted: List[dict] = field(default_factory=list)  # 2跳黑名单
    top_counterparties: List[dict] = field(default_factory=list) # 频率最高的普通对手方（用于图展开）
    bridge_interactions: List[dict] = field(default_factory=list)        # 透明跨链桥（可追踪）
    opaque_bridge_interactions: List[dict] = field(default_factory=list) # 不透明桥（资金流向不可追踪）
    mixer_interactions: List[dict] = field(default_factory=list)         # 混币器
    high_risk_exchanges: List[dict] = field(default_factory=list)        # 高风险交易所
    cross_chain_findings: List[dict] = field(default_factory=list)       # 跨链追踪发现

    warnings: List[str] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)


# ==================== ML 风险评分器（可选）====================
class MLRiskScorer:
    """
    加载训练好的 ML 模型，对地址做风险概率预测。
    如果模型文件不存在，graceful 降级为 None（系统回退到纯规则引擎）。
    """

    def __init__(self, model_dir: str = None):
        self.model = None
        self.meta = None
        if model_dir is None:
            model_dir = os.path.join(os.path.dirname(__file__), "ml", "data", "model_output")
        model_path = os.path.join(model_dir, "best_model.pkl")
        meta_path = os.path.join(model_dir, "model_meta.json")
        if os.path.exists(model_path) and os.path.exists(meta_path):
            try:
                import pickle
                with open(model_path, "rb") as f:
                    self.model = pickle.load(f)
                with open(meta_path) as f:
                    self.meta = json.load(f)
                print(f"  [ML] 已加载模型: {self.meta.get('model_name', '?')} "
                      f"(F1={self.meta.get('macro_f1', 0):.3f})")
            except Exception as e:
                print(f"  [ML] 模型加载失败: {e}")
                self.model = None

    @property
    def available(self) -> bool:
        return self.model is not None and self.meta is not None

    def predict_risk(self, report: 'RiskReport') -> Optional[int]:
        """
        从 RiskReport 提取特征子集 → 模型预测 → 返回 0-100 风险分。
        只用 report 中已有的信息，不额外调 API。
        """
        if not self.available:
            return None
        try:
            features = self._extract_features_from_report(report)
            feature_names = self.meta["feature_names"]
            X = []
            for fname in feature_names:
                X.append(features.get(fname, 0))
            import numpy as np
            X_arr = np.array([X], dtype=np.float64)
            X_arr = np.nan_to_num(X_arr, nan=0.0, posinf=999.0, neginf=-999.0)
            proba = self.model.predict_proba(X_arr)[0]
            # label 编码：meta 中 label_encoding 记录了 {label: index}
            label_enc = self.meta.get("label_encoding", {})
            bl_idx = label_enc.get("blocklisted", 0)
            risk_proba = proba[bl_idx] if bl_idx < len(proba) else proba[0]
            return int(risk_proba * 100)
        except Exception as e:
            print(f"  [ML] 预测失败: {e}")
            return None

    def _extract_features_from_report(self, report: 'RiskReport') -> dict:
        """从 RiskReport 中提取 ML 模型需要的特征（尽量覆盖）"""
        f = {}
        # Interaction features
        mixer_in = sum(1 for m in report.mixer_interactions if m.get("direction") == "IN")
        mixer_out = sum(1 for m in report.mixer_interactions if m.get("direction") != "IN")
        f["sent_to_mixer"] = mixer_out
        f["received_from_mixer"] = mixer_in
        f["has_mixer_interaction"] = int(len(report.mixer_interactions) > 0)

        opaque_in = sum(1 for b in report.opaque_bridge_interactions if b.get("direction") == "IN")
        opaque_out = sum(1 for b in report.opaque_bridge_interactions if b.get("direction") != "IN")
        f["sent_to_opaque_bridge"] = opaque_out
        f["received_from_opaque_bridge"] = opaque_in

        trans_in = sum(1 for b in report.bridge_interactions if b.get("direction") == "IN")
        trans_out = sum(1 for b in report.bridge_interactions if b.get("direction") != "IN")
        f["sent_to_transparent_bridge"] = trans_out
        f["received_from_transparent_bridge"] = trans_in
        f["has_bridge_interaction"] = int(len(report.bridge_interactions) + len(report.opaque_bridge_interactions) > 0)

        f["sent_to_flagged"] = len(report.hop1_blacklisted)
        f["received_from_flagged"] = 0  # 无法从 report 精确区分方向
        f["has_flagged_interaction"] = int(len(report.hop1_blacklisted) > 0)

        hrx_count = len(report.high_risk_exchanges)
        f["sent_to_high_risk_exchange"] = hrx_count
        f["received_from_high_risk_exchange"] = 0

        f["sent_to_cex"] = 0
        f["received_from_cex"] = 0
        f["has_cex_interaction"] = 0
        f["sent_to_dex"] = 0
        f["received_from_dex"] = 0

        # Transfer features
        f["total_count"] = report.total_transactions
        f["sent_count"] = 0
        f["received_count"] = 0
        f["total_sent_amount"] = 0
        f["total_received_amount"] = 0
        f["transfers_over_1k"] = 0
        f["transfers_over_5k"] = 0
        f["transfers_over_10k"] = 0
        f["transfers_over_50k"] = 0
        f["transfers_over_100k"] = 0
        f["in_out_ratio"] = 0
        f["drain_ratio"] = 0
        f["avg_amount"] = 0
        f["max_amount"] = 0
        f["min_amount"] = 0
        f["median_amount"] = 0
        f["std_amount"] = 0
        f["repeated_same_amount_groups"] = 0
        f["repeated_amount_ratio"] = 0

        # Network features
        f["unique_senders"] = 0
        f["unique_receivers"] = 0
        f["is_single_source"] = 0
        f["is_single_dest"] = 0
        f["in_degree"] = 0
        f["out_degree"] = len(report.top_counterparties)
        f["in_out_degree_ratio"] = 0
        f["total_unique_counterparties"] = report.total_counterparties
        f["counterparty_flagged_ratio"] = (
            len(report.hop1_blacklisted) / max(report.total_counterparties, 1)
        )
        f["counterparty_mixer_ratio"] = 0
        f["counterparty_bridge_ratio"] = 0
        f["counterparty_cex_ratio"] = 0
        f["has_proxy_behavior"] = 0

        # Temporal features
        f["account_age_days"] = 0
        f["prolonged_activity"] = 0
        f["avg_interval_seconds"] = 0
        f["min_interval_seconds"] = 0
        f["std_interval_seconds"] = 0
        f["has_high_frequency"] = 0
        f["rapid_tx_ratio"] = 0
        f["max_daily_count"] = 0
        f["has_daily_burst"] = 0
        f["has_rapid_reciprocal"] = 0
        f["hour_concentration"] = 0

        return f


# ==================== 核心分析引擎 ====================
class AMLAnalyzer:
    def __init__(self, blacklist: Dict[str, Dict], etherscan: EtherscanClient,
                 tronscan: TronScanClient, tracer: BridgeTracer = None,
                 time_window_days: int = 0):
        self.blacklist = blacklist
        self.eth = etherscan
        self.tron = tronscan
        self.tracer = tracer or BridgeTracer()
        # time_window_days=0 表示不限制时间；>0 则只分析最近 N 天的交易
        self.time_window_days = time_window_days
        # ML 风险评分器（可选，模型文件不存在时自动降级为纯规则）
        self.ml_scorer = MLRiskScorer()

    # ---------- 目标链 1 跳黑名单检测 ----------
    def _check_dst_hop1(self, address: str, chain: str) -> List[dict]:
        """在目标链上查询 address 的 1 跳黑名单关联（用于跨链追踪）"""
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
                    other = t if f == addr_norm else f
                    if other and other != addr_norm and other in self.blacklist:
                        info = self.blacklist[other]
                        entry = {"address": other, "chain": info["chain"],
                                 "blacklist_time": info["time"]}
                        if entry not in hits:
                            hits.append(entry)
        except Exception as e:
            print(f"  [WARN] 目标链({chain})查询失败: {e}", file=sys.stderr)
        return hits[:5]

    # ---------- USDT getLogs 查询（捕获 transferFrom 类型转账）----------
    def _get_usdt_logs(self, address: str) -> List[dict]:
        """
        通过 USDT Transfer 事件日志查找地址的收/发记录。
        即使地址从未主动发送交易（transferFrom 场景），也能找到关联。
        """
        USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
        TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        addr_norm = normalize(address)
        # 地址补零到32字节（用于 topic 匹配）
        padded = "0x" + "0" * 24 + addr_norm[2:]
        results = []

        for role, topic_key in [("sender", "topic1"), ("receiver", "topic2")]:
            time.sleep(REQUEST_DELAY)
            params = {
                "module": "logs", "action": "getLogs",
                "address": USDT,
                "topic0": TRANSFER_TOPIC,
                topic_key: padded,
                "topic0_1_opr" if role == "sender" else "topic0_2_opr": "and",
                "fromBlock": 0, "toBlock": 99999999,
                "page": 1, "offset": MAX_TX_FETCH,
            }
            # 优先 Blockscout（无制裁屏蔽）
            try:
                r = requests.get(self.eth.BLOCKSCOUT_BASE, params=params, timeout=15)
                logs = r.json().get("result", [])
                if isinstance(logs, list):
                    for log in logs:
                        log["_role"] = role
                    results.extend(logs)
            except Exception:
                pass

        return results

    # ---------- 以太坊分析 ----------
    def _analyze_ethereum(self, address: str, report: RiskReport, depth: int = 1):
        addr_norm = normalize(address)
        print(f"  [ETH] 查询交易记录...")
        time.sleep(REQUEST_DELAY)
        normal_txs = self.eth.get_normal_txs(address)
        time.sleep(REQUEST_DELAY)
        token_txs = self.eth.get_token_transfers(address)
        # 截断提示：如果返回数量恰好等于上限，说明可能还有更多历史交易
        if len(normal_txs) >= MAX_TX_FETCH:
            print(f"  [WARN] 普通交易达到上限 {MAX_TX_FETCH}，可能遗漏更早的记录")
        if len(token_txs) >= MAX_TX_FETCH:
            print(f"  [WARN] Token转账达到上限 {MAX_TX_FETCH}，可能遗漏更早的记录")

        # 若 txlist/tokentx 无结果，补充查 USDT 事件日志（处理 transferFrom 场景）
        usdt_logs = []
        if len(normal_txs) == 0 and len(token_txs) == 0:
            print(f"  [ETH] txlist/tokentx 无结果，尝试 USDT getLogs...")
            usdt_logs = self._get_usdt_logs(address)
            if usdt_logs:
                print(f"  [ETH] getLogs 获取到 {len(usdt_logs)} 条 USDT Transfer 事件")

        time.sleep(REQUEST_DELAY)
        report.account_info = self.eth.get_account_info(address)

        # 去重：同一笔 tx 在 txlist 和 tokentx 中可能各出现一次
        # 用 (hash, from, to) 三元组去重，保留不同 token transfer 事件
        _seen_tx_keys: Set[tuple] = set()
        all_txs = []
        for tx in normal_txs + token_txs:
            _key = (tx.get("hash", ""),
                    normalize(tx.get("from", "")),
                    normalize(tx.get("to", "") or tx.get("contractAddress", "")))
            if _key not in _seen_tx_keys:
                _seen_tx_keys.add(_key)
                all_txs.append(tx)

        # 时间窗口过滤：只保留最近 N 天的交易（防止远古交易误伤无关地址）
        if self.time_window_days > 0:
            cutoff_ts = int(time.time()) - self.time_window_days * 86400
            before = len(all_txs)
            all_txs = [tx for tx in all_txs
                       if int(tx.get("timeStamp", 0)) >= cutoff_ts]
            usdt_logs = [lg for lg in usdt_logs
                         if int(lg.get("timeStamp", 0)) >= cutoff_ts]
            if before != len(all_txs):
                print(f"  [ETH] 时间过滤（最近{self.time_window_days}天）: "
                      f"{before} → {len(all_txs)} 笔交易保留")

        report.total_transactions = len(all_txs) + len(usdt_logs)
        print(f"  [ETH] 获取到 {len(normal_txs)} 笔普通交易 + {len(token_txs)} 笔 Token 转账"
              + (f" + {len(usdt_logs)} 条 USDT 事件" if usdt_logs else ""))

        counterparties: Set[str] = set()
        counterparty_stats: Dict[str, Dict] = {}  # {addr: {"count": N, "total_value": V, "max_value": M}}

        # 从普通交易/token转账提取对手方（发送方主动调用的场景）
        for tx in all_txs:
            f = normalize(tx.get("from", ""))
            t = normalize(tx.get("to", "") or tx.get("contractAddress", ""))
            other = t if f == addr_norm else f
            if other and other != addr_norm:
                counterparties.add(other)
                # 解析金额：普通交易用 value (wei)，token 转账用 value + tokenDecimal
                raw_val = int(tx.get("value", "0") or "0")
                decimals = int(tx.get("tokenDecimal", "18") or "18")
                tx_value = raw_val / (10 ** decimals) if raw_val > 0 else 0
                if other not in counterparty_stats:
                    counterparty_stats[other] = {"count": 0, "total_value": 0.0, "max_value": 0.0}
                counterparty_stats[other]["count"] += 1
                counterparty_stats[other]["total_value"] += tx_value
                counterparty_stats[other]["max_value"] = max(counterparty_stats[other]["max_value"], tx_value)
                # 双向检测：from 和 to 都查桥/混币器/高风险交易所
                # 修复：旧版只查 to，导致从混币器提取资金（from=mixer）完全检测不到
                for check_addr, direction in [(t, "OUT" if f == addr_norm else "IN"),
                                               (f, "IN" if f != addr_norm else "OUT")]:
                    bridge_info = BRIDGE_REGISTRY.get(check_addr)
                    if bridge_info:
                        entry = {
                            "bridge": bridge_info["name"],
                            "contract": check_addr,
                            "tx": tx.get("hash", ""),
                            "direction": direction,
                            "token": tx.get("tokenSymbol", "ETH"),
                            "value": tx.get("value", "0"),
                            "traceable": bridge_info["traceable"],
                            "method": bridge_info["method"],
                            "dst_chains": bridge_info["dst_chains"],
                        }
                        if bridge_info["traceable"]:
                            report.bridge_interactions.append(entry)
                        else:
                            report.opaque_bridge_interactions.append(entry)
                    if check_addr in MIXER_CONTRACTS:
                        report.mixer_interactions.append({
                            "mixer": MIXER_CONTRACTS[check_addr],
                            "contract": check_addr,
                            "tx": tx.get("hash", ""),
                            "direction": direction,
                        })
                    if check_addr in HIGH_RISK_EXCHANGES:
                        report.high_risk_exchanges.append({
                            "exchange": HIGH_RISK_EXCHANGES[check_addr],
                            "contract": check_addr,
                            "tx": tx.get("hash", ""),
                            "direction": direction,
                        })

        # 从 USDT getLogs 提取对手方（transferFrom 场景 — 地址未主动发交易）
        for log in usdt_logs:
            topics = log.get("topics", [])
            if len(topics) < 3:
                continue
            log_from = "0x" + topics[1][-40:]
            log_to   = "0x" + topics[2][-40:]
            role = log.get("_role", "")
            other = log_to if role == "sender" else log_from
            if other and other != addr_norm:
                counterparties.add(other)
                if other not in counterparty_stats:
                    counterparty_stats[other] = {"count": 0, "total_value": 0.0, "max_value": 0.0}
                counterparty_stats[other]["count"] += 1

        report.total_counterparties = len(counterparties)
        print(f"  [ETH] 发现 {len(counterparties)} 个交易对手地址")

        # 已知协议合约地址（排除误报）
        PROTOCOL_CONTRACTS = {
            "0xdac17f958d2ee523a2206206994597c13d831ec7",  # USDT 合约本身
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC 合约
            "0x0000000000000000000000000000000000000000",  # 零地址
        }

        # 构建 top_counterparties — 金额加权排名（替代纯频率排名）
        # 修复：旧版按交互次数排序，DEX/交易所高频交易占满名额，
        #       低频但大额的可疑中转地址被淹没
        _exclude_addrs = (PROTOCOL_CONTRACTS | ALL_BRIDGE_ADDRS
                          | set(MIXER_CONTRACTS) | set(HIGH_RISK_EXCHANGES)
                          | KNOWN_DEX_ADDRS)
        scored_cps = []
        for addr, stats in counterparty_stats.items():
            if addr in _exclude_addrs or addr in self.blacklist:
                continue
            # 复合评分：大额单笔最重要，其次总金额，最后频率
            score = (stats["max_value"] * 0.6
                     + stats["total_value"] * 0.3
                     + stats["count"] * 0.1)
            scored_cps.append((addr, stats, score))
        scored_cps.sort(key=lambda x: x[2], reverse=True)
        report.top_counterparties = [
            {"address": addr, "tx_count": stats["count"],
             "total_value": round(stats["total_value"], 4),
             "max_value": round(stats["max_value"], 4),
             "chain": "ethereum"}
            for addr, stats, _ in scored_cps[:10]
        ]

        # 1跳黑名单检测
        for cp in counterparties:
            if cp in PROTOCOL_CONTRACTS:
                continue
            if cp in self.blacklist:
                info = self.blacklist[cp]
                report.hop1_blacklisted.append({
                    "address": cp,
                    "chain": info["chain"],
                    "blacklist_time": info["time"],
                })

        # 2跳分析（仅对非黑名单且非桥合约的对手方）
        if depth == 1 and HOP2_ENABLED and len(counterparties) > 0:
            clean_cps = [
                cp for cp in counterparties
                if cp not in self.blacklist
                and cp not in ALL_BRIDGE_ADDRS
                and cp not in MIXER_CONTRACTS
            ]
            # 取前5个对手方做2跳分析（避免请求过多）
            sample = list(clean_cps)[:5]
            if sample:
                print(f"  [ETH] 2跳分析 {len(sample)} 个对手方...")
                for cp in sample:
                    time.sleep(REQUEST_DELAY)
                    cp_txs = self.eth.get_normal_txs(cp, limit=50)
                    cp_token_txs = self.eth.get_token_transfers(cp, limit=50)
                    for tx in cp_txs + cp_token_txs:
                        t2 = normalize(tx.get("to", "") or "")
                        f2 = normalize(tx.get("from", "") or "")
                        for addr2 in [t2, f2]:
                            if addr2 and addr2 != cp and addr2 in self.blacklist and addr2 != addr_norm:
                                info = self.blacklist[addr2]
                                entry = {"address": addr2, "via": cp, "chain": info["chain"], "blacklist_time": info["time"]}
                                if entry not in report.hop2_blacklisted:
                                    report.hop2_blacklisted.append(entry)

        # ---------- 透明桥跨链追踪 ----------
        if BRIDGE_TRACE_ENABLED and report.bridge_interactions:
            # 只追踪 OUT 方向（本地址主动发出的桥交易），最多5笔
            out_bridges = [b for b in report.bridge_interactions if b.get("direction") == "OUT"]
            seen_tx: Set[str] = set()
            if out_bridges:
                print(f"  [ETH] 透明桥跨链追踪（{min(len(out_bridges), 5)} 笔）...")
            for b in out_bridges[:5]:
                tx_hash = b.get("tx", "")
                if not tx_hash or tx_hash in seen_tx:
                    continue
                seen_tx.add(tx_hash)
                time.sleep(REQUEST_DELAY)
                result = self.tracer.resolve(
                    tx_hash=tx_hash,
                    method=b.get("method", ""),
                    src_address=addr_norm,
                    dst_chains_hint=b.get("dst_chains", []),
                )
                if not result:
                    print(f"  [ETH]   {b['bridge']}: 无法解析对端地址")
                    continue

                dst_addr  = normalize(result.get("dst_address", ""))
                dst_chain = result.get("dst_chain", "")
                dst_tx    = result.get("dst_tx", "")
                finding = {
                    "bridge":          b["bridge"],
                    "src_tx":          tx_hash,
                    "dst_chain":       dst_chain,
                    "dst_address":     dst_addr,
                    "dst_tx":          dst_tx,
                    "blacklisted":     False,
                    "blacklist_info":  {},
                    "hop1_blacklisted": [],
                }

                # 直接黑名单命中
                if dst_addr and dst_addr in self.blacklist:
                    finding["blacklisted"] = True
                    finding["blacklist_info"] = self.blacklist[dst_addr]
                    print(f"  [!!!] 桥接目标地址命中黑名单: {dst_addr} ({dst_chain})")

                # 目标链 1 跳检测（目标链 ≠ ethereum，避免重复）
                elif dst_addr and dst_chain and dst_chain != "ethereum":
                    hop1 = self._check_dst_hop1(dst_addr, dst_chain)
                    if hop1:
                        finding["hop1_blacklisted"] = hop1
                        print(f"  [!] 桥接目标 {dst_chain}:{dst_addr[:16]}... "
                              f"1跳内有 {len(hop1)} 个黑名单地址")
                    else:
                        print(f"  [ETH]   {b['bridge']} → {dst_chain}:{dst_addr[:16]}... 未发现黑名单关联")

                report.cross_chain_findings.append(finding)

    # ---------- Tron 分析 ----------
    def _analyze_tron(self, address: str, report: RiskReport):
        tron_b58 = hex_to_tron_base58(address)
        report.tron_address = tron_b58
        print(f"  [TRON] 地址转换: {address} → {tron_b58}")
        print(f"  [TRON] 查询交易记录...")

        trc20_txs = self.tron.get_trc20_transfers(tron_b58)
        trx_txs = self.tron.get_transactions(tron_b58)
        report.account_info = self.tron.get_account_info(tron_b58)
        all_txs = trc20_txs + trx_txs
        report.total_transactions = len(all_txs)
        print(f"  [TRON] 获取到 {len(trc20_txs)} 笔 TRC20 + {len(trx_txs)} 笔 TRX 交易")

        counterparties: Set[str] = set()
        addr_b58_lower = tron_b58.lower()

        for tx in trc20_txs:
            f = (tx.get("from_address") or tx.get("transferFromAddress") or "").lower()
            t = (tx.get("to_address") or tx.get("transferToAddress") or "").lower()
            # 转换为 0x 格式做黑名单比对
            for raw_addr in [f, t]:
                if raw_addr and raw_addr != addr_b58_lower:
                    counterparties.add(raw_addr)

        for tx in trx_txs:
            ow = (tx.get("ownerAddress") or "").lower()
            to = (tx.get("toAddress") or "").lower()
            for raw_addr in [ow, to]:
                if raw_addr and raw_addr != addr_b58_lower:
                    counterparties.add(raw_addr)

        report.total_counterparties = len(counterparties)
        print(f"  [TRON] 发现 {len(counterparties)} 个交易对手地址")

        # Tron 地址黑名单查询：CSV 中存 0x 格式，需将 base58 转回做比对
        # TronScan 返回的是 base58，黑名单是 0x hex；逐一转换对比
        bl_tron = {addr: info for addr, info in self.blacklist.items() if info.get("chain") == "tron"}

        for cp_b58 in counterparties:
            # 尝试将 base58 转为 0x hex 格式查黑名单
            try:
                cp_hex = _tron_b58_to_hex(cp_b58)
                if cp_hex and cp_hex in bl_tron:
                    info = bl_tron[cp_hex]
                    report.hop1_blacklisted.append({
                        "address": cp_b58,
                        "address_hex": cp_hex,
                        "chain": "tron",
                        "blacklist_time": info["time"],
                    })
            except Exception:
                pass

    # ---------- 风险评分 ----------
    def _calculate_risk(self, report: RiskReport):
        score = 0
        factors = []

        if report.is_blacklisted:
            score = 100
            factors.append("地址本身已被 USDT 封禁 (CRITICAL)")

        else:
            # 混币器：最高优先级
            if report.mixer_interactions:
                score += 40
                names = list({m["mixer"] for m in report.mixer_interactions})
                factors.append(f"与混币器交互: {', '.join(names)}")

            # 不透明跨链桥（资金流向不可追踪，等同混币器行为）
            if report.opaque_bridge_interactions:
                score += 25
                names = list({b["bridge"] for b in report.opaque_bridge_interactions})
                factors.append(f"使用不透明跨链桥（资金流向不可追踪）: {', '.join(names)}")

            # 1跳黑名单
            h1 = len(report.hop1_blacklisted)
            if h1 >= 3:
                score += 35
                factors.append(f"1跳内有 {h1} 个黑名单地址（高度可疑）")
            elif h1 >= 1:
                score += 20
                factors.append(f"1跳内有 {h1} 个黑名单地址")

            # 透明跨链桥
            if report.bridge_interactions:
                bridge_names = list({b["bridge"] for b in report.bridge_interactions})
                if h1 > 0:
                    score += 20
                    factors.append(f"使用透明跨链桥且与黑名单地址关联: {', '.join(bridge_names)}")
                else:
                    score += 10
                    factors.append(f"使用透明跨链桥: {', '.join(bridge_names)}")

            # 2跳黑名单
            h2 = len(report.hop2_blacklisted)
            if h2 >= 3:
                score += 20
                factors.append(f"2跳内有 {h2} 个黑名单地址")
            elif h2 >= 1:
                score += 10
                factors.append(f"2跳内有 {h2} 个黑名单地址")

            # 跨链追踪发现
            bl_findings  = [f for f in report.cross_chain_findings if f.get("blacklisted")]
            hop1_findings = [f for f in report.cross_chain_findings if f.get("hop1_blacklisted")]
            if bl_findings:
                score += 35
                chains = list({f["dst_chain"] for f in bl_findings})
                factors.append(f"跨链桥对端地址命中黑名单 ({', '.join(chains)})")
            elif hop1_findings:
                score += 15
                chains = list({f["dst_chain"] for f in hop1_findings})
                factors.append(f"跨链桥对端地址 1 跳内有黑名单关联 ({', '.join(chains)})")

            # 高风险交易所
            if report.high_risk_exchanges:
                score += 5
                names = list({e["exchange"] for e in report.high_risk_exchanges})
                factors.append(f"与高风险交易所交互: {', '.join(names)}")

        rule_score = min(score, 100)

        # ML 模型混合评分：可用时混合规则分和 ML 分，不可用时纯规则
        ml_score = self.ml_scorer.predict_risk(report)
        if ml_score is not None and not report.is_blacklisted:
            # 混合策略：规则引擎 40% + ML 模型 60%
            final_score = int(rule_score * 0.4 + ml_score * 0.6)
            factors.append(f"ML 模型风险概率: {ml_score}% (混合权重 60%)")
        else:
            final_score = rule_score

        final_score = min(final_score, 100)
        report.risk_score = final_score
        report.risk_factors = factors

        if final_score == 100 or report.is_blacklisted:
            report.risk_level = "CRITICAL"
        elif final_score >= 60:
            report.risk_level = "HIGH"
        elif final_score >= 30:
            report.risk_level = "MEDIUM"
        else:
            report.risk_level = "LOW"

    # ---------- 主入口 ----------
    def analyze(self, address: str, chain: Optional[str] = None) -> RiskReport:
        addr_norm = normalize(address)
        detected_chain = chain or detect_chain(address, self.blacklist)
        report = RiskReport(address=addr_norm, chain=detected_chain)

        print(f"\n{'='*60}")
        print(f"分析地址: {addr_norm}")
        print(f"链类型:   {detected_chain}")
        print(f"{'='*60}")

        # 黑名单直接命中
        if addr_norm in self.blacklist:
            info = self.blacklist[addr_norm]
            report.is_blacklisted = True
            report.blacklist_time = info["time"]
            report.warnings.append(f"[!] 该地址已在 USDT 黑名单（封禁时间: {info['time']}）")
            print(f"  [!!!] 直接命中黑名单！封禁时间: {info['time']}")

        # 链上数据分析
        if detected_chain == "ethereum":
            self._analyze_ethereum(addr_norm, report)
        elif detected_chain == "tron":
            self._analyze_tron(addr_norm, report)
        else:
            print(f"  [WARN] 不支持的链类型: {detected_chain}，尝试 Ethereum 模式")
            self._analyze_ethereum(addr_norm, report)

        self._calculate_risk(report)
        return report


# ==================== Tron Base58 转 Hex ====================
_B58_MAP = {chr(_B58_ALPHABET[i]): i for i in range(58)}

def _tron_b58_to_hex(b58_addr: str) -> Optional[str]:
    """Tron base58check 地址 → 0x hex（20字节）"""
    try:
        num = 0
        for c in b58_addr:
            num = num * 58 + _B58_MAP[c]
        raw = num.to_bytes(25, "big")
        # raw = 1字节前缀(41) + 20字节地址 + 4字节校验
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
    "LOW":      "\033[92m",  # 绿
    "MEDIUM":   "\033[93m",  # 黄
    "HIGH":     "\033[91m",  # 红
    "CRITICAL": "\033[95m",  # 紫
    "RESET":    "\033[0m",
}


def print_report(report: RiskReport, use_color: bool = True):
    c = LEVEL_COLORS if use_color else {k: "" for k in LEVEL_COLORS}
    lc = c.get(report.risk_level, "")
    rc = c["RESET"]

    print(f"\n{'='*60}")
    print(f"  AML 风险分析报告")
    print(f"{'='*60}")
    print(f"  地址:     {report.address}")
    if report.tron_address:
        print(f"  Tron地址: {report.tron_address}")
    print(f"  链:       {report.chain}")
    print(f"  余额:     {report.account_info.get('balance', 'N/A')}")
    print(f"  是否合约: {'是' if report.account_info.get('is_contract') else '否'}")
    print(f"  交易数量: {report.total_transactions}")
    print(f"  对手方数: {report.total_counterparties}")
    print()
    print(f"  {'─'*54}")
    print(f"  风险等级: {lc}{report.risk_level}{rc}   风险分数: {lc}{report.risk_score}/100{rc}")
    print(f"  {'─'*54}")

    if report.is_blacklisted:
        print(f"\n  {lc}[!!!] 该地址已被 USDT 直接封禁{rc}")
        print(f"        封禁时间: {report.blacklist_time}")

    if report.risk_factors:
        print(f"\n  风险因素:")
        for f in report.risk_factors:
            print(f"    - {f}")

    if report.bridge_interactions:
        print(f"\n  透明跨链桥交互 ({len(report.bridge_interactions)} 笔，资金可追踪):")
        shown = {}
        for b in report.bridge_interactions:
            key = b["bridge"]
            if key not in shown:
                shown[key] = {"count": 0, "directions": set(), "tokens": set(), "dst_chains": b.get("dst_chains", []), "method": b.get("method", "")}
            shown[key]["count"] += 1
            shown[key]["directions"].add(b.get("direction", "?"))
            shown[key]["tokens"].add(b.get("token", "?"))
        for name, info in shown.items():
            dirs = "/".join(sorted(info["directions"]))
            tokens = "/".join(sorted(info["tokens"]))
            dst = "/".join(info["dst_chains"]) if info["dst_chains"] else "多链"
            print(f"    - {name}  [{dirs}]  Token: {tokens}  次数: {info['count']}  目标链: {dst}")
            for b in report.bridge_interactions:
                if b["bridge"] == name:
                    print(f"      合约: {b['contract']}  追踪方式: {b.get('method', 'N/A')}")
                    break

    if report.opaque_bridge_interactions:
        print(f"\n  {lc}不透明跨链桥交互 ({len(report.opaque_bridge_interactions)} 笔，资金流向不可追踪):{rc}")
        shown_op = {}
        for b in report.opaque_bridge_interactions:
            key = b["bridge"]
            if key not in shown_op:
                shown_op[key] = {"count": 0, "directions": set(), "tokens": set()}
            shown_op[key]["count"] += 1
            shown_op[key]["directions"].add(b.get("direction", "?"))
            shown_op[key]["tokens"].add(b.get("token", "?"))
        for name, info in shown_op.items():
            dirs = "/".join(sorted(info["directions"]))
            tokens = "/".join(sorted(info["tokens"]))
            print(f"    - {name}  [{dirs}]  Token: {tokens}  次数: {info['count']}")
            for b in report.opaque_bridge_interactions:
                if b["bridge"] == name:
                    print(f"      合约: {b['contract']}")
                    break

    if report.mixer_interactions:
        print(f"\n  {lc}混币器交互 ({len(report.mixer_interactions)} 笔):{rc}")
        for m in report.mixer_interactions:
            print(f"    - {m['mixer']}  tx: {m['tx'][:20]}...")

    if report.hop1_blacklisted:
        print(f"\n  {lc}1跳黑名单关联地址 ({len(report.hop1_blacklisted)} 个):{rc}")
        for h in report.hop1_blacklisted[:10]:
            print(f"    - {h['address']}  [{h['chain']}]  封禁: {h['blacklist_time'][:10]}")
        if len(report.hop1_blacklisted) > 10:
            print(f"    ... 共 {len(report.hop1_blacklisted)} 个")

    if report.hop2_blacklisted:
        print(f"\n  2跳黑名单关联地址 ({len(report.hop2_blacklisted)} 个):")
        for h in report.hop2_blacklisted[:5]:
            print(f"    - {h['address']}  via {h['via'][:16]}...  封禁: {h['blacklist_time'][:10]}")
        if len(report.hop2_blacklisted) > 5:
            print(f"    ... 共 {len(report.hop2_blacklisted)} 个")

    if report.high_risk_exchanges:
        print(f"\n  高风险交易所交互:")
        for e in report.high_risk_exchanges:
            print(f"    - {e['exchange']}")

    if report.cross_chain_findings:
        print(f"\n  跨链追踪发现 ({len(report.cross_chain_findings)} 条):")
        for f in report.cross_chain_findings:
            dst   = f.get("dst_address", "?")
            chain = f.get("dst_chain", "?")
            br    = f.get("bridge", "")
            if f.get("blacklisted"):
                bl_time = f.get("blacklist_info", {}).get("time", "")[:10]
                print(f"  {lc}  [{br}] → {chain}:{dst}  [黑名单 封禁:{bl_time}]{rc}")
            elif f.get("hop1_blacklisted"):
                n = len(f["hop1_blacklisted"])
                print(f"    [{br}] → {chain}:{dst[:18]}...  [1跳内 {n} 个黑名单]")
                for h in f["hop1_blacklisted"][:3]:
                    print(f"        └ {h['address']}  封禁:{h['blacklist_time'][:10]}")
            else:
                print(f"    [{br}] → {chain}:{dst[:18]}...  [无直接黑名单关联]")

    print(f"\n{'='*60}\n")


def export_json(report: RiskReport, path: str):
    """导出 JSON 报告"""
    import dataclasses
    with open(path, "w") as f:
        json.dump(dataclasses.asdict(report), f, ensure_ascii=False, indent=2)
    print(f"[INFO] JSON 报告已保存: {path}")


# ==================== CLI ====================
def main():
    parser = argparse.ArgumentParser(
        description="AML 风险识别 - USDT黑名单关联地址分析",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("address", nargs="?", help="要分析的地址（0x 格式）")
    parser.add_argument("--chain", choices=["ethereum", "tron"], help="强制指定链类型")
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

    print("[*] 加载黑名单...")
    blacklist = load_blacklist(args.blacklist)
    print(f"[*] 已加载 {len(blacklist)} 个黑名单地址")

    etherscan = EtherscanClient(ETHERSCAN_API_KEY)
    tronscan  = TronScanClient()
    tracer    = BridgeTracer()
    analyzer  = AMLAnalyzer(blacklist, etherscan, tronscan, tracer)

    if args.batch:
        # 批量模式
        with open(args.batch) as f:
            addresses = [line.strip() for line in f if line.strip()]
        print(f"[*] 批量模式：共 {len(addresses)} 个地址")
        reports = []
        for i, addr in enumerate(addresses, 1):
            print(f"\n[{i}/{len(addresses)}] 处理: {addr}")
            report = analyzer.analyze(addr, chain=args.chain)
            print_report(report, use_color=not args.no_color)
            reports.append(report)
            time.sleep(0.5)
        # 批量汇总
        print(f"\n{'='*60}")
        print(f"批量分析汇总")
        print(f"{'='*60}")
        for r in reports:
            lc = LEVEL_COLORS.get(r.risk_level, "") if not args.no_color else ""
            rc = LEVEL_COLORS["RESET"] if not args.no_color else ""
            h1 = len(r.hop1_blacklisted)
            bridges = len(r.bridge_interactions)
            print(f"  {r.address[:20]}...  {lc}{r.risk_level:8s}{rc}  分数:{r.risk_score:3d}  1跳黑名单:{h1}  桥:{bridges}")
        if args.json:
            import dataclasses
            with open(args.json, "w") as f:
                json.dump([dataclasses.asdict(r) for r in reports], f, ensure_ascii=False, indent=2)
            print(f"[INFO] 批量 JSON 已保存: {args.json}")

    elif args.address:
        report = analyzer.analyze(args.address, chain=args.chain)
        print_report(report, use_color=not args.no_color)
        if args.json:
            export_json(report, args.json)

    else:
        # 交互模式
        print("\n[*] 进入交互模式（输入 q 退出）")
        while True:
            try:
                addr = input("\n请输入地址: ").strip()
                if addr.lower() in ("q", "quit", "exit"):
                    break
                if not addr:
                    continue
                chain_input = input("链类型 [ethereum/tron/auto]: ").strip().lower()
                chain_arg = chain_input if chain_input in ("ethereum", "tron") else None
                report = analyzer.analyze(addr, chain=chain_arg)
                print_report(report, use_color=not args.no_color)
            except KeyboardInterrupt:
                break
        print("\n[*] 退出")


if __name__ == "__main__":
    main()
