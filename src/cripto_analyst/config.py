#!/usr/bin/env python3
"""全局配置：路径、API key、限速参数、风险类别权重、稳定币集合、方法选择器解码、统一风险等级。"""

import os
from pathlib import Path
from typing import Dict, Set

from dotenv import load_dotenv

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


# ==================== 统一风险等级阈值 ====================
# 单一事实来源：评分引擎（analyzer）与溯源树展示（trace_graph）共用。
RISK_LEVEL_THRESHOLDS = ((80.0, "CRITICAL"), (45.0, "HIGH"), (20.0, "MEDIUM"))


def risk_level(score: float) -> str:
    """0-100 分 → CRITICAL / HIGH / MEDIUM / LOW"""
    for cutoff, name in RISK_LEVEL_THRESHOLDS:
        if score >= cutoff:
            return name
    return "LOW"
