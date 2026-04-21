"""
Travis · threat_intel — 威胁情报数据加载器

所有需要人工维护的地址库都在这里的 JSON 文件中管理：
  mixers.json    - 混币器合约
  bridges.json   - 跨链桥合约（含透明/不透明分类）
  exchanges.json - 交易所热钱包、高风险交易所、充值地址识别参数

使用方式：
  from threat_intel import MIXER_CONTRACTS, BRIDGE_REGISTRY, EXCHANGE_HOT_WALLETS, \
                           HIGH_RISK_EXCHANGES, DEPOSIT_DETECTION_PARAMS
"""

import json
from pathlib import Path
from typing import Dict, Set

_DIR = Path(__file__).parent


def _load(filename: str) -> dict:
    with open(_DIR / filename, encoding="utf-8") as f:
        return json.load(f)


# ── 混币器 ──────────────────────────────────────────────────────────────────
_mixer_data = _load("mixers.json")
MIXER_CONTRACTS: Dict[str, str] = {
    addr: name
    for addr, name in _mixer_data["contracts"].items()
    if not addr.startswith("_") and name != "_placeholder"
}

# ── 跨链桥 ──────────────────────────────────────────────────────────────────
_bridge_data = _load("bridges.json")
BRIDGE_REGISTRY: Dict[str, Dict] = _bridge_data["contracts"]
ALL_BRIDGE_ADDRS: Set[str] = set(BRIDGE_REGISTRY)
OPAQUE_BRIDGE_ADDRS: Set[str] = {
    a for a, v in BRIDGE_REGISTRY.items() if not v["traceable"]
}

# ── 交易所 ──────────────────────────────────────────────────────────────────
_exchange_data = _load("exchanges.json")

EXCHANGE_HOT_WALLETS: Dict[str, Dict] = _exchange_data["hot_wallets"]
HIGH_RISK_EXCHANGES: Dict[str, Dict] = _exchange_data["high_risk"]
DEPOSIT_DETECTION_PARAMS: dict = _exchange_data["deposit_detection"]

# 合并所有交易所地址（热钱包 + 高风险），供充值地址检测用
ALL_EXCHANGE_ADDRS: Set[str] = set(EXCHANGE_HOT_WALLETS) | set(HIGH_RISK_EXCHANGES)

# 向后兼容：部分旧代码直接用 {addr: "name"} 格式
HIGH_RISK_EXCHANGES_FLAT: Dict[str, str] = {
    addr: info["name"] for addr, info in HIGH_RISK_EXCHANGES.items()
}
EXCHANGE_HOT_WALLETS_FLAT: Dict[str, str] = {
    addr: f"{info['exchange']} ({info['name']})" for addr, info in EXCHANGE_HOT_WALLETS.items()
}
