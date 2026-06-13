"""
Travis · threat_intel — 威胁情报数据加载器

人工维护的地址库：
  mechanisms.json     - 资金转移机制统一注册表（混币器 + 跨链桥），单一事实来源
  mechanisms.py       - 机制的定义与判别器（MappingSource / is_tracing_boundary / classify）
  exchanges.json      - 交易所热钱包、高风险交易所、充值地址识别参数
  ofac_sanctioned.json- OFAC SDN 名单中的加密货币地址（BTC/ETH/TRX等，自动更新）

混币器与桥不再是两个分离的文件——它们由「映射可观测性」统一定义，旧的
MIXER_CONTRACTS / BRIDGE_REGISTRY / OPAQUE_BRIDGE_ADDRS 现在都从 mechanisms 派生
（向后兼容，调用方无需改动）。

使用方式：
  from threat_intel import MIXER_CONTRACTS, BRIDGE_REGISTRY, EXCHANGE_HOT_WALLETS, \
                           HIGH_RISK_EXCHANGES, DEPOSIT_DETECTION_PARAMS, \
                           OFAC_SANCTIONED, OFAC_SANCTIONED_ADDRS
  from threat_intel.mechanisms import classify, Mechanism, MappingSource  # 新判别器
"""

import json
from pathlib import Path
from typing import Dict, Set

from .mechanisms import (  # noqa: F401  对外暴露新定义层
    REGISTRY, Mechanism, MappingSource, EvidenceStrength, Kind,
    classify, classify_by_fingerprint,
)

_DIR = Path(__file__).parent


def _load(filename: str) -> dict:
    with open(_DIR / filename, encoding="utf-8") as f:
        return json.load(f)


# ── 从统一机制注册表派生旧常量（向后兼容）──────────────────────────────────
# 混币器：{地址: 名称}
MIXER_CONTRACTS: Dict[str, str] = {
    m.address: m.name for m in REGISTRY.values() if m.kind == Kind.MIXER
}

# 跨链桥：还原旧 {地址: {name, traceable, method, dst_chains}} 形态。
# traceable 不再是手填字段，而是统一定义的派生量：可追踪 ⇔ 不是追踪边界。
BRIDGE_REGISTRY: Dict[str, Dict] = {
    m.address: {
        "name": m.name,
        "traceable": not m.is_tracing_boundary,
        "method": m.resolution_method,
        "dst_chains": list(m.dst_chains),
    }
    for m in REGISTRY.values() if m.kind == Kind.BRIDGE
}
ALL_BRIDGE_ADDRS: Set[str] = set(BRIDGE_REGISTRY)
# 不透明桥 = 是桥、且是追踪边界（映射不可还原）
OPAQUE_BRIDGE_ADDRS: Set[str] = {
    m.address for m in REGISTRY.values()
    if m.kind == Kind.BRIDGE and m.is_tracing_boundary
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

# ── OFAC SDN 制裁名单 ────────────────────────────────────────────────────────
# 来源：OFAC SDN_ADVANCED.XML，含 BTC/ETH/TRX/USDT 等多链地址
# 字段：{addr: {currency, entity, source}}
_ofac_data = _load("ofac_sanctioned.json")
# 统一小写，兼容大小写不一致的输入
OFAC_SANCTIONED: Dict[str, Dict] = {
    addr.lower(): info for addr, info in _ofac_data.items()
}
OFAC_SANCTIONED_ADDRS: Set[str] = set(OFAC_SANCTIONED)
