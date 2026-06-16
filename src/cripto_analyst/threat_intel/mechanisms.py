"""资金转移机制的统一定义层（混币器 + 跨链桥）。

这个模块把 report 2 里散落在三张表中的同一个性质，提升为一个**可执行的定义**：

    追踪边界（tracing boundary）：一个资金转移机制，当且仅当它的【进出映射】
    无法从公开链上状态还原。混币器、不透明桥、隐私币都是该定义下的实例，
    区别只在映射不可还原的**方式**（链下私有账本 / 密码学销毁 / 根本不存在）。

设计要点（回答"为什么不是只弄 JSON"）：
  - JSON（mechanisms.json）只负责存「已知实例」这一份策展数据；
  - 本模块负责「定义」与「判别器」——前者是类型与谓词（MappingSource /
    is_tracing_boundary），后者是 classify()：地址精确查（第 0 级）→ 协议
    指纹匹配（第 1 级，能认出未登记的同协议部署）。判别逻辑在代码里，不在数据里。

指纹常量（函数选择器 / 事件 topic0）均由 keccak256 离线算出并验证
（transfer(address,uint256)=0xa9059cbb 作为校验锚），运行时不依赖 keccak。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

_DIR = Path(__file__).parent


class MappingSource(str, Enum):
    """机制的「进出映射」能从哪里还原——这是判别追踪边界的唯一维度。"""
    ONCHAIN_EVENT = "onchain_event"          # 源链事件日志 / calldata 直接给出
    ROLLUP_DERIVATION = "rollup_derivation"  # Rollup 官方桥：目标地址=源地址，可推导
    INDEXER_API = "indexer_api"              # 协议索引器发布映射（可信第三方，需回锚）
    OFFCHAIN_PRIVATE = "offchain_private"    # 映射只存在于 maker/运营方的链下账本
    ZK_DESTROYED = "zk_destroyed"            # 映射被零知识证明在密码学上销毁
    NONE = "none"                            # 链上根本不存在映射（如换成隐私币）


# 映射「可公开还原」的来源——这之外的都是追踪边界。
_RECOVERABLE: Set[MappingSource] = {
    MappingSource.ONCHAIN_EVENT,
    MappingSource.ROLLUP_DERIVATION,
    MappingSource.INDEXER_API,
}


class EvidenceStrength(str, Enum):
    STRONG = "strong"      # 映射可仅凭链数据重新推导
    MODERATE = "moderate"  # 映射经可信索引器，再用目标链 receipt 回锚
    WEAK = "weak"          # 只有启发式线索（金额/时间相似）
    NONE = "none"          # 无可用的延续证据


class Kind(str, Enum):
    BRIDGE = "bridge"
    MIXER = "mixer"


@dataclass(frozen=True)
class Mechanism:
    """一个资金转移机制的分类结果。"""
    address: str
    name: str
    kind: Kind
    mapping_source: MappingSource
    evidence_strength: EvidenceStrength
    mechanism: str = ""  # 资金转移机制：burn_mint / lock_mint / message_passing /
                         # liquidity_fill / maker_fill / pooled_fill / rollup_canonical /
                         # zk_pool / centralized_swap / mpc_custody
    resolution_method: Optional[str] = None
    dst_chains: Tuple[str, ...] = ()
    inferred: bool = False  # True = 由指纹推断（未登记部署），而非地址精确命中

    @property
    def is_tracing_boundary(self) -> bool:
        """统一定义：追踪在此终止，当且仅当进出映射不可从公开链上状态还原。

        这一行谓词，就是把混币器与不透明桥归为同类的那个判据。
        """
        return self.mapping_source not in _RECOVERABLE


# ==================== 数据层：加载已知实例（第 0 级判别器的数据）====================
def _load_registry() -> Dict[str, Mechanism]:
    raw = json.loads((_DIR / "mechanisms.json").read_text(encoding="utf-8"))
    reg: Dict[str, Mechanism] = {}
    for addr, m in raw["mechanisms"].items():
        reg[addr.lower()] = Mechanism(
            address=addr.lower(),
            name=m["name"],
            kind=Kind(m["kind"]),
            mapping_source=MappingSource(m["mapping_source"]),
            evidence_strength=EvidenceStrength(m["evidence_strength"]),
            mechanism=m.get("mechanism", ""),
            resolution_method=m.get("resolution_method"),
            dst_chains=tuple(m.get("dst_chains", [])),
        )
    return reg


REGISTRY: Dict[str, Mechanism] = _load_registry()


# ==================== 判别器第 1 级：协议指纹（认出未登记的同协议部署）====================
# 常量由 keccak256 离线算出（见模块 docstring）。一个全新地址的 Tornado fork，
# 地址不在 REGISTRY 里，但它的存取款函数选择器 / 事件 topic0 与这里一致 → 被认出。
@dataclass(frozen=True)
class _Fingerprint:
    family: str
    selectors: Set[str]       # 函数选择器（4-byte）
    event_topics: Set[str]    # 事件 topic0（32-byte）
    kind: Kind
    mapping_source: MappingSource
    evidence_strength: EvidenceStrength


_FINGERPRINTS: List[_Fingerprint] = [
    _Fingerprint(
        family="Tornado-style ZK mixer",
        selectors={
            "0xb214faa5",  # deposit(bytes32)
            "0x21a0adb6",  # withdraw(bytes,bytes32,bytes32,address,address,uint256,uint256)
        },
        event_topics={
            "0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196",  # Deposit(bytes32,uint32,uint256)
            "0xe9e508bad6d4c3227e881ca19068f099da81b5164dd6d62b2eaf1e8bc6c34931",  # Withdrawal(address,bytes32,address,uint256)
        },
        kind=Kind.MIXER,
        mapping_source=MappingSource.ZK_DESTROYED,
        evidence_strength=EvidenceStrength.NONE,
    ),
]


def classify_by_fingerprint(
    selectors: Iterable[str] = (),
    event_topics: Iterable[str] = (),
) -> Optional[Mechanism]:
    """第 1 级判别：按协议接口指纹识别一个未登记的机制。

    传入某合约被观测到的函数选择器与事件 topic0；命中已知协议族则返回一个
    inferred=True 的 Mechanism。这是字典做不到的——它认的是协议接口，不是地址。
    """
    sels = {s.lower() for s in selectors}
    tops = {t.lower() for t in event_topics}
    for fp in _FINGERPRINTS:
        if (sels & fp.selectors) or (tops & fp.event_topics):
            return Mechanism(
                address="", name=f"inferred: {fp.family}",
                kind=fp.kind, mapping_source=fp.mapping_source,
                evidence_strength=fp.evidence_strength, inferred=True,
            )
    return None


def classify(
    address: str,
    selectors: Iterable[str] = (),
    event_topics: Iterable[str] = (),
) -> Optional[Mechanism]:
    """统一入口：先地址精确查（第 0 级，零误判），未命中再走指纹（第 1 级）。

    返回 None = 既不在注册表、也不匹配任何已知协议指纹（对该机制无判断）。
    """
    hit = REGISTRY.get(address.lower())
    if hit is not None:
        return hit
    return classify_by_fingerprint(selectors, event_topics)
