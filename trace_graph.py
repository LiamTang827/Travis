#!/usr/bin/env python3
"""
资金溯源图分析器（Transaction Graph Tracer）

核心思想：以目标地址为根节点，递归展开其关联地址，构建一棵风险树。
每个节点按类型决定是否继续扩展：
  - 黑名单 / 混币器 / 不透明桥 → 终止节点（高风险）
  - 透明桥目标地址            → 继续扩展（切换到目标链）
  - 普通对手方                → 继续扩展（有深度限制）

剪枝规则防止节点爆炸：
  - max_depth:    最大追踪深度（默认 3）
  - max_children: 每节点最多展开子节点数（默认 5）
  - max_nodes:    全局节点上限（默认 50）
  - visited set:  防止循环
"""

import time
import json
import sys
import argparse
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set
from collections import deque

# 复用 aml_analyzer 的配置和客户端
import aml_analyzer as _aml
from aml_analyzer import (
    AMLAnalyzer, EtherscanClient, TronScanClient, BridgeTracer,
    RiskReport, load_blacklist,
    ETHERSCAN_API_KEY, BLACKLIST_CSV, REQUEST_DELAY,
    BRIDGE_REGISTRY, ALL_BRIDGE_ADDRS, OPAQUE_BRIDGE_ADDRS,
    MIXER_CONTRACTS, CHAIN_SCANNERS, LZ_CHAIN_MAP,
    HIGH_RISK_EXCHANGES, KNOWN_DEX_ADDRS,
    normalize,
)
# CEX 地址表从 feature_engineer 复用（aml_analyzer 没有统一的 CEX 集合）
try:
    from ml.feature_engineer import KNOWN_CEX_ADDRS
except ImportError:
    KNOWN_CEX_ADDRS: set = set()

# ==================== 节点类型 ====================
NODE_CLEAN          = "clean"           # 普通地址，无已知风险
NODE_BLACKLISTED    = "blacklisted"     # 直接黑名单命中
NODE_MIXER          = "mixer"           # 混币器交互（高风险，路径断裂）
NODE_OPAQUE_BRIDGE  = "opaque_bridge"   # 不透明跨链桥（高风险，追踪断开）
NODE_BRIDGE_DST     = "bridge_dst"      # 透明桥目标地址（已切链，继续追踪）
NODE_HIGH_RISK      = "high_risk"       # 综合评分高风险（1跳内多个黑名单）
NODE_SUSPECT        = "suspect"         # 疑似中转地址（本身干净但子树有高风险命中）

# 终止节点：不继续展开
# NODE_SUSPECT 用于两种场景：
#   1. 展开时发现使用过混币器/不透明桥 → BFS 直接终止（资金流向不可追踪）
#   2. 展开后 _reclassify_suspects 回头标记 → 该节点已经展开完，子树可见，仅作风险显示用
TERMINAL_TYPES = {NODE_BLACKLISTED, NODE_MIXER, NODE_OPAQUE_BRIDGE, NODE_SUSPECT}

# 节点类型对应的风险权重（用于向上传播评分）
NODE_RISK_WEIGHT = {
    NODE_BLACKLISTED:   100,
    NODE_MIXER:          80,
    NODE_OPAQUE_BRIDGE:  60,
    NODE_HIGH_RISK:      50,
    NODE_SUSPECT:        35,   # 中转嫌疑：本身干净但污染来源于子树
    NODE_BRIDGE_DST:     20,
    NODE_CLEAN:           0,
}

# 旧版固定衰减系数（保留用于 --legacy 模式对比）
DEPTH_DECAY = 0.6

# 改进版：节点类型 → 风险传播率
# 原理（Möser 2014, Liao 2025）：不同类型节点对 taint 的"传导能力"完全不同。
# 混币器几乎 100% 传导（使用它就是为了隐匿），CEX 则近乎隔断（千万用户共用）。
NODE_PROPAGATION_RATE = {
    NODE_BLACKLISTED:   0.95,  # 风险源本身，几乎完全传导
    NODE_MIXER:         0.85,  # 混币器：进入的资金几乎都是隐匿目的
    NODE_OPAQUE_BRIDGE: 0.80,  # 不透明桥：资金流不可追踪，高风险
    NODE_HIGH_RISK:     0.70,  # 综合高风险节点
    NODE_SUSPECT:       0.50,  # 中转嫌疑：来源不明但本身未直接接触黑名单
    NODE_BRIDGE_DST:    0.40,  # 透明桥目标：来源已知可追踪，不确定性低于中转
    NODE_CLEAN:         0.30,  # 普通地址：低传导
}

# 已知实体类型覆盖（比 node_type 更精确）
ENTITY_PROPAGATION_OVERRIDE = {
    "cex":          0.05,  # CEX：日均千万笔交易，单一连接无统计意义
    "dex":          0.15,  # DEX Router：公开协议，大量正常用户
    "high_risk_ex": 0.60,  # 高风险交易所（Garantex 等）：KYC 不足，传导较高
}


# ==================== 数据结构 ====================
@dataclass
class TraceNode:
    address: str
    chain: str
    depth: int
    node_type: str = NODE_CLEAN

    # 到达此节点的路径信息
    parent_address: Optional[str] = None
    parent_chain: Optional[str] = None
    via_bridge: Optional[str] = None      # 经由哪个桥到达（bridge_dst 节点）

    # 此节点的分析结果
    risk_score: int = 0
    hop1_blacklisted: List[dict] = field(default_factory=list)
    bridge_interactions: List[dict] = field(default_factory=list)
    opaque_bridge_interactions: List[dict] = field(default_factory=list)
    mixer_interactions: List[dict] = field(default_factory=list)
    cross_chain_findings: List[dict] = field(default_factory=list)
    total_counterparties: int = 0

    # 普通对手方（来自 RiskReport.top_counterparties，用于子节点展开）
    top_counterparties: List[dict] = field(default_factory=list)
    # 本节点允许的最大深度（自适应深度：可疑分支比普通分支多追 depth_bonus 跳）
    local_max_depth: int = 3

    # 子节点（BFS 展开后填充）
    children: List['TraceNode'] = field(default_factory=list)

    # 子树中发现的最高风险（向上传播用）
    subtree_max_risk: int = 0
    subtree_blacklist_count: int = 0
    # 来自子树的污染评分（不含自身 risk_score，用于识别中转地址）
    contamination_score: int = 0

    # 汇聚信息：当多条路径指向此节点时，记录额外的父节点
    # 修复：旧版 visited 直接跳过，导致分散→汇聚的洗钱模式不可见
    converge_from: List[str] = field(default_factory=list)  # ["parent_addr:chain", ...]
    in_degree: int = 1  # 入度（被几条路径指向，初始=1 表示首次发现的那条）

    @property
    def node_key(self) -> str:
        return f"{self.address}:{self.chain}"

    @property
    def is_terminal(self) -> bool:
        return self.node_type in TERMINAL_TYPES

    def to_dict(self) -> dict:
        return {
            "address":      self.address,
            "chain":        self.chain,
            "depth":        self.depth,
            "node_type":    self.node_type,
            "risk_score":   self.risk_score,
            "via_bridge":   self.via_bridge,
            "parent":       self.parent_address,
            "hop1_blacklisted": self.hop1_blacklisted,
            "mixer_interactions": [m["mixer"] for m in self.mixer_interactions],
            "opaque_bridges": [b["bridge"] for b in self.opaque_bridge_interactions],
            "bridge_interactions": [{"bridge": b["bridge"], "direction": b.get("direction")}
                                    for b in self.bridge_interactions],
            "subtree_max_risk":        self.subtree_max_risk,
            "subtree_blacklist_count": self.subtree_blacklist_count,
            "contamination_score":     self.contamination_score,
            "in_degree":               self.in_degree,
            "converge_from":           self.converge_from,
            "children": [c.to_dict() for c in self.children],
        }


# ==================== 图分析器 ====================
class TraceGraph:
    """
    BFS 资金溯源图：以一个地址为根，逐层展开关联地址，按风险剪枝。

    使用方法：
        graph = TraceGraph(analyzer)
        root = graph.trace("0xABC...", chain="ethereum")
        graph.print_tree(root)
    """

    def __init__(self, analyzer: AMLAnalyzer,
                 max_depth: int = 3,
                 max_children: int = 5,
                 max_nodes: int = 50,
                 depth_bonus: int = 1):
        self.analyzer = analyzer
        self.max_depth = max_depth
        self.max_children = max_children
        self.max_nodes = max_nodes
        # 自适应深度：发现混币器/不透明桥/黑名单关联时，该分支额外追 N 跳
        self.depth_bonus = depth_bonus

    def trace(self, address: str, chain: str = "ethereum") -> TraceNode:
        """入口：构建以 address 为根的溯源树，返回根节点。"""
        visited: Set[str] = set()
        visited_nodes: Dict[str, TraceNode] = {}  # node_key → 已展开的节点引用
        total = [0]  # 用列表实现可变引用

        root = TraceNode(address=normalize(address), chain=chain, depth=0,
                         local_max_depth=self.max_depth)
        queue: deque = deque([root])

        print(f"\n[图分析] 开始追踪: {address}  最大深度={self.max_depth}  最大节点={self.max_nodes}")

        while queue:
            node = queue.popleft()

            if node.node_key in visited:
                # 不展开，但记录汇聚信息（多条路径指向同一节点）
                existing = visited_nodes.get(node.node_key)
                if existing and node.parent_address:
                    existing.converge_from.append(f"{node.parent_address}:{node.parent_chain}")
                    existing.in_degree += 1
                continue
            if total[0] >= self.max_nodes:
                print(f"  [图分析] 已达节点上限 ({self.max_nodes})，停止展开")
                break

            visited.add(node.node_key)
            visited_nodes[node.node_key] = node
            total[0] += 1

            print(f"  [{'─'*node.depth}> 深度{node.depth}] {node.chain}:{node.address[:18]}...")

            # 分析此节点
            self._analyze_node(node)

            # 终止节点不继续展开
            if node.is_terminal:
                continue
            if node.depth >= node.local_max_depth:
                continue

            # 生成子节点列表
            children = self._get_children(node, visited)
            for child in children[:self.max_children]:
                node.children.append(child)
                queue.append(child)

        # 向上传播风险，然后二次分类中转嫌疑节点
        self._propagate_risk(root)
        self._reclassify_suspects(root)

        print(f"  [图分析] 完成，共分析 {total[0]} 个节点\n")
        return root

    # -------------------- 节点分析 --------------------
    def _analyze_node(self, node: TraceNode):
        """对单个节点运行 AML 分析，填充 node 字段，确定节点类型。"""
        try:
            report: RiskReport = self.analyzer.analyze(node.address, chain=node.chain)
        except Exception as e:
            print(f"    [WARN] 分析失败: {e}", file=sys.stderr)
            return

        node.risk_score               = report.risk_score
        node.hop1_blacklisted         = report.hop1_blacklisted
        node.bridge_interactions      = report.bridge_interactions
        node.opaque_bridge_interactions = report.opaque_bridge_interactions
        node.mixer_interactions       = report.mixer_interactions
        node.cross_chain_findings     = report.cross_chain_findings
        node.total_counterparties     = report.total_counterparties
        node.top_counterparties       = report.top_counterparties

        # 分类节点类型
        # 注意：混币器/不透明桥的【合约】子节点在 _get_children 中被显式设为 NODE_MIXER/NODE_OPAQUE_BRIDGE（终止节点）
        # 而此处分类的是【用户地址】：使用过混币器或不透明桥的用户地址仍继续展开，只是打上 suspect 标记
        if report.is_blacklisted:
            node.node_type = NODE_BLACKLISTED
        elif report.mixer_interactions or report.opaque_bridge_interactions:
            # 用户使用了混币器/不透明桥 → 可疑，但仍可继续追踪其他对手方
            node.node_type = NODE_SUSPECT
        elif report.risk_score >= 60:
            # 分数由 _calculate_risk 已按方向加权计算，直接用分数阈值判断
            node.node_type = NODE_HIGH_RISK
        elif node.via_bridge:
            node.node_type = NODE_BRIDGE_DST
        else:
            node.node_type = NODE_CLEAN

        print(f"    → 类型={node.node_type}  风险={node.risk_score}  "
              f"1跳黑名单={len(node.hop1_blacklisted)}  "
              f"透明桥={len(node.bridge_interactions)}  "
              f"不透明桥={len(node.opaque_bridge_interactions)}")

    # -------------------- 子节点生成 --------------------
    def _get_children(self, node: TraceNode, visited: Set[str]) -> List[TraceNode]:
        """
        生成下一层候选子节点。优先级：
        1. 透明桥目标地址（跨链，最有追踪价值）
        2. 1跳黑名单的直接对手方（最可疑）
        3. 普通对手方（用交易数/可疑度排序，取前 N）
        """
        candidates: List[TraceNode] = []

        # 判断当前节点是否"可疑"：若是，子节点继承额外深度预算
        # 可疑条件：直接接触黑名单 / 使用了混币器 / 使用了不透明桥
        is_suspicious = bool(
            node.hop1_blacklisted
            or node.mixer_interactions
            or node.opaque_bridge_interactions
        )
        # 子节点的 local_max_depth：可疑分支比父节点多 depth_bonus 跳，
        # 但绝不超过 max_depth + depth_bonus（防止无限延伸）
        child_max_depth = (
            min(node.local_max_depth + self.depth_bonus,
                self.max_depth + self.depth_bonus)
            if is_suspicious
            else node.local_max_depth
        )

        # 1. 透明桥跨链追踪结果（BridgeTracer 已经解析好了）
        for finding in node.cross_chain_findings:
            dst_addr  = finding.get("dst_address", "")
            dst_chain = finding.get("dst_chain", "")
            if not dst_addr or not dst_chain:
                continue
            key = f"{dst_addr}:{dst_chain}"
            if key in visited:
                continue
            child = TraceNode(
                address=dst_addr, chain=dst_chain,
                depth=node.depth + 1,
                parent_address=node.address, parent_chain=node.chain,
                via_bridge=finding.get("bridge", ""),
                local_max_depth=child_max_depth,
            )
            candidates.append(child)

        # 2. 1跳黑名单直接对手方（终止节点，local_max_depth 无实际作用）
        for bl in node.hop1_blacklisted:
            addr = bl.get("address", "")
            chain = bl.get("chain", "ethereum")
            if not addr:
                continue
            key = f"{addr}:{chain}"
            if key in visited:
                continue
            child = TraceNode(
                address=addr, chain=chain,
                depth=node.depth + 1,
                parent_address=node.address, parent_chain=node.chain,
                node_type=NODE_BLACKLISTED,
                risk_score=100,
                local_max_depth=child_max_depth,
            )
            candidates.append(child)

        # 3. 不透明桥/混币器合约 → 终止节点展示（合约本身不展开）
        for b in node.opaque_bridge_interactions:
            addr = b.get("contract", "")
            if not addr:
                continue
            key = f"{addr}:ethereum"
            if key in visited:
                continue
            child = TraceNode(
                address=addr, chain="ethereum",
                depth=node.depth + 1,
                parent_address=node.address, parent_chain=node.chain,
                node_type=NODE_OPAQUE_BRIDGE,
                risk_score=60,
                via_bridge=b.get("bridge", ""),
                local_max_depth=child_max_depth,
            )
            candidates.append(child)

        for m in node.mixer_interactions:
            addr = m.get("contract", "")
            if not addr:
                continue
            key = f"{addr}:ethereum"
            if key in visited:
                continue
            child = TraceNode(
                address=addr, chain="ethereum",
                depth=node.depth + 1,
                parent_address=node.address, parent_chain=node.chain,
                node_type=NODE_MIXER,
                risk_score=80,
                via_bridge=m.get("mixer", ""),
                local_max_depth=child_max_depth,
            )
            candidates.append(child)

        # 4. 普通对手方（按交互频率降序，排除已加入候选的地址）
        #    这些地址本身看起来"干净"，但可能是洗钱中转跳板，需继续展开分析
        already_added = {c.address for c in candidates}
        for cp in node.top_counterparties:
            addr = cp.get("address", "")
            if not addr or addr in already_added:
                continue
            key = f"{addr}:{node.chain}"
            if key in visited:
                continue
            child = TraceNode(
                address=addr, chain=node.chain,
                depth=node.depth + 1,
                parent_address=node.address, parent_chain=node.chain,
                node_type=NODE_CLEAN,
                local_max_depth=child_max_depth,
            )
            candidates.append(child)
            already_added.add(addr)

        return candidates

    # -------------------- 风险向上传播 --------------------
    def _propagate_risk(self, node: TraceNode):
        """
        后序遍历：将子树风险传播到父节点。
        - contamination_score: 来自子树的最大衰减风险（不含自身得分），
          反映"此地址是否为中转跳板"的可能性。
        - 每跳衰减系数 DEPTH_DECAY(0.6)：
            深度1直接接触: ×1.0  → CRITICAL/HIGH
            深度2二跳:     ×0.6  → HIGH/MEDIUM
            深度3三跳:     ×0.36 → MEDIUM
            深度4+远距:    ×≤0.22 → LOW
        """
        if not node.children:
            node.subtree_max_risk = node.risk_score
            node.subtree_blacklist_count = 1 if node.node_type == NODE_BLACKLISTED else 0
            node.contamination_score = 0
            return

        child_max = 0
        bl_count  = 0
        for child in node.children:
            self._propagate_risk(child)
            decayed = int(child.subtree_max_risk * DEPTH_DECAY)
            child_max = max(child_max, decayed)
            bl_count += child.subtree_blacklist_count

        node.contamination_score = child_max   # 纯来自子树的污染（无自身得分）
        node.subtree_max_risk = max(node.risk_score, child_max)
        node.subtree_blacklist_count = (
            (1 if node.node_type == NODE_BLACKLISTED else 0) + bl_count
        )

    def _reclassify_suspects(self, root: TraceNode):
        """
        传播完成后二次分类：
        - NODE_CLEAN 节点若子树存在黑名单命中 → 升级为 NODE_SUSPECT（疑似中转地址）
        - NODE_BRIDGE_DST 若子树存在黑名单命中 → 也升级（跨链后依然污染）
        """
        queue: deque = deque([root])
        while queue:
            node = queue.popleft()
            if node.node_type in (NODE_CLEAN, NODE_BRIDGE_DST):
                if node.subtree_blacklist_count > 0:
                    node.node_type = NODE_SUSPECT
            queue.extend(node.children)


# ==================== 树状输出 ====================
NODE_ICONS = {
    NODE_CLEAN:         "○",
    NODE_BLACKLISTED:   "🔴",
    NODE_MIXER:         "🔴",
    NODE_OPAQUE_BRIDGE: "🟠",
    NODE_BRIDGE_DST:    "🔵",
    NODE_HIGH_RISK:     "🟡",
    NODE_SUSPECT:       "⚠",    # 疑似中转（本身干净但子树污染）
}

LEVEL_COLORS = {
    "CRITICAL": "\033[95m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[92m",
    "RESET":    "\033[0m",
}


def _score_to_level(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 30: return "MEDIUM"
    return "LOW"


def print_tree(node: TraceNode, prefix: str = "", is_last: bool = True,
               use_color: bool = True):
    """递归打印树状结构"""
    connector = "└─ " if is_last else "├─ "
    icon = NODE_ICONS.get(node.node_type, "?")
    level = _score_to_level(node.subtree_max_risk)
    lc = LEVEL_COLORS.get(level, "") if use_color else ""
    rc = LEVEL_COLORS["RESET"] if use_color else ""

    addr_short = node.address[:20] + "..." if len(node.address) > 20 else node.address
    via = f" ←[{node.via_bridge}]" if node.via_bridge else ""
    risk_str = f"风险:{node.subtree_max_risk}"
    bl_str   = f" 子树黑名单:{node.subtree_blacklist_count}" if node.subtree_blacklist_count else ""
    cont_str = (f" 污染:{node.contamination_score}"
                if node.node_type == NODE_SUSPECT and node.contamination_score else "")

    print(f"{prefix}{connector}{lc}{icon} {node.chain}:{addr_short}{via}  "
          f"[{node.node_type}]  {risk_str}{bl_str}{cont_str}{rc}")

    child_prefix = prefix + ("   " if is_last else "│  ")
    for i, child in enumerate(node.children):
        print_tree(child, child_prefix, i == len(node.children) - 1, use_color)


def print_summary(root: TraceNode, use_color: bool = True):
    """打印扁平化高风险节点汇总"""
    lc_h = LEVEL_COLORS["HIGH"] if use_color else ""
    lc_c = LEVEL_COLORS["CRITICAL"] if use_color else ""
    rc    = LEVEL_COLORS["RESET"] if use_color else ""

    # BFS 收集所有节点
    all_nodes: List[TraceNode] = []
    q: deque = deque([root])
    while q:
        n = q.popleft()
        all_nodes.append(n)
        q.extend(n.children)

    blacklisted = [n for n in all_nodes if n.node_type == NODE_BLACKLISTED]
    mixers      = [n for n in all_nodes if n.node_type == NODE_MIXER]
    opaque      = [n for n in all_nodes if n.node_type == NODE_OPAQUE_BRIDGE]
    high_risk   = [n for n in all_nodes if n.node_type == NODE_HIGH_RISK]
    suspects    = [n for n in all_nodes if n.node_type == NODE_SUSPECT]
    bridge_dst  = [n for n in all_nodes if n.node_type == NODE_BRIDGE_DST]

    print(f"\n{'='*60}")
    print(f"  溯源图分析汇总")
    print(f"{'='*60}")
    print(f"  根节点:     {root.address}  ({root.chain})")
    print(f"  总节点数:   {len(all_nodes)}")
    print(f"  树深度:     {max(n.depth for n in all_nodes)}")
    print(f"  子树最高风险: {lc_c}{root.subtree_max_risk}{rc}")
    print(f"  子树黑名单数: {root.subtree_blacklist_count}")
    print()

    if blacklisted:
        print(f"  {lc_c}黑名单命中节点 ({len(blacklisted)} 个):{rc}")
        for n in blacklisted:
            path = _get_path(n)
            print(f"    🔴 {n.chain}:{n.address}  深度={n.depth}")
            print(f"       路径: {' → '.join(path)}")

    if mixers:
        print(f"\n  {lc_h}混币器节点 ({len(mixers)} 个):{rc}")
        for n in mixers:
            print(f"    🔴 {n.chain}:{n.via_bridge or n.address}  深度={n.depth}")

    if opaque:
        print(f"\n  {lc_h}不透明桥节点 ({len(opaque)} 个):{rc}")
        for n in opaque:
            print(f"    🟠 {n.via_bridge or n.address}  深度={n.depth}  (追踪断开)")

    if bridge_dst:
        print(f"\n  跨链追踪节点 ({len(bridge_dst)} 个):")
        for n in bridge_dst:
            print(f"    🔵 {n.chain}:{n.address[:20]}  经由:{n.via_bridge}  "
                  f"深度={n.depth}  子树风险={n.subtree_max_risk}")

    if high_risk:
        print(f"\n  综合高风险节点 ({len(high_risk)} 个):")
        for n in high_risk:
            print(f"    🟡 {n.chain}:{n.address[:20]}  风险={n.risk_score}  深度={n.depth}")

    if suspects:
        print(f"\n  {lc_h}疑似中转地址 ({len(suspects)} 个):{rc}")
        print(f"  {'─'*50}")
        print(f"  说明: 地址本身未直接命中风险，但子树存在黑名单/混币器/不透明桥命中，")
        print(f"        疑似用于隔离资金来源（洗钱中转跳板）。")
        for n in sorted(suspects, key=lambda x: x.contamination_score, reverse=True):
            print(f"    ⚠  {n.chain}:{n.address[:20]}  深度={n.depth}  "
                  f"子树黑名单={n.subtree_blacklist_count}  "
                  f"污染评分={n.contamination_score}")
            path = _get_path(n)
            print(f"       路径: {' → '.join(path)}")

    print(f"\n{'─'*60}")
    print(f"  深度-风险评估标准（污染衰减系数 {DEPTH_DECAY}/跳）:")
    print(f"    深度1 直接接触  系数=1.00  → CRITICAL / HIGH")
    print(f"    深度2 二跳关联  系数=0.60  → HIGH / MEDIUM")
    print(f"    深度3 三跳关联  系数=0.36  → MEDIUM")
    print(f"    深度4+ 远距联系 系数=≤0.22 → LOW（参考意义为主）")
    print(f"  高风险地址类型: 黑名单 > 混币器 > 不透明桥 > 疑似中转 > 综合评分")
    print(f"\n{'='*60}\n")


def _get_path(node: TraceNode) -> List[str]:
    """从根到此节点的地址路径（用于汇总展示）"""
    path = [node.address[:16] + "..."]
    if node.parent_address:
        path.insert(0, node.parent_address[:16] + "...")
    return path


# ==================== Mermaid 导出 ====================
# 节点类型 → Mermaid 样式（fill颜色）
NODE_MERMAID_STYLE = {
    NODE_CLEAN:         "fill:#90EE90,stroke:#2e8b57,color:#000",   # 浅绿
    NODE_BLACKLISTED:   "fill:#FF4444,stroke:#8b0000,color:#fff",   # 红
    NODE_MIXER:         "fill:#CC0000,stroke:#8b0000,color:#fff",   # 深红
    NODE_OPAQUE_BRIDGE: "fill:#FFA500,stroke:#cc6600,color:#000",   # 橙
    NODE_SUSPECT:       "fill:#FFD700,stroke:#b8860b,color:#000",   # 金黄（中转嫌疑）
    NODE_BRIDGE_DST:    "fill:#4169E1,stroke:#00008b,color:#fff",   # 蓝
    NODE_HIGH_RISK:     "fill:#FFD700,stroke:#b8860b,color:#000",   # 黄
}


def to_mermaid(root: TraceNode) -> str:
    """
    将溯源树转换为 Mermaid flowchart 格式。
    可直接粘贴到 https://mermaid.live 或 Obsidian/Notion 等工具中渲染。
    """
    lines = ["flowchart TD"]
    style_lines = []
    counter = [0]

    # 为每个节点分配唯一短 ID
    node_ids: Dict[str, str] = {}

    def get_id(node: TraceNode) -> str:
        key = node.node_key
        if key not in node_ids:
            counter[0] += 1
            node_ids[key] = f"N{counter[0]}"
        return node_ids[key]

    def node_label(node: TraceNode) -> str:
        addr_short = node.address[:8] + "..." + node.address[-4:]
        chain_tag  = f"[{node.chain}]" if node.chain != "ethereum" else ""
        risk_tag   = f"⚠{node.subtree_max_risk}" if node.subtree_max_risk >= 30 else ""
        via_tag    = f"←{node.via_bridge[:12]}" if node.via_bridge else ""

        parts = [addr_short]
        if chain_tag: parts.append(chain_tag)
        if via_tag:   parts.append(via_tag)
        if risk_tag:  parts.append(risk_tag)

        # 节点形状：黑名单/混币器用六边形，桥用圆角，普通用矩形
        label_text = "\n".join(parts)
        nid = get_id(node)
        if node.node_type in (NODE_BLACKLISTED, NODE_MIXER):
            return f'{nid}{{{{"{ label_text }"}}}}'   # 六边形（终止高风险）
        elif node.node_type == NODE_BRIDGE_DST:
            return f'{nid}(["{label_text}"])'          # 圆角（透明桥目标）
        elif node.node_type == NODE_OPAQUE_BRIDGE:
            return f'{nid}[/"{label_text}"/]'          # 平行四边形（不透明桥）
        elif node.node_type == NODE_SUSPECT:
            return f'{nid}>{"{label_text}"}]'          # 不对称旗帜（中转嫌疑）
        else:
            return f'{nid}["{label_text}"]'            # 普通矩形

    def walk(node: TraceNode):
        nid  = get_id(node)
        nlbl = node_label(node)

        for child in node.children:
            cid  = get_id(child)
            clbl = node_label(child)

            # 边标签：桥名称（若有）
            edge_label = f"|{child.via_bridge[:15]}|" if child.via_bridge else ""
            lines.append(f"    {nlbl} --{edge_label}--> {clbl}")

            # 样式
            style = NODE_MERMAID_STYLE.get(child.node_type, "")
            if style:
                style_lines.append(f"    style {cid} {style}")

            walk(child)

    # 根节点样式
    root_id  = get_id(root)
    root_lbl = node_label(root)
    lines.append(f"    {root_lbl}")
    root_style = NODE_MERMAID_STYLE.get(root.node_type, NODE_MERMAID_STYLE[NODE_CLEAN])
    style_lines.append(f"    style {root_id} {root_style},stroke-width:3px")

    walk(root)
    lines.extend(style_lines)

    # 图例
    lines += [
        "",
        "    %% 图例",
        f'    LEG_BL{{"黑名单"}}',
        f'    LEG_MX{{"混币器"}}',
        "    LEG_OP[/\"不透明桥\"/]",
        "    LEG_BD([\"透明桥目标\"])",
        '    LEG_HR["高风险"]',
        '    LEG_SP>"疑似中转"]',
        '    LEG_CL["普通地址"]',
        f"    style LEG_BL {NODE_MERMAID_STYLE[NODE_BLACKLISTED]}",
        f"    style LEG_MX {NODE_MERMAID_STYLE[NODE_MIXER]}",
        f"    style LEG_OP {NODE_MERMAID_STYLE[NODE_OPAQUE_BRIDGE]}",
        f"    style LEG_BD {NODE_MERMAID_STYLE[NODE_BRIDGE_DST]}",
        f"    style LEG_HR {NODE_MERMAID_STYLE[NODE_HIGH_RISK]}",
        f"    style LEG_SP {NODE_MERMAID_STYLE[NODE_SUSPECT]}",
        f"    style LEG_CL {NODE_MERMAID_STYLE[NODE_CLEAN]}",
    ]

    return "\n".join(lines)


# ==================== CLI ====================
def main():
    parser = argparse.ArgumentParser(
        description="资金溯源图分析 - 递归追踪地址关联网络",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("address", help="要追踪的根地址（0x 格式）")
    parser.add_argument("--chain", default="ethereum",
                        choices=["ethereum", "tron"], help="链类型（默认 ethereum）")
    parser.add_argument("--depth",    type=int, default=3,  help="最大追踪深度（默认 3）")
    parser.add_argument("--children", type=int, default=5,  help="每节点最大子节点数（默认 5）")
    parser.add_argument("--nodes",    type=int, default=50, help="全局节点上限（默认 50）")
    parser.add_argument("--blacklist", default=BLACKLIST_CSV, help="黑名单 CSV 路径")
    parser.add_argument("--json",    metavar="FILE", help="导出 JSON 图结构")
    parser.add_argument("--mermaid", metavar="FILE", help="导出 Mermaid 流程图（.md 文件）")
    parser.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    parser.add_argument("--no-trace", action="store_true", help="禁用透明桥跨链追踪（加快速度）")
    parser.add_argument("--no-hop2",  action="store_true", help="禁用 2 跳分析（加快速度）")
    parser.add_argument("--time-window", type=int, default=0, metavar="DAYS",
                        help="只分析最近 N 天的交易（0=不限制，建议 365~730）")
    parser.add_argument("--depth-bonus", type=int, default=1, metavar="N",
                        help="可疑分支额外追踪深度（默认 1，即多追 1 跳）")
    args = parser.parse_args()

    if args.no_trace:
        _aml.BRIDGE_TRACE_ENABLED = False
    if args.no_hop2:
        _aml.HOP2_ENABLED = False

    print("[*] 加载黑名单...")
    blacklist = load_blacklist(args.blacklist)
    print(f"[*] 已加载 {len(blacklist)} 个黑名单地址")

    etherscan = EtherscanClient(ETHERSCAN_API_KEY)
    tronscan  = TronScanClient()
    tracer    = BridgeTracer()
    analyzer  = AMLAnalyzer(blacklist, etherscan, tronscan, tracer,
                             time_window_days=args.time_window)

    graph = TraceGraph(
        analyzer,
        max_depth    = args.depth,
        max_children = args.children,
        max_nodes    = args.nodes,
        depth_bonus  = args.depth_bonus,
    )

    root = graph.trace(args.address, chain=args.chain)

    print("\n树状结构：")
    print_tree(root, use_color=not args.no_color)
    print_summary(root, use_color=not args.no_color)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(root.to_dict(), f, ensure_ascii=False, indent=2)
        print(f"[*] JSON 图结构已保存: {args.json}")

    if args.mermaid:
        mermaid_text = to_mermaid(root)
        with open(args.mermaid, "w", encoding="utf-8") as f:
            f.write("```mermaid\n")
            f.write(mermaid_text)
            f.write("\n```\n")
        print(f"[*] Mermaid 图已保存: {args.mermaid}")


if __name__ == "__main__":
    main()
