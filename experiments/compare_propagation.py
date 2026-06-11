#!/usr/bin/env python3
"""
风险传播算法对比实验
======================
用真实 transfer 数据构造子图，对比三种风险传播策略的差异：
  A) 当前方法：固定 0.6 衰减，只取 max
  B) Möser Haircut：按交易金额比例分配 taint
  C) 改进版：节点类型感知衰减 + 多路径独立证据合并

Author: CriptoAnalyst experiment
"""

import json
import os
import sys
from collections import defaultdict
from typing import Dict, List, Tuple

# ==================== 已知实体类型注册表 ====================
# 从 aml_analyzer.py 复用关键地址
KNOWN_MIXERS = {
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash",
    "0x23773e65ed146a459791799d01336db287f25334": "Tornado Cash",
    "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc": "Tornado Cash 0.1 ETH",
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado Cash 1 ETH",
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado Cash 10 ETH",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash 100 ETH",
}

KNOWN_CEX = {
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549": "Binance",
    "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": "Binance",
    "0x28c6c06298d514db089934071355e5743bf21d60": "Binance 14",
    "0x56eddb7aa87536c09ccc2793473599fd21a8b17f": "Binance 16",
}

KNOWN_DEX = {
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap Universal Router",
}


def get_entity_type(addr: str) -> str:
    addr = addr.lower()
    if addr in KNOWN_MIXERS:
        return "mixer"
    if addr in KNOWN_CEX:
        return "cex"
    if addr in KNOWN_DEX:
        return "dex"
    return "unknown_eoa"


# ==================== 传播率表 ====================
PROPAGATION_RATE = {
    "mixer":         0.85,  # 几乎所有经过 mixer 的钱都是为了混淆
    "opaque_bridge": 0.80,  # 不可追踪的桥
    "flagged":       0.75,  # 已知高风险
    "unknown_eoa":   0.45,  # 普通未知地址
    "transparent_bridge": 0.55,
    "dex":           0.15,  # 大量正常用户共用
    "cex":           0.05,  # 交易所：风险到此基本消散
}


# ==================== 方法 A：当前系统（固定 0.6，只取 max）====================
def propagate_current(graph: Dict, seed_scores: Dict[str, float]) -> Dict[str, float]:
    """
    当前 trace_graph.py 的传播逻辑：
    - 固定衰减 0.6/跳
    - 多个子节点只取 max
    - 不考虑交易金额
    """
    DECAY = 0.6
    scores = dict(seed_scores)

    # BFS 从 seed 向外传播
    visited = set()
    from collections import deque
    queue = deque()

    for seed in seed_scores:
        queue.append((seed, 0))
        visited.add(seed)

    while queue:
        node, depth = queue.popleft()

        for neighbor, edge_data in graph.get(node, {}).items():
            if neighbor in visited:
                continue
            visited.add(neighbor)

            # 固定衰减
            decayed = scores[node] * DECAY
            scores[neighbor] = max(scores.get(neighbor, 0), decayed)
            queue.append((neighbor, depth + 1))

    return scores


# ==================== 方法 B：Möser Haircut ====================
def propagate_haircut(graph: Dict, seed_scores: Dict[str, float],
                      outflows: Dict[str, float]) -> Dict[str, float]:
    """
    Möser 2014 Haircut 法：
    - taint 按金额比例分配（发给你的钱占我总发出的比例）
    - 仍只取最短路径（单次 BFS）
    """
    scores = dict(seed_scores)
    visited = set()
    from collections import deque
    queue = deque()

    for seed in seed_scores:
        queue.append(seed)
        visited.add(seed)

    while queue:
        node = queue.popleft()
        total_out = outflows.get(node, 0)

        for neighbor, edge_data in graph.get(node, {}).items():
            if neighbor in visited:
                continue
            visited.add(neighbor)

            # Haircut: 按金额占比分配
            if total_out > 0:
                volume_ratio = edge_data["amount"] / total_out
            else:
                volume_ratio = 1.0  # 没有流出记录时退化为全量传播

            decayed = scores[node] * volume_ratio
            scores[neighbor] = max(scores.get(neighbor, 0), decayed)
            queue.append(neighbor)

    return scores


# ==================== 方法 C：完整改进版 ====================
def propagate_improved(graph: Dict, seed_scores: Dict[str, float],
                       outflows: Dict[str, float]) -> Dict[str, float]:
    """
    改进版传播：
    - 节点类型决定传播率（mixer 0.85, CEX 0.05）
    - Möser Haircut 金额加权
    - 多路径独立证据合并: P = 1 - ∏(1 - pᵢ)
    - 迭代收敛（处理环路）
    """
    scores = {node: 0.0 for node in _all_nodes(graph)}
    scores.update(seed_scores)

    MAX_ITER = 15
    for iteration in range(MAX_ITER):
        new_scores = dict(seed_scores)  # seed 分数固定不变

        for node in _all_nodes(graph):
            if node in seed_scores:
                continue  # seed 不被覆盖

            # 收集所有入边的贡献
            contributions = []
            for parent, edges in graph.items():
                if node in edges:
                    edge_data = edges[node]

                    # (1) 节点类型传播率
                    parent_type = get_entity_type(parent)
                    type_rate = PROPAGATION_RATE.get(parent_type, 0.45)

                    # (2) Haircut 金额比例
                    total_out = outflows.get(parent, 0)
                    if total_out > 0:
                        volume_ratio = min(edge_data["amount"] / total_out, 1.0)
                    else:
                        volume_ratio = 1.0

                    # (3) 单条路径贡献
                    p = scores[parent] * type_rate * volume_ratio
                    p = min(p, 1.0)  # clamp
                    if p > 0.001:
                        contributions.append(p)

            if contributions:
                # 独立证据合并: 1 - ∏(1 - pᵢ)
                product = 1.0
                for p in contributions:
                    product *= (1 - p)
                new_scores[node] = 1.0 - product
            else:
                new_scores[node] = scores.get(node, 0)

        # 检查收敛
        max_delta = max(abs(new_scores.get(n, 0) - scores.get(n, 0))
                        for n in _all_nodes(graph))
        scores = new_scores

        if max_delta < 0.001:
            print(f"    [收敛] 第 {iteration+1} 轮收敛，max_delta={max_delta:.6f}")
            break

    return scores


def _all_nodes(graph):
    nodes = set()
    for parent, edges in graph.items():
        nodes.add(parent)
        for child in edges:
            nodes.add(child)
    return nodes


# ==================== 从真实数据构建子图 ====================
def build_graph_from_transfers(json_path: str) -> Tuple[Dict, Dict[str, float], str]:
    """
    从 transfer JSON 构建有向加权图。

    返回:
      graph: {from_addr: {to_addr: {"amount": total_amount, "count": N}}}
      outflows: {addr: total_outflow}
      center_addr: 中心地址
    """
    with open(json_path) as f:
        data = json.load(f)

    center = data["address"].lower()
    graph = defaultdict(lambda: defaultdict(lambda: {"amount": 0.0, "count": 0}))
    outflows = defaultdict(float)

    for tx in data.get("transfers_sent", []):
        fr = tx["from"].lower()
        to = tx["to"].lower()
        amt = float(tx["amount"])
        graph[fr][to]["amount"] += amt
        graph[fr][to]["count"] += 1
        outflows[fr] += amt

    for tx in data.get("transfers_received", []):
        fr = tx["from"].lower()
        to = tx["to"].lower()
        amt = float(tx["amount"])
        graph[fr][to]["amount"] += amt
        graph[fr][to]["count"] += 1
        outflows[fr] += amt

    return dict(graph), dict(outflows), center


# ==================== 场景构建 ====================
def scenario_real_data():
    """
    场景1：用真实 blocklisted 地址 0x0027846505cd5e91bdb743770f3d89de9cb7b978 的数据。
    这是一个经典的 pass-through 钱包：从多个来源收钱，全部转给一个目标。
    """
    print("=" * 70)
    print("  场景 1: 真实 blocklisted pass-through 钱包")
    print("=" * 70)

    json_path = os.path.join(os.path.dirname(__file__),
                             "ml/data/transfers/0x0027846505cd5e91bdb743770f3d89de9cb7b978.json")
    if not os.path.exists(json_path):
        print(f"  [SKIP] 文件不存在: {json_path}")
        return

    graph, outflows, center = build_graph_from_transfers(json_path)

    # 这个地址本身就是 blocklisted，设为 seed
    seed_scores = {center: 1.0}

    print(f"\n  中心地址 (seed): {center[:16]}... [blocklisted, risk=1.0]")
    print(f"  图中节点数: {len(_all_nodes(graph))}")
    print(f"  图中边数: {sum(len(v) for v in graph.values())}")

    # 列出图结构
    print(f"\n  图结构:")
    for parent, edges in graph.items():
        p_type = get_entity_type(parent)
        p_label = "★SEED" if parent == center else p_type
        total = outflows.get(parent, 0)
        for child, data in edges.items():
            c_type = get_entity_type(child)
            pct = (data['amount'] / total * 100) if total > 0 else 0
            print(f"    {parent[:12]}...[{p_label}] "
                  f"→ {child[:12]}...[{c_type}]  "
                  f"${data['amount']:>12,.0f} ({pct:5.1f}% of outflow)  x{data['count']}")

    # 运行三种方法
    print(f"\n  --- 方法 A: 当前系统（固定 0.6 衰减）---")
    scores_a = propagate_current(graph, seed_scores)

    print(f"\n  --- 方法 B: Möser Haircut（金额比例）---")
    scores_b = propagate_haircut(graph, seed_scores, outflows)

    print(f"\n  --- 方法 C: 改进版（类型+金额+多路径）---")
    scores_c = propagate_improved(graph, seed_scores, outflows)

    # 对比输出
    print(f"\n  {'地址':^18s} {'类型':^12s} {'方法A':>8s} {'方法B':>8s} {'方法C':>8s}  差异说明")
    print(f"  {'─'*80}")

    all_addrs = sorted(_all_nodes(graph), key=lambda x: scores_c.get(x, 0), reverse=True)
    for addr in all_addrs:
        if addr == center:
            continue
        a = scores_a.get(addr, 0)
        b = scores_b.get(addr, 0)
        c = scores_c.get(addr, 0)
        etype = get_entity_type(addr)

        note = ""
        if abs(a - c) > 0.1:
            if c > a:
                note = f"← 改进版更高 (+{c-a:.2f})"
            else:
                note = f"← 改进版更低 ({c-a:.2f})"

        print(f"  {addr[:18]}  {etype:^12s}  {a:>7.3f}  {b:>7.3f}  {c:>7.3f}  {note}")


def scenario_convergent_paths():
    """
    场景2：手工构造一个汇聚路径 + 不同节点类型的场景。

    Blacklisted_A (risk=1.0)
       ├→ Mixer_M (0.85 传播率)
       │    └→ Target_T
       ├→ Unknown_B (0.45 传播率)
       │    └→ Target_T   ← 多路径汇聚！
       └→ CEX_Binance (0.05 传播率)
            └→ Target_T

    当前系统: T 只会得到 max(A→M→T, A→B→T, A→CEX→T) = A→M→T 的 0.6^2 = 0.36
    Haircut:   取决于金额分配
    改进版:    T 得到三条路径的独立证据合并，且 Mixer 路径权重 >> CEX 路径
    """
    print("\n" + "=" * 70)
    print("  场景 2: 汇聚路径 + 不同节点类型（手工构造）")
    print("=" * 70)

    # 构造图
    A = "0xaaaa_blacklisted_seed"
    M = "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b"  # Tornado Cash (真实地址)
    B = "0xbbbb_unknown_middleman"
    CEX = "0x28c6c06298d514db089934071355e5743bf21d60"  # Binance 14 (真实地址)
    T = "0xtttt_target_convergence"

    # A 分别发给 M, B, CEX
    # M, B, CEX 分别发给 T
    graph = {
        A: {
            M:   {"amount": 50000, "count": 5},    # $50k 去 mixer
            B:   {"amount": 30000, "count": 3},    # $30k 去中间人
            CEX: {"amount": 20000, "count": 2},    # $20k 去交易所
        },
        M:   {T: {"amount": 50000, "count": 5}},
        B:   {T: {"amount": 30000, "count": 3}},
        CEX: {T: {"amount": 20000, "count": 2}},
    }
    outflows = {
        A: 100000,
        M: 50000,
        B: 30000,
        CEX: 20000,
    }
    seed_scores = {A: 1.0}

    print(f"\n  图结构:")
    print(f"    A (blocklisted, risk=1.0)")
    print(f"    ├→ M (Tornado Cash)     $50,000  (50% of A's outflow)")
    print(f"    │   └→ T (target)       $50,000")
    print(f"    ├→ B (unknown EOA)      $30,000  (30% of A's outflow)")
    print(f"    │   └→ T (target)       $30,000")
    print(f"    └→ CEX (Binance)        $20,000  (20% of A's outflow)")
    print(f"        └→ T (target)       $20,000")
    print(f"")
    print(f"  问题: T 同时从 mixer、middleman、CEX 收到资金。")
    print(f"        正确答案: T 应该有高风险（多源汇聚），但 CEX 那条线不该贡献太多。")

    # 运行三种方法
    print(f"\n  --- 方法 A: 当前系统（固定 0.6 衰减）---")
    scores_a = propagate_current(graph, seed_scores)

    print(f"\n  --- 方法 B: Möser Haircut（金额比例）---")
    scores_b = propagate_haircut(graph, seed_scores, outflows)

    print(f"\n  --- 方法 C: 改进版（类型+金额+多路径）---")
    scores_c = propagate_improved(graph, seed_scores, outflows)

    # 对比
    print(f"\n  {'节点':^25s} {'类型':^12s} {'方法A':>8s} {'方法B':>8s} {'方法C':>8s}")
    print(f"  {'─'*65}")

    labels = {A: "A (seed)", M: "M (Tornado Cash)", B: "B (unknown)", CEX: "CEX (Binance)", T: "T (target)"}
    for node in [A, M, B, CEX, T]:
        a = scores_a.get(node, 0)
        b = scores_b.get(node, 0)
        c = scores_c.get(node, 0)
        etype = get_entity_type(node) if node not in [A, T, B] else ("seed" if node == A else "target" if node == T else "unknown_eoa")
        print(f"  {labels[node]:^25s}  {etype:^12s}  {a:>7.3f}  {b:>7.3f}  {c:>7.3f}")

    # 详细解释
    print(f"\n  分析:")
    print(f"  方法 A: T = max(0.6×0.6, 0.6×0.6, 0.6×0.6) = {scores_a.get(T, 0):.3f}")
    print(f"          → 三条路径完全相同！Mixer 和 Binance 被同等对待。")

    t_hair_via_m = scores_b.get(M, 0) * 1.0  # M 全部发给 T
    t_hair_via_b = scores_b.get(B, 0) * 1.0
    t_hair_via_cex = scores_b.get(CEX, 0) * 1.0
    print(f"  方法 B: M={scores_b.get(M,0):.3f}, B={scores_b.get(B,0):.3f}, CEX={scores_b.get(CEX,0):.3f}")
    print(f"          T = max(M→T, B→T, CEX→T) = {scores_b.get(T, 0):.3f}")
    print(f"          → 金额加权生效（A→M 占 50%），但还是只取 max。")

    # 改进版的详细计算
    # A→M: type_rate(A)=0.45 (treated as unknown), volume=50k/100k=0.5
    # Actually A is seed with score 1.0
    # M gets: 1.0 × PROPAGATION_RATE[unknown_eoa for A? A isn't in entity registry] × (50k/100k)
    # Hmm, A is the seed, its type matters...
    print(f"  方法 C:")
    print(f"    M 的分数: A(1.0) × rate(A:unknown=0.45) × volume(50k/100k=0.5) = {scores_c.get(M, 0):.3f}")
    print(f"    B 的分数: A(1.0) × rate(A:unknown=0.45) × volume(30k/100k=0.3) = {scores_c.get(B, 0):.3f}")
    print(f"    CEX 分数: A(1.0) × rate(A:unknown=0.45) × volume(20k/100k=0.2) = {scores_c.get(CEX, 0):.3f}")

    # T receives from M, B, CEX
    p_m = scores_c.get(M, 0) * PROPAGATION_RATE["mixer"] * 1.0  # M→T = 100%
    p_b = scores_c.get(B, 0) * PROPAGATION_RATE["unknown_eoa"] * 1.0
    p_c = scores_c.get(CEX, 0) * PROPAGATION_RATE["cex"] * 1.0
    combined = 1.0 - (1 - p_m) * (1 - p_b) * (1 - p_c)
    print(f"    T 的三条入边贡献:")
    print(f"      M→T: {scores_c.get(M,0):.3f} × rate(mixer=0.85) × vol(1.0) = {p_m:.3f}")
    print(f"      B→T: {scores_c.get(B,0):.3f} × rate(unknown=0.45) × vol(1.0) = {p_b:.3f}")
    print(f"      CEX→T: {scores_c.get(CEX,0):.3f} × rate(cex=0.05) × vol(1.0) = {p_c:.3f}")
    print(f"      合并: 1-(1-{p_m:.3f})(1-{p_b:.3f})(1-{p_c:.3f}) = {combined:.3f}")
    print(f"      实际(迭代收敛): {scores_c.get(T, 0):.3f}")
    print(f"")
    print(f"  关键差异:")
    print(f"    方法A: Mixer 路径和 Binance 路径对 T 贡献完全相同 → 不合理")
    print(f"    方法B: 金额分配更合理，但 max 只取一条路径 → 忽略了汇聚效应")
    print(f"    方法C: Mixer 贡献 >> Binance 贡献，且三条路径独立合并 → 最接近真实情况")


def scenario_cex_damping():
    """
    场景3：普通用户收到来自 Binance 的转账，而 Binance 也和 blacklisted 地址有交易。
    这是典型的"无辜被污染"场景。

    Blacklisted_A → Binance (CEX) → Innocent_User

    当前系统: User 风险 = 1.0 × 0.6 × 0.6 = 0.36（MEDIUM）→ 可能导致误判
    改进版:   User 风险 = 1.0 × 0.45 × (amt/total) × 0.05 × 1.0 ≈ 极低
             因为 Binance 每天处理千万笔交易，单一 blacklisted 来源的 taint 被稀释到几乎为零
    """
    print("\n" + "=" * 70)
    print("  场景 3: 无辜用户通过 CEX 被间接污染")
    print("=" * 70)

    A = "0xaaaa_blacklisted"
    CEX = "0x28c6c06298d514db089934071355e5743bf21d60"  # Binance 14
    USER = "0xdddd_innocent_user"

    graph = {
        A:   {CEX: {"amount": 10000, "count": 1}},
        CEX: {USER: {"amount": 500, "count": 1}},
    }
    # 关键：Binance 每天处理数百万 USDT，A 的 10000 只是沧海一粟
    outflows = {
        A: 10000,
        CEX: 50_000_000,  # Binance 日均 outflow: $5000万+
    }
    seed_scores = {A: 1.0}

    print(f"\n  图结构:")
    print(f"    A (blocklisted) →[$10,000]→ Binance →[$500]→ Innocent User")
    print(f"    Binance 日均 outflow: $50,000,000")
    print(f"")
    print(f"  问题: User 只是碰巧从 Binance 提币，和 A 完全无关。")
    print(f"        当前系统会给 User 0.36 分（MEDIUM），导致误判。")

    scores_a = propagate_current(graph, seed_scores)
    scores_b = propagate_haircut(graph, seed_scores, outflows)

    print(f"\n  --- 方法 C ---")
    scores_c = propagate_improved(graph, seed_scores, outflows)

    print(f"\n  {'节点':^25s} {'方法A':>8s} {'方法B':>8s} {'方法C':>8s}")
    print(f"  {'─'*50}")
    for node, label in [(A, "A (blacklisted)"), (CEX, "Binance (CEX)"), (USER, "Innocent User")]:
        a = scores_a.get(node, 0)
        b = scores_b.get(node, 0)
        c = scores_c.get(node, 0)
        print(f"  {label:^25s}  {a:>7.4f}  {b:>7.4f}  {c:>7.4f}")

    print(f"\n  分析:")
    print(f"    方法 A: User = {scores_a.get(USER,0):.4f}  → MEDIUM 风险，触发误报！")
    print(f"    方法 B: User = {scores_b.get(USER,0):.6f}")
    print(f"             (Binance outflow $50M, A→Binance $10k 占 0.02%,")
    print(f"              Binance→User $500 占 0.001% → taint 基本消散)")
    print(f"    方法 C: User = {scores_c.get(USER,0):.6f}")
    print(f"             (Binance 传播率仅 0.05，再乘 volume ratio → 几乎为零)")
    print(f"")
    print(f"  结论: 方法 A 会误伤无辜用户，方法 B/C 正确识别了 CEX 的 taint 隔断效应。")


# ==================== Main ====================
if __name__ == "__main__":
    print("\n" + "█" * 70)
    print("  风险传播算法 A/B/C 对比实验")
    print("█" * 70)

    scenario_real_data()
    scenario_convergent_paths()
    scenario_cex_damping()

    print("\n" + "=" * 70)
    print("  总结")
    print("=" * 70)
    print("""
  1. 方法 A（当前系统）问题:
     - 固定 0.6 衰减让 Mixer 和 Binance 被同等对待
     - 只取 max 丢失了多路径汇聚信号
     - CEX 场景会产生大量误报

  2. 方法 B（Möser Haircut）改进:
     - 金额比例分配解决了"大额 vs 小额"不区分的问题
     - CEX 的海量 outflow 自然稀释了 taint
     - 但仍只取 max，不处理多路径

  3. 方法 C（完整改进）优势:
     - 节点类型感知: mixer 高传播, CEX 低传播 → 符合直觉
     - Haircut 金额加权: 大额交易传播更多 taint
     - 多路径合并: 汇聚节点的风险正确累积
     - 迭代收敛: 自然处理环路
""")
