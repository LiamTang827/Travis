# ============================================================
# edge_tagger.py
# 把 detector 结果反标回每条边
# 每条 (tx_hash, log_index) → topo_tags: ["peel_chain", "fan_out", ...]
# ============================================================

import json
from collections import defaultdict


def tag_edges(records, detector_results, nodes=None, edges=None):
    """
    给每条交易记录打拓扑标签

    records:          list of dict（来自 collector_v2.load_from_db）
    detector_results: analyze.py 里 detector_results dict
    nodes/edges:      graph.py 建的图（可选，用于更精确的标注）

    返回：records（in-place 修改 topo_tags 字段）
    """

    # 建索引：from_addr, to_addr → records
    from_idx  = defaultdict(list)
    to_idx    = defaultdict(list)
    pair_idx  = defaultdict(list)

    for rec in records:
        f = rec["from_addr"]
        t = rec["to_addr"]
        from_idx[f].append(rec)
        to_idx[t].append(rec)
        pair_idx[(f, t)].append(rec)

    # ── Peel Chain ──────────────────────────────────────────
    peel = detector_results.get("peel_chain", {})
    if peel.get("detected"):
        chains = peel.get("chains", [])
        for chain in chains:
            # chain 是地址列表 [a, b, c, d, ...]
            for i in range(len(chain) - 1):
                for rec in pair_idx.get((chain[i], chain[i+1]), []):
                    _add_tag(rec, "peel_chain")

    # ── Fan-out ─────────────────────────────────────────────
    fanout = detector_results.get("fanout", {})
    if fanout.get("detected"):
        hubs = fanout.get("hubs", [])
        hub_addrs = {h["address"] if isinstance(h, dict) else h for h in hubs}
        for hub in hub_addrs:
            for rec in from_idx.get(hub, []):
                _add_tag(rec, "fan_out")
            # fan-in: 收款方是hub
            for rec in to_idx.get(hub, []):
                _add_tag(rec, "fan_in")

    # ── Smurfing ────────────────────────────────────────────
    smurfing = detector_results.get("smurfing", {})
    if smurfing.get("detected"):
        patterns = smurfing.get("patterns", [])
        for pat in patterns:
            # pattern 通常有 amount 和 transactions 列表
            txs = pat.get("transactions", pat.get("tx_hashes", []))
            for tx_ref in txs:
                h = tx_ref if isinstance(tx_ref, str) else tx_ref.get("hash", "")
                for rec in records:
                    if rec["tx_hash"] == h:
                        _add_tag(rec, "smurfing")

    # ── Bipartite ───────────────────────────────────────────
    bipartite = detector_results.get("bipartite", {})
    if bipartite.get("detected"):
        groups = bipartite.get("groups", [])
        for grp in groups:
            group_addrs = set(grp.get("group", grp if isinstance(grp, list) else []))
            for rec in records:
                if rec["from_addr"] in group_addrs or rec["to_addr"] in group_addrs:
                    _add_tag(rec, "bipartite")

    # ── Mixer ───────────────────────────────────────────────
    mixer = detector_results.get("mixer", {})
    if mixer.get("detected"):
        mixer_addrs = set(mixer.get("mixer_addresses", []))
        for rec in records:
            if rec["from_addr"] in mixer_addrs or rec["to_addr"] in mixer_addrs:
                _add_tag(rec, "mixer")

    # ── Blacklist ───────────────────────────────────────────
    blacklist = detector_results.get("blacklist", {})
    if blacklist.get("detected"):
        bl_addrs = set(blacklist.get("blacklist_hits", {}).keys())
        for rec in records:
            if rec["from_addr"] in bl_addrs or rec["to_addr"] in bl_addrs:
                _add_tag(rec, "blacklist")

    # ── Cross-chain ─────────────────────────────────────────
    crosschain = detector_results.get("crosschain", {})
    if crosschain.get("detected"):
        bridge_addrs = set(crosschain.get("bridge_addresses", []))
        for rec in records:
            if rec["from_addr"] in bridge_addrs or rec["to_addr"] in bridge_addrs:
                _add_tag(rec, "cross_chain")

    # ── DeFi ────────────────────────────────────────────────
    defi = detector_results.get("defi", {})
    if defi.get("detected"):
        defi_type = defi.get("defi_type", "dex_swap")
        for rec in records:
            if rec["method"] in (
                "exactInputSingle", "exactInput", "swap",
                "swapExactTokensForTokens", "swapExactETHForTokens",
                "multicall", "addLiquidity", "removeLiquidity",
            ):
                _add_tag(rec, f"defi_{defi_type}")

    # ── Dusting ─────────────────────────────────────────────
    dusting = detector_results.get("dusting", {})
    if dusting.get("detected"):
        dust_threshold = dusting.get("threshold", 1000000)  # 1 USDT in raw
        for rec in records:
            try:
                val = int(rec.get("value_raw", 0))
                if val > 0 and val < dust_threshold:
                    _add_tag(rec, "dusting")
            except:
                pass

    # ── Pig Butchering ──────────────────────────────────────
    pig = detector_results.get("pig_butchering", {})
    if pig.get("detected"):
        for rec in records:
            _add_tag(rec, "pig_butchering")

    # ── NFT ─────────────────────────────────────────────────
    nft = detector_results.get("nft", {})
    if nft.get("detected"):
        nft_methods = {"safeMint", "mint", "transferFrom", "safeTransferFrom"}
        for rec in records:
            if rec["method"] in nft_methods:
                _add_tag(rec, "nft_washing")

    return records


def _add_tag(rec, tag):
    if tag not in rec["topo_tags"]:
        rec["topo_tags"].append(tag)


# ============================================================
# 把标签写回 SQLite
# ============================================================

def flush_tags_to_db(records, conn):
    """把 topo_tags 批量写回数据库"""
    from collector_v2 import update_topo_tags
    count = 0
    for rec in records:
        if rec["topo_tags"]:
            update_topo_tags(rec["tx_hash"], rec["log_index"], rec["topo_tags"], conn)
            count += 1
    print(f"    [edge_tagger] 写入 {count} 条边标签")


# ============================================================
# 导出带标签的图 JSON（给前端用）
# ============================================================

TOPO_COLORS = {
    "blacklist":     "#ff2244",
    "peel_chain":    "#ff4400",
    "fan_out":       "#ff6622",
    "fan_in":        "#ff6622",
    "smurfing":      "#ffaa00",
    "bipartite":     "#cc44ff",
    "mixer":         "#ff00aa",
    "cross_chain":   "#00aaff",
    "defi_dex_swap": "#22ccaa",
    "dusting":       "#888888",
    "pig_butchering":"#ff8800",
    "nft_washing":   "#aa88ff",
}

TOPO_PRIORITY = [
    "blacklist", "mixer", "peel_chain", "pig_butchering",
    "fan_out", "fan_in", "smurfing", "bipartite",
    "cross_chain", "nft_washing", "defi_dex_swap", "dusting",
]


def edge_color(topo_tags):
    """按优先级返回边颜色"""
    for tag in TOPO_PRIORITY:
        if tag in topo_tags:
            return TOPO_COLORS[tag]
    return "rgba(42,90,138,0.2)"


def edge_width(topo_tags, tx_count=1):
    """高风险边更粗"""
    high_risk = {"blacklist", "mixer", "peel_chain", "pig_butchering"}
    if any(t in high_risk for t in topo_tags):
        return min(1.5 + tx_count * 0.3, 6)
    return min(0.5 + tx_count * 0.15, 3)


def records_to_graph_json(records, target_address=None, max_nodes=500):
    """
    把带标签的 records 转成前端图 JSON
    格式兼容 lucidaml_subgraph.html
    """
    from collections import Counter

    # 建节点统计
    node_stats = defaultdict(lambda: {
        "tx_count": 0, "total_in": 0, "total_out": 0,
        "methods": set(), "topo_tags": set(),
        "is_blacklist": False, "is_target": False,
    })

    edge_agg = defaultdict(lambda: {
        "tx_count": 0, "amount": 0,
        "methods": set(), "topo_tags": set(),
        "txs": [],
    })

    for rec in records:
        f = rec["from_addr"]
        t = rec["to_addr"]
        try:
            val = int(rec.get("value_raw", 0))
            dec = int(rec.get("token_decimal", 18))
            amount = val / (10 ** dec)
        except:
            amount = 0

        node_stats[f]["tx_count"]  += 1
        node_stats[f]["total_out"] += amount
        node_stats[f]["methods"].add(rec["method"])
        node_stats[t]["total_in"]  += amount

        for tag in rec["topo_tags"]:
            node_stats[f]["topo_tags"].add(tag)
            node_stats[t]["topo_tags"].add(tag)
            if tag == "blacklist":
                node_stats[f]["is_blacklist"] = True
                node_stats[t]["is_blacklist"] = True

        if target_address and (f == target_address.lower() or t == target_address.lower()):
            node_stats[f]["is_target"] = True
            node_stats[t]["is_target"] = True

        key = (f, t)
        edge_agg[key]["tx_count"] += 1
        edge_agg[key]["amount"]   += amount
        edge_agg[key]["methods"].add(rec["method"])
        for tag in rec["topo_tags"]:
            edge_agg[key]["topo_tags"].add(tag)
        if len(edge_agg[key]["txs"]) < 20:
            edge_agg[key]["txs"].append({
                "hash":   rec["tx_hash"],
                "amount": amount,
                "method": rec["method"],
                "ts":     rec["ts"],
                "tags":   rec["topo_tags"],
            })

    # 采样节点（优先高风险）
    def node_priority(item):
        addr, stats = item
        bl  = 0 if stats["is_blacklist"] else 1
        tgt = 0 if stats["is_target"] else 1
        topo_score = -len(stats["topo_tags"])
        return (bl, tgt, topo_score, -stats["tx_count"])

    sorted_nodes = sorted(node_stats.items(), key=node_priority)[:max_nodes]
    kept = {addr for addr, _ in sorted_nodes}

    # 同心圆布局（按风险标签分层）
    import math
    cx, cy = 800, 500
    by_layer = defaultdict(list)
    for addr, stats in sorted_nodes:
        tags = stats["topo_tags"]
        if stats["is_blacklist"]:        layer = 0
        elif "mixer" in tags:            layer = 1
        elif "peel_chain" in tags:       layer = 2
        elif "fan_out" in tags or "fan_in" in tags: layer = 3
        elif "smurfing" in tags:         layer = 4
        elif stats["is_target"]:         layer = 5
        else:                            layer = 6
        by_layer[layer].append(addr)

    positions = {}
    for layer, addrs in by_layer.items():
        r = 80 + layer * 120
        for i, addr in enumerate(addrs):
            angle = (2 * math.pi * i) / max(len(addrs), 1)
            positions[addr] = (
                cx + r * math.cos(angle) + (hash(addr) % 20 - 10),
                cy + r * math.sin(angle) + (hash(addr) % 20 - 10),
            )

    # 组装节点
    nodes_out = []
    for addr, stats in sorted_nodes:
        x, y = positions.get(addr, (cx, cy))
        tags  = list(stats["topo_tags"])
        color = next((TOPO_COLORS[t] for t in TOPO_PRIORITY if t in tags), "#1e3a5f")
        nodes_out.append({
            "id":           addr,
            "label":        addr[:6] + "..." + addr[-4:],
            "x":            round(x, 1),
            "y":            round(y, 1),
            "hop":          None,
            "risk":         "BLACKLIST" if stats["is_blacklist"] else
                            ("HIGH" if tags else "SAFE"),
            "risk_score":   0,
            "tx_count":     stats["tx_count"],
            "total_out":    round(stats["total_out"], 4),
            "total_in":     round(stats["total_in"], 4),
            "methods":      list(stats["methods"])[:5],
            "topo_tags":    tags,
            "is_blacklist": stats["is_blacklist"],
            "is_protocol":  False,
            "is_target":    stats["is_target"],
            "color":        color,
        })

    # 组装边
    links_out = []
    for (f, t), edata in edge_agg.items():
        if f not in kept or t not in kept:
            continue
        tags = list(edata["topo_tags"])
        links_out.append({
            "source":    f,
            "target":    t,
            "tx_count":  edata["tx_count"],
            "amount":    round(edata["amount"], 4),
            "methods":   list(edata["methods"])[:3],
            "topo_tags": tags,
            "color":     edge_color(tags),
            "width":     edge_width(tags, edata["tx_count"]),
            "txs":       edata["txs"],
        })

    # topo 告警摘要
    all_tags = Counter()
    for rec in records:
        for tag in rec["topo_tags"]:
            all_tags[tag] += 1

    alerts = [
        {"type": tag, "level": "HIGH" if tag in {"blacklist","mixer","peel_chain"} else "MEDIUM",
         "count": cnt, "desc": f"{cnt} transactions"}
        for tag, cnt in all_tags.most_common()
    ]

    return {
        "meta": {
            "target":          target_address,
            "total_rows":      len(records),
            "total_nodes_original": len(node_stats),
            "nodes_rendered":  len(nodes_out),
            "sampled":         len(node_stats) > max_nodes,
        },
        "alerts": alerts,
        "nodes":  nodes_out,
        "links":  links_out,
    }
