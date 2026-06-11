# ============================================================
# detectors/d_crosschain.py
# 跨链桥检测
# 覆盖：D1 透明桥、D2 不透明桥、D3 多链快速跳转
# ============================================================

from collections import defaultdict

# ── 透明桥（有 source-target 映射记录）────────────────────
TRANSPARENT_BRIDGES = {
    "0x1116898dda4015ed8ddefb84b6e8bc24528af2d8": "Harmony Horizon Bridge",
    "0x40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf": "Polygon PoS Bridge",
    "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1": "Optimism Bridge",
    "0x3ee18b2214aff97000d974cf647e7c347e8fa585": "Wormhole Bridge",
    "0x5a58505a96d1dbf8df91cb21b54419fc36e93fde": "Hop Protocol",
    "0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f": "Arbitrum Inbox",
    "0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a": "Arbitrum Bridge",
}

# ── 不透明桥（流动性池模式，断链）────────────────────────
OPAQUE_BRIDGES = {
    "0x9ad122c22b14202b4490edaf288fdb3c7cb3ff5e": "Railgun",
    "0x2796317b0ff8538f1925E9b2B8C75C955b9C6Bf": "Synapse Bridge",
    "0xd31a59c85ae9d8edefec411d448f90841571b89c": "Wanchain Bridge",
    "0xa0c68c638235ee32657e8f720a23cec1bfc77c77": "Polygon Plasma Bridge",
    "0x48b62137edfa95a428d35c09e44256a739f6b557": "Orbiter Finance",
}

# ── 已知被制裁的桥合约 ─────────────────────────────────────
SANCTIONED_BRIDGES = {
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": "Tornado Cash Router (OFAC)",
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado Cash 1ETH (OFAC)",
}

# 快速跳转时间窗口（24小时）
RAPID_HOP_WINDOW = 86400


def detect(nodes, edges, target_address=None, eth_txs=None, **kwargs):
    """
    检测跨链桥相关洗钱手法

    D1 透明桥：与已知透明桥合约交互
    D2 不透明桥：与已知不透明桥合约交互（更可疑）
    D3 多链快速跳转：短时间内资金经过多个桥

    返回：
      detected:        bool
      severity:        CRITICAL / HIGH / MEDIUM
      transparent:     D1 结果
      opaque:          D2 结果
      rapid_hop:       D3 结果
      sanctioned:      制裁桥合约交互
    """
    results = {}

    # ── 制裁桥（最高优先级）──────────────────────────────
    results["sanctioned"] = _detect_sanctioned(nodes, edges)

    # ── D2 不透明桥 ───────────────────────────────────────
    results["opaque"] = _detect_opaque(nodes, edges, target_address)

    # ── D1 透明桥 ─────────────────────────────────────────
    results["transparent"] = _detect_transparent(nodes, edges, target_address)

    # ── D3 多链快速跳转 ───────────────────────────────────
    results["rapid_hop"] = _detect_rapid_hop(nodes, edges, target_address)

    any_detected = any(v.get("detected") for v in results.values())
    if not any_detected:
        return {"detected": False}

    # 最高严重度
    sevs = [v.get("severity","LOW") for v in results.values() if v.get("detected")]
    top  = ("CRITICAL" if "CRITICAL" in sevs
            else "HIGH" if "HIGH" in sevs
            else "MEDIUM")

    detected_types = [k for k,v in results.items() if v.get("detected")]

    return {
        "detected":       True,
        "severity":       top,
        "results":        results,
        "detected_types": detected_types,
        "summary":        f"跨链桥检测: {', '.join(detected_types)}",
    }


def _detect_sanctioned(nodes, edges):
    """制裁桥合约交互"""
    hits = []
    for addr in nodes:
        if addr in SANCTIONED_BRIDGES:
            hits.append({
                "address": addr,
                "label":   SANCTIONED_BRIDGES[addr],
            })
    if not hits:
        return {"detected": False}
    return {
        "detected": True,
        "severity": "CRITICAL",
        "hits":     hits,
        "summary":  f"与 {len(hits)} 个制裁桥合约交互",
    }


def _detect_opaque(nodes, edges, target_address):
    """D2 不透明桥检测"""
    addr = (target_address or "").lower()
    hits = []

    for bridge_addr, bridge_name in OPAQUE_BRIDGES.items():
        if bridge_addr not in nodes:
            continue

        # 找与目标地址的交互
        interactions = [
            (f, t, v, ts, typ) for (f, t, v, ts, typ) in edges
            if (f == addr and t == bridge_addr)
            or (t == addr and f == bridge_addr)
        ]

        if interactions:
            sent = sum(v for f,t,v,ts,typ in interactions if f==addr)
            recv = sum(v for f,t,v,ts,typ in interactions if t==addr)
            hits.append({
                "bridge":   bridge_name,
                "address":  bridge_addr,
                "sent":     sent,
                "received": recv,
                "tx_count": len(interactions),
            })

    if not hits:
        return {"detected": False}

    return {
        "detected": True,
        "severity": "HIGH",
        "hits":     hits,
        "summary":  f"使用不透明跨链桥 {len(hits)} 次（链上关联断裂）",
    }


def _detect_transparent(nodes, edges, target_address):
    """D1 透明桥检测"""
    addr = (target_address or "").lower()
    hits = []

    for bridge_addr, bridge_name in TRANSPARENT_BRIDGES.items():
        if bridge_addr not in nodes:
            continue

        interactions = [
            (f, t, v, ts, typ) for (f, t, v, ts, typ) in edges
            if (f == addr and t == bridge_addr)
            or (t == addr and f == bridge_addr)
        ]

        if interactions:
            # 检查桥对端是否有黑名单
            from config import BLACKLIST, KNOWN_MIXERS
            peers = set()
            for (f, t, v, ts, typ) in edges:
                if f == bridge_addr: peers.add(t)
                if t == bridge_addr: peers.add(f)
            bl_peers = [p for p in peers if p in BLACKLIST or p in KNOWN_MIXERS]

            hits.append({
                "bridge":    bridge_name,
                "address":   bridge_addr,
                "tx_count":  len(interactions),
                "bl_peers":  bl_peers[:3],
                "risky":     bool(bl_peers),
            })

    if not hits:
        return {"detected": False}

    has_risky = any(h["risky"] for h in hits)
    return {
        "detected": True,
        "severity": "HIGH" if has_risky else "MEDIUM",
        "hits":     hits,
        "summary":  f"使用透明桥 {len(hits)} 次"
                    + ("（对端含黑名单）" if has_risky else ""),
    }


def _detect_rapid_hop(nodes, edges, target_address):
    """
    D3 多链快速跳转
    检测：在 RAPID_HOP_WINDOW 内经过 >= 2 个不同桥
    """
    addr = (target_address or "").lower()
    ALL_BRIDGES = {**TRANSPARENT_BRIDGES, **OPAQUE_BRIDGES}

    # 找所有与桥的交互时间
    bridge_interactions = []
    for (f, t, v, ts, typ) in edges:
        if (f == addr or t == addr) and ts > 0:
            bridge = ALL_BRIDGES.get(t) or ALL_BRIDGES.get(f)
            if bridge:
                bridge_interactions.append((ts, bridge, t if f==addr else f))

    if len(bridge_interactions) < 2:
        return {"detected": False}

    bridge_interactions.sort(key=lambda x: x[0])

    # 滑动窗口：找 24 小时内经过 >= 2 个桥
    rapid_hops = []
    for i, (ts1, b1, a1) in enumerate(bridge_interactions):
        window = [(ts2, b2, a2) for ts2, b2, a2 in bridge_interactions[i:]
                  if ts2 - ts1 <= RAPID_HOP_WINDOW]
        bridges_in_window = set(b for _, b, _ in window)
        if len(bridges_in_window) >= 2:
            rapid_hops.append({
                "start_ts":    ts1,
                "bridges":     list(bridges_in_window),
                "bridge_count": len(bridges_in_window),
            })

    if not rapid_hops:
        return {"detected": False}

    max_bridges = max(h["bridge_count"] for h in rapid_hops)
    return {
        "detected":    True,
        "severity":    "HIGH" if max_bridges >= 3 else "MEDIUM",
        "hops":        rapid_hops[:3],
        "max_bridges": max_bridges,
        "summary":     f"24小时内经过 {max_bridges} 个跨链桥（多链快速跳转）",
    }


# ════════════════════════════════════════════════════════
# 跨链桥资金审计
# ════════════════════════════════════════════════════════

def audit_bridge_flow(address, nodes, edges):
    """
    审计资金进出跨链桥的差额
    不透明桥：存入 A → 取出 B，代币种类改变
    """
    addr      = address.lower()
    ALL       = {**TRANSPARENT_BRIDGES, **OPAQUE_BRIDGES}
    flows     = {}

    for (f, t, v, ts, typ) in edges:
        for bridge_addr, bridge_name in ALL.items():
            if f == addr and t == bridge_addr:
                flows.setdefault(bridge_addr, {
                    "name": bridge_name,
                    "type": "opaque" if bridge_addr in OPAQUE_BRIDGES else "transparent",
                    "sent": 0, "recv": 0,
                    "tokens_sent": [], "tokens_recv": [],
                })
                flows[bridge_addr]["sent"] += v
                flows[bridge_addr]["tokens_sent"].append(typ)

            if t == addr and f == bridge_addr:
                flows.setdefault(bridge_addr, {
                    "name": bridge_name,
                    "type": "opaque" if bridge_addr in OPAQUE_BRIDGES else "transparent",
                    "sent": 0, "recv": 0,
                    "tokens_sent": [], "tokens_recv": [],
                })
                flows[bridge_addr]["recv"] += v
                flows[bridge_addr]["tokens_recv"].append(typ)

    suspicious = []
    for ba, fl in flows.items():
        token_change = set(fl["tokens_sent"]) != set(fl["tokens_recv"])
        if fl["type"] == "opaque" or token_change:
            suspicious.append({
                "bridge":       fl["name"],
                "type":         fl["type"],
                "sent":         fl["sent"],
                "received":     fl["recv"],
                "token_change": token_change,
                "sent_tokens":  list(set(fl["tokens_sent"])),
                "recv_tokens":  list(set(fl["tokens_recv"])),
                "risk":         "HIGH" if fl["type"]=="opaque" else "MEDIUM",
            })

    return {
        "flows":      flows,
        "suspicious": suspicious,
        "summary":    f"跨链桥资金审计: {len(flows)} 个桥, {len(suspicious)} 个可疑",
    }
