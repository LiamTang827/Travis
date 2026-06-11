# ============================================================
# tracer.py
# 资金路径追踪引擎
# 双向 BFS：正向（出金追踪）+ 逆向（来源溯源）
# 不额外调 API，直接在已建好的 graph 上跑
# ============================================================

from collections import defaultdict, deque
from config import BLACKLIST, KNOWN_MIXERS, KNOWN_BRIDGES

# ── 已知终点类型 ────────────────────────────────────────────
KNOWN_CEX_ADDRS = {
    "0x28c6c06298d514db089934071355e5743bf21d60": "Binance",
    "0x21a31ee1afc51d94c2efee98d4c2d258c33d8b61": "Binance",
    "0xf977814e90da44bfa03b6295a0616a897441acec": "Binance",
    "0xbe0eb53f46cd790cd13851d5eff43d12404d33e8": "Binance",
    "0x0d0707963952f2fba59dd06f2b425ace40b492fe": "Gate.io",
    "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b": "OKX",
    "0x1b3cb81e51011b549d78bf720b0d924ac763a7c2": "Coinbase",
    "0x503828976d22510aad0201ac7ec88293211d23da": "Coinbase",
}

MAX_HOPS    = 8    # 最多追几跳
MAX_PATHS   = 50   # 最多返回几条路径
MAX_NODES   = 500  # 每方向最多展开几个节点


def _classify_node(addr: str) -> str:
    """给节点打类型标签"""
    if addr in BLACKLIST:        return "blacklist"
    if addr in KNOWN_MIXERS:     return "mixer"
    if addr in KNOWN_BRIDGES:    return "bridge"
    if addr in KNOWN_CEX_ADDRS:  return "cex"
    return "normal"


def _build_adjacency(edges: list) -> tuple[dict, dict]:
    """
    从 edge 列表建双向邻接表
    forward:  addr → [(to, value, timestamp, type)]
    backward: addr → [(from, value, timestamp, type)]
    """
    forward  = defaultdict(list)
    backward = defaultdict(list)
    for (f, t, v, ts, typ) in edges:
        forward[f].append((t, v, ts, typ))
        backward[t].append((f, v, ts, typ))
    return forward, backward


# ============================================================
# 正向追踪：资金去哪了
# ============================================================

def trace_forward(
    start: str,
    forward: dict,
    nodes: dict,
    max_hops: int = MAX_HOPS,
    max_nodes: int = MAX_NODES,
) -> dict:
    """
    从 start 出发，正向 BFS 追踪资金去向
    返回：路径树 + 关键终点
    """
    start = start.lower()
    visited  = {start: 0}   # addr → hop
    queue    = deque([(start, 0, [start])])
    paths    = []
    endpoints= []           # 有意义的终点（黑名单/mixer/cex）
    path_tree= {}           # addr → {hop, type, children, value_in}

    path_tree[start] = {
        "hop": 0, "type": _classify_node(start),
        "children": [], "value_out": 0,
    }

    total_expanded = 0

    while queue and total_expanded < max_nodes:
        addr, hop, path = queue.popleft()

        if hop >= max_hops:
            continue

        for (nxt, val, ts, typ) in forward.get(addr, []):
            nxt = nxt.lower()
            ntype = _classify_node(nxt)

            if nxt not in path_tree:
                path_tree[nxt] = {
                    "hop": hop + 1, "type": ntype,
                    "children": [], "value_in": val,
                    "via_type": typ,
                }
            else:
                path_tree[nxt]["value_in"] = path_tree[nxt].get("value_in", 0) + val

            if addr in path_tree:
                path_tree[addr]["value_out"] = path_tree[addr].get("value_out", 0) + val
                if nxt not in path_tree[addr]["children"]:
                    path_tree[addr]["children"].append(nxt)

            new_path = path + [nxt]

            # 关键节点 → 记录路径
            if ntype in ("blacklist", "mixer", "cex", "bridge"):
                label = (BLACKLIST.get(nxt) or KNOWN_MIXERS.get(nxt)
                         or KNOWN_BRIDGES.get(nxt) or KNOWN_CEX_ADDRS.get(nxt, ntype))
                endpoints.append({
                    "address":  nxt,
                    "type":     ntype,
                    "label":    label,
                    "hop":      hop + 1,
                    "path":     new_path,
                    "value":    val,
                    "via_type": typ,
                })
                if len(paths) < MAX_PATHS:
                    paths.append(new_path)

            if nxt not in visited or visited[nxt] > hop + 1:
                visited[nxt] = hop + 1
                if ntype == "normal":   # 非终点才继续展开
                    queue.append((nxt, hop + 1, new_path))
                    total_expanded += 1

    # 去重endpoints（同地址保留最短路径）
    seen = {}
    for ep in endpoints:
        a = ep["address"]
        if a not in seen or seen[a]["hop"] > ep["hop"]:
            seen[a] = ep
    endpoints = sorted(seen.values(), key=lambda x: x["hop"])

    return {
        "direction":  "forward",
        "start":      start,
        "path_tree":  path_tree,
        "endpoints":  endpoints,
        "total_nodes_expanded": total_expanded,
        "summary": _summarize_endpoints(endpoints, "forward"),
    }


# ============================================================
# 逆向溯源：资金从哪来
# ============================================================

def trace_backward(
    start: str,
    backward: dict,
    nodes: dict,
    max_hops: int = MAX_HOPS,
    max_nodes: int = MAX_NODES,
) -> dict:
    """
    从 start 出发，逆向 BFS 追溯资金来源
    """
    start = start.lower()
    visited  = {start: 0}
    queue    = deque([(start, 0, [start])])
    paths    = []
    sources  = []
    path_tree= {}

    path_tree[start] = {
        "hop": 0, "type": _classify_node(start),
        "parents": [], "value_out": 0,
    }

    total_expanded = 0

    while queue and total_expanded < max_nodes:
        addr, hop, path = queue.popleft()

        if hop >= max_hops:
            continue

        for (src, val, ts, typ) in backward.get(addr, []):
            src   = src.lower()
            stype = _classify_node(src)

            if src not in path_tree:
                path_tree[src] = {
                    "hop": hop + 1, "type": stype,
                    "parents": [], "value_out": val,
                    "via_type": typ,
                }
            else:
                path_tree[src]["value_out"] = path_tree[src].get("value_out", 0) + val

            if addr in path_tree:
                if src not in path_tree[addr].get("parents", []):
                    path_tree[addr].setdefault("parents", []).append(src)

            new_path = [src] + path

            if stype in ("blacklist", "mixer", "cex", "bridge"):
                label = (BLACKLIST.get(src) or KNOWN_MIXERS.get(src)
                         or KNOWN_BRIDGES.get(src) or KNOWN_CEX_ADDRS.get(src, stype))
                sources.append({
                    "address":  src,
                    "type":     stype,
                    "label":    label,
                    "hop":      hop + 1,
                    "path":     new_path,
                    "value":    val,
                    "via_type": typ,
                })
                if len(paths) < MAX_PATHS:
                    paths.append(new_path)

            if src not in visited or visited[src] > hop + 1:
                visited[src] = hop + 1
                if stype == "normal":
                    queue.append((src, hop + 1, new_path))
                    total_expanded += 1

    seen = {}
    for s in sources:
        a = s["address"]
        if a not in seen or seen[a]["hop"] > s["hop"]:
            seen[a] = s
    sources = sorted(seen.values(), key=lambda x: x["hop"])

    return {
        "direction":  "backward",
        "start":      start,
        "path_tree":  path_tree,
        "sources":    sources,
        "total_nodes_expanded": total_expanded,
        "summary": _summarize_endpoints(sources, "backward"),
    }


# ============================================================
# 完整双向追踪
# ============================================================

def trace_full(
    address: str,
    nodes: dict,
    edges: list,
    max_hops: int = MAX_HOPS,
) -> dict:
    """
    对一个地址做完整的双向资金追踪
    直接在已有 graph 数据上跑，不调 API
    """
    addr    = address.lower()
    forward, backward = _build_adjacency(edges)

    fwd = trace_forward(addr,  forward,  nodes, max_hops)
    bwd = trace_backward(addr, backward, nodes, max_hops)

    # 合并所有关键路径上的节点（用于 graph 高亮）
    highlight_nodes = set([addr])
    highlight_edges = set()

    for ep in fwd.get("endpoints", []):
        path = ep["path"]
        for n in path:
            highlight_nodes.add(n)
        for i in range(len(path) - 1):
            highlight_edges.add((path[i], path[i+1]))

    for src in bwd.get("sources", []):
        path = src["path"]
        for n in path:
            highlight_nodes.add(n)
        for i in range(len(path) - 1):
            highlight_edges.add((path[i], path[i+1]))

    # Peel chain 检测：正向路径中是否有连续单出度节点
    peel_paths = _detect_peel_in_trace(fwd["path_tree"], addr, forward)

    # 风险路径汇总
    risk_paths = []
    for ep in fwd.get("endpoints", []):
        if ep["type"] == "blacklist":
            risk_paths.append({
                "direction": "→ 流出至黑名单",
                "hops":      ep["hop"],
                "label":     ep["label"],
                "address":   ep["address"],
                "path":      ep["path"],
                "severity":  "CRITICAL",
            })
        elif ep["type"] == "mixer":
            risk_paths.append({
                "direction": "→ 流入混币器",
                "hops":      ep["hop"],
                "label":     ep["label"],
                "address":   ep["address"],
                "path":      ep["path"],
                "severity":  "HIGH",
            })
        elif ep["type"] == "cex":
            risk_paths.append({
                "direction": "→ 出金至交易所",
                "hops":      ep["hop"],
                "label":     ep["label"],
                "address":   ep["address"],
                "path":      ep["path"],
                "severity":  "MEDIUM",
            })

    for src in bwd.get("sources", []):
        if src["type"] == "blacklist":
            risk_paths.append({
                "direction": "← 来自黑名单",
                "hops":      src["hop"],
                "label":     src["label"],
                "address":   src["address"],
                "path":      src["path"],
                "severity":  "CRITICAL",
            })
        elif src["type"] == "mixer":
            risk_paths.append({
                "direction": "← 来自混币器",
                "hops":      src["hop"],
                "label":     src["label"],
                "address":   src["address"],
                "path":      src["path"],
                "severity":  "HIGH",
            })

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    risk_paths.sort(key=lambda x: sev_order.get(x["severity"], 3))

    return {
        "address":          addr,
        "forward":          fwd,
        "backward":         bwd,
        "highlight_nodes":  list(highlight_nodes),
        "highlight_edges":  [list(e) for e in highlight_edges],
        "risk_paths":       risk_paths,
        "peel_paths":       peel_paths,
        "stats": {
            "forward_endpoints":  len(fwd.get("endpoints", [])),
            "backward_sources":   len(bwd.get("sources",   [])),
            "highlight_nodes":    len(highlight_nodes),
            "highlight_edges":    len(highlight_edges),
            "critical_paths":     len([p for p in risk_paths if p["severity"] == "CRITICAL"]),
            "high_paths":         len([p for p in risk_paths if p["severity"] == "HIGH"]),
        },
        "summary": _build_full_summary(risk_paths, peel_paths),
    }


# ============================================================
# 批量追踪：对多个地址同时追踪
# ============================================================

def trace_batch(
    addresses: list,
    nodes: dict,
    edges: list,
    max_hops: int = 5,
) -> dict:
    """
    对一批地址做追踪（共用同一份 graph，效率高）
    """
    forward, backward = _build_adjacency(edges)
    results = {}

    for addr in addresses:
        addr = addr.lower()
        fwd  = trace_forward( addr, forward,  nodes, max_hops)
        bwd  = trace_backward(addr, backward, nodes, max_hops)

        highlight_nodes = set([addr])
        highlight_edges = set()
        for ep in fwd.get("endpoints", []) + bwd.get("sources", []):
            for n in ep["path"]:
                highlight_nodes.add(n)
            p = ep["path"]
            for i in range(len(p)-1):
                highlight_edges.add((p[i], p[i+1]))

        results[addr] = {
            "forward":         fwd,
            "backward":        bwd,
            "highlight_nodes": list(highlight_nodes),
            "highlight_edges": [list(e) for e in highlight_edges],
            "risk_paths":      _merge_risk_paths(fwd, bwd),
        }

    return results


# ============================================================
# 辅助函数
# ============================================================

def _detect_peel_in_trace(path_tree: dict, start: str, forward: dict) -> list:
    """在正向路径树中找 Peel Chain（连续单出度节点）"""
    chains = []
    visited = set()

    def follow_chain(addr, chain):
        if addr in visited:
            return
        visited.add(addr)
        children = path_tree.get(addr, {}).get("children", [])
        out_edges = forward.get(addr, [])
        if len(out_edges) == 1 and len(children) <= 1:
            chain.append(addr)
            if children:
                follow_chain(children[0], chain)
        else:
            if len(chain) >= 3:
                chains.append(list(chain))
            chain.clear()

    current = start
    chain   = []
    for _ in range(100):
        children = path_tree.get(current, {}).get("children", [])
        out_cnt  = len(forward.get(current, []))
        if out_cnt == 1 and len(children) <= 1:
            chain.append(current)
            if children:
                current = children[0]
            else:
                break
        else:
            if len(chain) >= 3:
                chains.append(list(chain))
            break

    return chains


def _summarize_endpoints(endpoints: list, direction: str) -> str:
    if not endpoints:
        return "未发现关键节点"
    bl  = [e for e in endpoints if e["type"] == "blacklist"]
    mx  = [e for e in endpoints if e["type"] == "mixer"]
    cex = [e for e in endpoints if e["type"] == "cex"]
    parts = []
    if bl:  parts.append(f"黑名单 {len(bl)} 个")
    if mx:  parts.append(f"Mixer {len(mx)} 个")
    if cex: parts.append(f"交易所 {len(cex)} 个")
    dir_str = "流向" if direction == "forward" else "来源"
    return f"{dir_str}: {' | '.join(parts)}" if parts else "未发现高风险节点"


def _merge_risk_paths(fwd: dict, bwd: dict) -> list:
    paths = []
    sev   = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    for ep in fwd.get("endpoints", []):
        t = ep["type"]
        if t in ("blacklist", "mixer", "cex"):
            paths.append({
                "direction": "→ " + {"blacklist":"黑名单","mixer":"混币器","cex":"交易所"}.get(t,t),
                "hops":      ep["hop"],
                "label":     ep["label"],
                "address":   ep["address"],
                "path":      ep["path"],
                "severity":  "CRITICAL" if t=="blacklist" else "HIGH" if t=="mixer" else "MEDIUM",
            })
    for src in bwd.get("sources", []):
        t = src["type"]
        if t in ("blacklist", "mixer"):
            paths.append({
                "direction": "← " + {"blacklist":"黑名单","mixer":"混币器"}.get(t,t),
                "hops":      src["hop"],
                "label":     src["label"],
                "address":   src["address"],
                "path":      src["path"],
                "severity":  "CRITICAL" if t=="blacklist" else "HIGH",
            })
    paths.sort(key=lambda x: sev.get(x["severity"], 3))
    return paths


def _build_full_summary(risk_paths: list, peel_paths: list) -> str:
    parts = []
    critical = [p for p in risk_paths if p["severity"] == "CRITICAL"]
    high     = [p for p in risk_paths if p["severity"] == "HIGH"]
    if critical: parts.append(f"🔴 {len(critical)} 条CRITICAL路径")
    if high:     parts.append(f"🟠 {len(high)} 条HIGH路径")
    if peel_paths: parts.append(f"⛓ Peel Chain {len(peel_paths)} 段")
    return " | ".join(parts) if parts else "未发现高风险资金路径"
