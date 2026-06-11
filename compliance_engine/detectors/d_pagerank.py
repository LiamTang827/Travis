from collections import defaultdict

MAX_NODES_PR = 2000

def detect(nodes, edges, target_address=None, **kwargs):
    if not nodes or not edges:
        return {"detected": False}

    addr = (target_address or "").lower()
    if addr not in nodes:
        return {"detected": False}

    # Trim to top MAX_NODES by activity (in+out count), always keep target
    if len(nodes) > MAX_NODES_PR:
        sorted_nodes = sorted(
            nodes.items(),
            key=lambda x: x[1]["in_count"] + x[1]["out_count"],
            reverse=True
        )
        keep = {a for a, _ in sorted_nodes[:MAX_NODES_PR]}
        keep.add(addr)
        nodes = {a: info for a, info in nodes.items() if a in keep}
        edges = [(f,t,v,ts,typ) for (f,t,v,ts,typ) in edges
                 if f in keep and t in keep]

    # Build adjacency
    in_links   = defaultdict(list)
    out_degree = defaultdict(int)
    for (f, t, v, ts, typ) in edges:
        in_links[t].append(f)
        out_degree[f] += 1

    # Seed = target address only, score 1.0
    scores = {a: 0.0 for a in nodes}
    scores[addr] = 1.0

    damping = 0.85
    for _ in range(10):
        new_scores = {a: 0.0 for a in nodes}
        new_scores[addr] = 1.0  # keep target as permanent seed
        for node in nodes:
            if node == addr:
                continue
            incoming = sum(
                scores.get(src, 0) / max(out_degree[src], 1)
                for src in in_links[node]
            )
            new_scores[node] = (1 - damping) + damping * incoming
        scores = new_scores

    # Find nodes most connected to target
    threshold = 0.3
    connected = sorted(
        [(a, s) for a, s in scores.items() if s >= threshold and a != addr],
        key=lambda x: -x[1]
    )[:10]

    # Flag if any high-score nodes are risky
    from config import BLACKLIST, KNOWN_MIXERS
    risky_connected = [(a, s) for a, s in connected
                       if a in BLACKLIST or a in KNOWN_MIXERS
                       or nodes[a].get("is_blacklist")
                       or nodes[a].get("is_mixer")]

    if not connected:
        return {"detected": False}

    return {
        "detected":         True,
        "severity":         "HIGH" if risky_connected else "MEDIUM",
        "connected_nodes":  len(connected),
        "risky_connected":  len(risky_connected),
        "top_connected":    [(a[:16], round(s,4)) for a,s in connected[:5]],
        "summary":          f"PageRank: {len(connected)} 个高关联节点"
                            + (f"，其中 {len(risky_connected)} 个高风险" if risky_connected else ""),
    }
