
from config import DETECTOR_CONFIG

def detect(nodes, edges, **kwargs):
    cfg       = DETECTOR_CONFIG
    min_depth = cfg.get("peel_chain_min_depth", 5)
    hi_depth  = cfg.get("peel_chain_high_depth", 10)

    candidates = {
        addr for addr, info in nodes.items()
        if info["in_count"] == 1 and info["out_count"] == 1
    }
    next_map = {}
    for (f, t, v, ts, typ) in edges:
        if f in candidates:
            next_map[f] = t

    visited = set()
    chains  = []
    for start in candidates:
        if start in visited: continue
        chain = [start]
        cur   = start
        while (cur in next_map
               and next_map[cur] in candidates
               and next_map[cur] not in visited):
            cur = next_map[cur]
            chain.append(cur)
            visited.add(cur)
        if len(chain) >= min_depth:
            chains.append(chain)

    chains.sort(key=len, reverse=True)
    if not chains:
        return {"detected": False}

    longest = len(chains[0])
    return {
        "detected":       True,
        "severity":       "HIGH" if longest >= hi_depth else "MEDIUM",
        "chains":         [c[:8] for c in chains[:5]],
        "chain_count":    len(chains),
        "longest_length": longest,
        "summary":        f"检测到 {len(chains)} 条Peel Chain，最长 {longest} 跳",
    }
