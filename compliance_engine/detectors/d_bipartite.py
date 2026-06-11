
from collections import defaultdict

def detect(nodes, edges, **kwargs):
    by_first_seen = defaultdict(list)
    for addr, info in nodes.items():
        if info["first_seen"] > 0:
            by_first_seen[info["first_seen"]].append(addr)

    suspicious_groups = {
        ts: addrs for ts, addrs in by_first_seen.items()
        if len(addrs) >= 3
    }

    results = []
    for ts, group in suspicious_groups.items():
        group_set = set(group)
        internal = [(f,t) for f,t,*_ in edges if f in group_set and t in group_set]
        external = [(f,t) for f,t,*_ in edges if (f in group_set) != (t in group_set)]
        if len(internal) == 0 and len(external) >= 3:
            results.append({
                "timestamp":      ts,
                "group_size":     len(group_set),
                "external_edges": len(external),
            })

    if not results:
        return {"detected": False}

    return {
        "detected": True,
        "severity": "HIGH" if len(results) >= 5 else "MEDIUM",
        "patterns": results[:5],
        "count":    len(results),
        "summary":  f"检测到 {len(results)} 个二分图模式",
    }
