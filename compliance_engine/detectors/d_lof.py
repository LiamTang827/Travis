
import math
from collections import defaultdict

def detect(nodes, edges, target_address=None, **kwargs):
    """
    Simplified LOF (Local Outlier Factor)
    使用交易频率、金额分布作为特征向量
    """
    addr = (target_address or "").lower()
    if addr not in nodes or len(nodes) < 10:
        return {"detected": False}

    # Feature vector: [in_count, out_count, in_value_log, out_value_log, token_count]
    def get_features(a):
        info = nodes[a]
        return [
            math.log1p(info["in_count"]),
            math.log1p(info["out_count"]),
            math.log1p(info["in_value"]),
            math.log1p(info["out_value"]),
            math.log1p(len(info.get("tokens", set()))),
        ]

    def distance(a, b):
        fa, fb = get_features(a), get_features(b)
        return math.sqrt(sum((x-y)**2 for x,y in zip(fa,fb)))

    node_list = list(nodes.keys())
    if len(node_list) > 200:
        node_list = node_list[:200]

    k = min(5, len(node_list)-1)

    # k-nearest neighbors for target
    dists = sorted([(distance(addr, b), b) for b in node_list if b != addr])[:k]
    if not dists:
        return {"detected": False}

    # Reachability distance and LOF
    k_dist = dists[-1][0] if dists else 0
    lrd_target = 1 / (sum(max(distance(addr,b), k_dist) for _,b in dists) / k + 1e-10)

    # LOF for target
    neighbor_lrds = []
    for _, nb in dists:
        nb_dists = sorted([distance(nb, c) for c in node_list if c != nb])[:k]
        nb_k_dist = nb_dists[-1] if nb_dists else 0
        reach_dists = [max(distance(nb, c), nb_k_dist)
                       for c in node_list if c != nb][:k]
        lrd_nb = 1 / (sum(reach_dists) / max(len(reach_dists), 1) + 1e-10)
        neighbor_lrds.append(lrd_nb)

    lof = (sum(neighbor_lrds) / (k * lrd_target + 1e-10)) if lrd_target > 0 else 1.0
    lof = round(min(lof, 10.0), 3)

    if lof < 1.5:
        return {"detected": False}

    return {
        "detected": True,
        "severity": "HIGH" if lof >= 3.0 else "MEDIUM",
        "lof_score": lof,
        "summary":   f"LOF 异常分: {lof}（>1.5为异常，>3.0为高度异常）",
    }
