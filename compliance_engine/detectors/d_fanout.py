
from config import DETECTOR_CONFIG

def detect(nodes, edges, **kwargs):
    cfg          = DETECTOR_CONFIG
    min_in       = cfg.get("fanout_min_in",       5)
    min_out      = cfg.get("fanout_min_out",       5)
    max_lifetime = cfg.get("fanout_max_lifetime", 3600)

    hubs = []
    for addr, info in nodes.items():
        if info["in_count"] >= min_in and info["out_count"] >= min_out:
            lifetime = info["last_seen"] - info["first_seen"]
            if lifetime <= max_lifetime:
                hubs.append({
                    "address":  addr,
                    "in":       info["in_count"],
                    "out":      info["out_count"],
                    "lifetime": lifetime,
                    "labels":   info["labels"],
                })
    hubs.sort(key=lambda x: x["in"] + x["out"], reverse=True)

    if not hubs:
        return {"detected": False}

    return {
        "detected":  True,
        "severity":  "HIGH" if len(hubs) >= 3 else "MEDIUM",
        "hubs":      hubs[:5],
        "hub_count": len(hubs),
        "summary":   f"检测到 {len(hubs)} 个蜘蛛网中转节点",
    }
