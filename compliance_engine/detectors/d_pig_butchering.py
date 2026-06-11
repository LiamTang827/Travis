
from collections import defaultdict

def detect(nodes, edges, target_address=None, **kwargs):
    addr = (target_address or "").lower()

    # Pig butchering pattern: 3 phases
    # Phase 1: small incoming (bait) → Phase 2: increasing outflows → Phase 3: large final drain
    out_edges = sorted(
        [(t, v, ts) for (f,t,v,ts,typ) in edges if f == addr and v > 0],
        key=lambda x: x[2]
    )
    in_edges = sorted(
        [(f, v, ts) for (f,t,v,ts,typ) in edges if t == addr and v > 0],
        key=lambda x: x[2]
    )

    if len(out_edges) < 3 or len(in_edges) < 1:
        return {"detected": False}

    # Check for increasing out pattern
    out_vals = [v for t,v,ts in out_edges]
    increasing_count = sum(1 for i in range(1, len(out_vals)) if out_vals[i] > out_vals[i-1])
    increasing_ratio = increasing_count / max(len(out_vals)-1, 1)

    # Large drain at end (last outflow > 3x average)
    avg_out = sum(out_vals) / len(out_vals)
    final_drain = out_vals[-1] > avg_out * 3 if out_vals else False

    # Identify final drain destination
    final_dest = out_edges[-1][0] if out_edges else ""

    if increasing_ratio < 0.5 and not final_drain:
        return {"detected": False}

    return {
        "detected":        True,
        "severity":        "MEDIUM",
        "increasing_ratio": round(increasing_ratio, 2),
        "final_drain":     final_drain,
        "final_dest":      final_dest[:20] + "..." if final_dest else "",
        "out_count":       len(out_edges),
        "summary":         f"猪杀盘疑似三段式：诱饵 {len(in_edges)} → 递增出账 → 归集至 {final_dest[:12] if final_dest else 'unknown'}...",
    }
