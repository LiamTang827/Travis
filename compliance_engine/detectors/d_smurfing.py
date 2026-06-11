
from collections import Counter, defaultdict
from config import DETECTOR_CONFIG

def detect(nodes, edges, target_address=None, **kwargs):
    cfg        = DETECTOR_CONFIG
    min_repeat = cfg.get("smurfing_min_repeat", 5)
    tolerance  = cfg.get("smurfing_regularity_tolerance", 0.3)
    addr       = (target_address or "").lower()

    # 找目标地址的出账，按金额分组
    out_edges = [(v, ts) for (f, t, v, ts, typ) in edges if f == addr and v > 0]
    if len(out_edges) < min_repeat:
        return {"detected": False}

    value_counter = Counter(v for v, ts in out_edges)
    repeated = {v: cnt for v, cnt in value_counter.items() if cnt >= min_repeat}

    if not repeated:
        return {"detected": False}

    # 检查时间规律性
    patterns = []
    for val, cnt in sorted(repeated.items(), key=lambda x: -x[1])[:10]:
        timestamps = sorted(ts for v, ts in out_edges if v == val and ts > 0)
        regularity = False
        if len(timestamps) >= 3:
            intervals = [timestamps[i+1]-timestamps[i] for i in range(len(timestamps)-1)]
            if intervals:
                avg = sum(intervals) / len(intervals)
                if avg > 0:
                    variance = sum(abs(x-avg)/avg for x in intervals) / len(intervals)
                    regularity = variance < tolerance
        patterns.append({
            "value":      val,
            "count":      cnt,
            "regular":    regularity,
        })

    max_cnt = max(p["count"] for p in patterns)
    severity = "HIGH" if any(p["regular"] for p in patterns) else "MEDIUM"

    return {
        "detected":     True,
        "severity":     severity,
        "patterns":     patterns[:5],
        "pattern_count":len(patterns),
        "summary":      f"检测到 {len(patterns)} 个拆单模式，最高频次 {max_cnt} 次",
    }
