
from config import DETECTOR_CONFIG, BLACKLIST, KNOWN_MIXERS

def detect(nodes, edges, target_address=None, **kwargs):
    cfg      = DETECTOR_CONFIG
    addr     = (target_address or "").lower()
    max_val  = int(cfg.get("dusting_max_value_eth", 0.001) * 1e18)
    min_cnt  = cfg.get("dusting_min_count", 10)

    # Dust = tiny incoming transactions
    dust_txs = [
        (f, v, ts) for (f,t,v,ts,typ) in edges
        if t == addr and 0 < v <= max_val and typ == "ETH"
    ]

    if len(dust_txs) < min_cnt:
        # Also check if target received dust FROM blacklist
        bl_dust = [(f,v,ts) for f,v,ts in dust_txs if f in BLACKLIST or f in KNOWN_MIXERS]
        if not bl_dust:
            return {"detected": False}
        return {
            "detected": True,
            "severity": "HIGH",
            "dust_count": len(bl_dust),
            "sources":   [f for f,v,ts in bl_dust[:5]],
            "summary":   f"检测到 {len(bl_dust)} 个尘埃攻击来源，已发生归并操作（高风险）",
        }

    # Check if dust sources are blacklisted
    bl_sources = [(f,v,ts) for f,v,ts in dust_txs if f in BLACKLIST or f in KNOWN_MIXERS]
    severity   = "HIGH" if bl_sources else "MEDIUM"

    return {
        "detected":   True,
        "severity":   severity,
        "dust_count": len(dust_txs),
        "bl_sources": len(bl_sources),
        "sources":    list(set(f for f,v,ts in dust_txs[:20])),
        "summary":    f"检测到 {len(dust_txs)} 笔尘埃交易" + (f"，{len(bl_sources)} 个来自黑名单" if bl_sources else ""),
    }
