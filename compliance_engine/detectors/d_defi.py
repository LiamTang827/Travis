
from config import DETECTOR_CONFIG
from collections import defaultdict

# Known DEX/DeFi contract addresses
KNOWN_DEX = {
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router",
    "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch Router",
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange",
}

KNOWN_LP = {
    "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f": "Uniswap V2 Factory",
    "0x1f98431c8ad98523631ae4a59f267346ea31f984": "Uniswap V3 Factory",
}

def detect(nodes, edges, target_address=None, eth_txs=None, **kwargs):
    cfg      = DETECTOR_CONFIG
    addr     = (target_address or "").lower()
    findings = []

    # E1: DEX multi-swap
    dex_hits = [a for a in nodes if a in KNOWN_DEX]
    if len(dex_hits) >= 2:
        # Count unique tokens swapped in 1 hour windows
        token_txs_by_hour = defaultdict(set)
        for (f, t, v, ts, typ) in edges:
            if (f == addr or t == addr) and typ not in ("ETH", "INT") and ts > 0:
                hour = ts // 3600
                token_txs_by_hour[hour].add(typ)
        max_tokens = max((len(v) for v in token_txs_by_hour.values()), default=0)
        if max_tokens >= cfg.get("token_swap_min_tokens", 4):
            findings.append("dex_swap")

    # E2: Rapid LP (add/remove within short window)
    lp_interactions = [(ts, f==addr) for f,t,v,ts,typ in edges
                       if t in KNOWN_LP or f in KNOWN_LP]
    if len(lp_interactions) >= 2:
        lp_interactions.sort()
        for i in range(len(lp_interactions)-1):
            if lp_interactions[i+1][0] - lp_interactions[i][0] < cfg.get("rapid_lp_max_hold", 1800):
                findings.append("rapid_lp")
                break

    # E3: Flash loan detection (same block in/out large amounts)
    block_flows = defaultdict(lambda: {"in": 0, "out": 0})
    for tx in (eth_txs or []):
        blk = tx.get("blockNumber", 0)
        val = int(tx.get("value", 0) or 0)
        if tx.get("to","").lower() == addr and val > 0:
            block_flows[blk]["in"] += val
        elif tx.get("from","").lower() == addr and val > 0:
            block_flows[blk]["out"] += val
    for blk, flow in block_flows.items():
        if flow["in"] > 1e18 and flow["out"] > 1e18 and abs(flow["in"]-flow["out"]) < flow["in"]*0.01:
            findings.append("flash_loan")
            break

    # E4: Yield farming (repeated LP interactions over time)
    if len(lp_interactions) >= 5:
        findings.append("yield_farm")

    if not findings:
        return {"detected": False}

    return {
        "detected": True,
        "severity": "MEDIUM",
        "findings": findings,
        "summary":  f"DeFi 滥用：{', '.join(findings)}",
    }
