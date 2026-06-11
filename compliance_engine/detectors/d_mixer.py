
from config import KNOWN_MIXERS

def detect(nodes, edges, target_address=None, **kwargs):
    addr  = (target_address or "").lower()
    hits  = []

    for a in nodes:
        if a in KNOWN_MIXERS:
            # Find interactions with target
            interactions = [
                (f,t,v,ts,typ) for (f,t,v,ts,typ) in edges
                if (f == addr and t == a) or (t == addr and f == a)
            ]
            if interactions:
                sent = sum(v for f,t,v,ts,typ in interactions if f == addr)
                recv = sum(v for f,t,v,ts,typ in interactions if t == addr)
                hits.append({
                    "address":  a,
                    "label":    KNOWN_MIXERS[a],
                    "sent":     sent,
                    "received": recv,
                    "tx_count": len(interactions),
                })

    if not hits:
        return {"detected": False}

    return {
        "detected": True,
        "severity": "HIGH",
        "results":  {"mixer_interactions": {"count": len(hits), "hits": hits}},
        "summary":  f"与 {len(hits)} 个混币器交互",
    }
