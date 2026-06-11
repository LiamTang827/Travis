
from config import BLACKLIST, KNOWN_MIXERS

def detect(nodes, edges, target_address=None, **kwargs):
    addr = (target_address or "").lower()

    active_bl  = []  # addr → blacklist (sent to)
    passive_bl = []  # blacklist → addr (received from)

    for (f, t, v, ts, typ) in edges:
        if f == addr and (t in BLACKLIST or t in KNOWN_MIXERS):
            label = BLACKLIST.get(t) or KNOWN_MIXERS.get(t, "Known Risk")
            active_bl.append({"address": t, "label": label, "value": v})
        if t == addr and (f in BLACKLIST or f in KNOWN_MIXERS):
            label = BLACKLIST.get(f) or KNOWN_MIXERS.get(f, "Known Risk")
            passive_bl.append({"address": f, "label": label, "value": v})

    if not active_bl and not passive_bl:
        return {"detected": False}

    severity = "HIGH" if active_bl else "MEDIUM"

    return {
        "detected":      True,
        "severity":      severity,
        "active_count":  len(active_bl),
        "passive_count": len(passive_bl),
        "active":        active_bl[:5],
        "passive":       passive_bl[:5],
        "summary":       f"主动交互黑名单 {len(active_bl)} 次 | 被动收款自黑名单 {len(passive_bl)} 次",
    }
