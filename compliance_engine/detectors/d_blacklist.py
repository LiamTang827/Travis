
from config import BLACKLIST, KNOWN_MIXERS

def detect(nodes, edges, target_address=None, **kwargs):
    addr  = (target_address or "").lower()
    hits  = []
    mixer_hits = []

    for a, info in nodes.items():
        if info.get("is_blacklist") or a in BLACKLIST:
            label = BLACKLIST.get(a, "Known Blacklist")
            hop   = 0 if a == addr else 1
            hits.append({"address": a, "label": label, "hop": hop})
        if info.get("is_mixer") or a in KNOWN_MIXERS:
            label = KNOWN_MIXERS.get(a, "Known Mixer")
            mixer_hits.append({"address": a, "label": label})

    if not hits and not mixer_hits:
        return {"detected": False}

    severity = "CRITICAL" if hits else "HIGH"
    return {
        "detected":    True,
        "severity":    severity,
        "hits":        hits,
        "mixer_hits":  mixer_hits,
        "summary":     f"命中 {len(hits)} 个已知风险地址" + (f"，{len(mixer_hits)} 个Mixer" if mixer_hits else ""),
    }
