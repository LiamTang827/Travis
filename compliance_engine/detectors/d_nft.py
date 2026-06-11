
from collections import defaultdict

KNOWN_NFT_MARKETS = {
    "0x7be8076f4ea4a4ad08075c2508e481d6c946d12b": "OpenSea v1",
    "0x7f268357a8c2552623316e2562d90e642bb538e5": "OpenSea v2",
    "0x00000000006c3852cbef3e08e8df289169ede581": "OpenSea Seaport",
    "0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb": "CryptoPunks",
    "0x60cd862c9c687a9de49aecdc3a99b74a4fc54ab6": "LooksRare",
    "0x74312363e45dcaba76c59ec49a13aa114034c39b": "X2Y2",
}

def detect(nodes, edges, target_address=None, **kwargs):
    addr = (target_address or "").lower()
    nft_interactions = []

    for a in nodes:
        if a in KNOWN_NFT_MARKETS:
            txs = [(f,t,v,ts,typ) for (f,t,v,ts,typ) in edges
                   if (f == addr and t == a) or (t == addr and f == a)]
            if txs:
                nft_interactions.append({
                    "market":   KNOWN_NFT_MARKETS[a],
                    "address":  a,
                    "tx_count": len(txs),
                })

    if not nft_interactions:
        return {"detected": False}

    # Wash trading: buy and sell same NFT rapidly
    # Proxy: same address interacts with NFT market both ways
    wash_indicators = []
    for ni in nft_interactions:
        a = ni["address"]
        sent = sum(v for f,t,v,ts,typ in edges if f==addr and t==a)
        recv = sum(v for f,t,v,ts,typ in edges if t==addr and f==a)
        if sent > 0 and recv > 0:
            wash_indicators.append(ni["market"])

    severity = "HIGH" if wash_indicators else "MEDIUM"

    return {
        "detected":        True,
        "severity":        severity,
        "nft_markets":     nft_interactions,
        "wash_indicators": wash_indicators,
        "summary":         "检测到 NFT 洗钱相关行为" + (f"（疑似Wash Trading: {wash_indicators}）" if wash_indicators else ""),
    }
