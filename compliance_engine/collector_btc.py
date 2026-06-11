# ============================================================
# collector_btc.py
# BTC 链数据采集 — Blockstream API（免费，无需 API Key）
# ============================================================

import requests, time
from collections import defaultdict

BTC_BASE = "https://blockstream.info/api"
SESS     = requests.Session()
SESS.headers.update({"User-Agent": "LucidAML/1.0"})

# 已知 BTC 黑名单地址
BTC_BLACKLIST = {
    "1Lw6QLShKVbWQQB8FpMBDtHqNqEbdqEGE3": "Lazarus Group BTC",
    "1Kuf2Rd8mDyAViwBozGTNYnvWL8uDUMFMr": "Lazarus Group BTC 2",
    "1CdpoB3QNbKdnFJmg7mjcq1hWCcVHhKf3s": "Ronin Bridge BTC",
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh": "Lazarus BTC bech32",
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf": "Genesis Block (Safe)",
}

# 已知 BTC Mixer
BTC_MIXERS = {
    "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s": "Chipmixer",
    "1FKDjd6vRKKHiRRHjHR3YVPbNZQxrBc3HG": "Wasabi Wallet",
    "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9wnkny": "JoinMarket",
}


# ════════════════════════════════════════════════════════
# 核心请求
# ════════════════════════════════════════════════════════

def _get_btc(path, retry=3):
    url = f"{BTC_BASE}/{path}"
    for i in range(retry):
        try:
            r = SESS.get(url, timeout=20)
            if r.status_code == 200:
                return r.json()
            if r.status_code == 429:
                time.sleep(2 ** i)
                continue
        except Exception as e:
            time.sleep(1)
    return None


# ════════════════════════════════════════════════════════
# 地址数据采集
# ════════════════════════════════════════════════════════

def fetch_btc_address(address):
    """
    获取 BTC 地址基本信息
    返回：余额、交易数量、总收发金额
    """
    data = _get_btc(f"address/{address}")
    if not data:
        return {}
    return {
        "address":         address,
        "funded_txo_sum":  data.get("chain_stats", {}).get("funded_txo_sum", 0),
        "spent_txo_sum":   data.get("chain_stats", {}).get("spent_txo_sum", 0),
        "tx_count":        data.get("chain_stats", {}).get("tx_count", 0),
        "balance":         data.get("chain_stats", {}).get("funded_txo_sum", 0)
                           - data.get("chain_stats", {}).get("spent_txo_sum", 0),
    }


def fetch_btc_txs(address, limit=50):
    """
    获取 BTC 地址的交易列表
    Blockstream 每次最多返回 25 笔，自动翻页
    """
    txs     = []
    last_tx = None

    while len(txs) < limit:
        path = f"address/{address}/txs"
        if last_tx:
            path += f"/chain/{last_tx}"

        data = _get_btc(path)
        if not data:
            break

        txs.extend(data)
        if len(data) < 25:
            break
        last_tx = data[-1]["txid"]
        time.sleep(0.3)

    return txs[:limit]


def parse_btc_txs(address, raw_txs):
    """
    解析 BTC 原始交易，提取边关系
    返回 edges 列表：(from, to, value_sat, timestamp, "BTC")
    """
    edges = []
    addr  = address.lower()

    for tx in raw_txs:
        ts    = tx.get("status", {}).get("block_time", 0) or 0
        txid  = tx.get("txid", "")

        # 输入地址
        in_addrs = []
        for vin in tx.get("vin", []):
            prev = vin.get("prevout", {})
            a    = prev.get("scriptpubkey_address", "")
            if a:
                in_addrs.append(a.lower())

        # 输出地址
        for vout in tx.get("vout", []):
            out_addr = vout.get("scriptpubkey_address", "")
            val      = vout.get("value", 0)  # satoshi
            if not out_addr:
                continue
            out_addr = out_addr.lower()

            # 对每个输入 → 这个输出建一条边
            for in_a in in_addrs:
                if in_a != out_addr:
                    edges.append((in_a, out_addr, val, ts, "BTC"))

    return edges


def fetch_btc_all(address, verbose=True):
    """
    采集 BTC 地址完整数据
    返回 (info, edges)
    """
    if verbose:
        print(f"    [BTC] 采集地址 {address[:20]}...")

    info = fetch_btc_address(address)
    if verbose:
        print(f"      → 交易数: {info.get('tx_count', 0)}")

    raw_txs = fetch_btc_txs(address, limit=100)
    if verbose:
        print(f"      → 拉取 {len(raw_txs)} 笔交易")

    edges = parse_btc_txs(address, raw_txs)
    return info, edges


# ════════════════════════════════════════════════════════
# BTC 图分析
# ════════════════════════════════════════════════════════

def build_btc_graph(address, edges):
    """
    建立 BTC 地址图
    返回 (nodes, edges) 格式与 ETH graph.py 一致
    """
    nodes = {}

    def upsert(addr, val, direction):
        if addr not in nodes:
            nodes[addr] = {
                "first_seen":   0,
                "last_seen":    0,
                "in_count":     0,
                "out_count":    0,
                "in_value":     0,
                "out_value":    0,
                "tokens":       set(),
                "is_blacklist": addr in BTC_BLACKLIST,
                "is_mixer":     addr in BTC_MIXERS,
                "is_gambling":  False,
                "is_bridge":    False,
                "labels":       _get_btc_labels(addr),
                "chain":        "BTC",
            }
        if direction == "in":
            nodes[addr]["in_count"]  += 1
            nodes[addr]["in_value"]  += val
        else:
            nodes[addr]["out_count"] += 1
            nodes[addr]["out_value"] += val

    for (f, t, v, ts, typ) in edges:
        upsert(f, v, "out")
        upsert(t, v, "in")

    return nodes, edges


def _get_btc_labels(addr):
    labels = []
    if addr in BTC_BLACKLIST:
        labels.append(BTC_BLACKLIST[addr])
    if addr in BTC_MIXERS:
        labels.append(f"BTC Mixer: {BTC_MIXERS[addr]}")
    return labels


# ════════════════════════════════════════════════════════
# BTC 黑名单检测
# ════════════════════════════════════════════════════════

def detect_btc_blacklist(address, nodes, edges):
    """检测 BTC 地址与已知黑名单的关联"""
    hits = []

    for addr, info in nodes.items():
        if addr in BTC_BLACKLIST:
            hits.append({
                "address":  addr,
                "type":     "BTC_BLACKLIST",
                "label":    BTC_BLACKLIST[addr],
                "severity": "CRITICAL",
            })
        elif addr in BTC_MIXERS:
            hits.append({
                "address":  addr,
                "type":     "BTC_MIXER",
                "label":    BTC_MIXERS[addr],
                "severity": "HIGH",
            })

    if not hits:
        return {"detected": False}

    return {
        "detected": True,
        "severity": "CRITICAL" if any(h["severity"]=="CRITICAL" for h in hits) else "HIGH",
        "hits":     hits,
        "summary":  f"BTC链命中 {len(hits)} 个已知风险地址",
    }


# ════════════════════════════════════════════════════════
# BTC Peel Chain 检测
# ════════════════════════════════════════════════════════

def detect_btc_peel_chain(nodes, edges, min_depth=5):
    """
    BTC 特有的 Peel Chain 检测
    特征更明显：UTXO 模型下每笔交易的找零地址形成连续链
    """
    # 出度=1的地址
    out_degree = defaultdict(int)
    in_degree  = defaultdict(int)
    next_map   = {}

    for (f, t, v, ts, typ) in edges:
        out_degree[f] += 1
        in_degree[t]  += 1
        next_map[f]    = t

    candidates = {a for a in nodes if out_degree[a]==1 and in_degree[a]<=1}

    visited = set()
    chains  = []

    for start in candidates:
        if start in visited:
            continue
        chain = [start]
        cur   = start
        while cur in next_map and next_map[cur] in candidates and next_map[cur] not in visited:
            cur = next_map[cur]
            chain.append(cur)
            visited.add(cur)
        if len(chain) >= min_depth:
            chains.append(chain)

    if not chains:
        return {"detected": False}

    chains.sort(key=len, reverse=True)
    return {
        "detected":       True,
        "severity":       "HIGH" if len(chains[0]) >= 10 else "MEDIUM",
        "chain_count":    len(chains),
        "longest_length": len(chains[0]),
        "summary":        f"BTC Peel Chain: {len(chains)} 条，最长 {len(chains[0])} 跳",
    }


# ════════════════════════════════════════════════════════
# 跨链关联（BTC ↔ ETH）
# ════════════════════════════════════════════════════════

def find_crosschain_link(btc_address, eth_address=None):
    """
    尝试发现 BTC 和 ETH 之间的跨链关联
    通过已知的跨链桥地址（RenBridge、tBTC等）
    """
    RENBRIDGE_BTC = [
        "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h",  # RenBridge BTC gateway
    ]

    txs = fetch_btc_txs(btc_address, limit=50)

    crosschain_hints = []
    for tx in txs:
        for vout in tx.get("vout", []):
            addr = vout.get("scriptpubkey_address", "")
            if addr in RENBRIDGE_BTC:
                crosschain_hints.append({
                    "txid":    tx.get("txid"),
                    "bridge":  "RenBridge",
                    "value":   vout.get("value", 0),
                    "ts":      tx.get("status", {}).get("block_time", 0),
                })

    return crosschain_hints
