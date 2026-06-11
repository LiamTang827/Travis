# ============================================================
# collector_tron.py
# TRON 地址数据采集 — TronGrid API
# ============================================================

import sys, os, json, time, requests
from datetime import datetime
from collections import defaultdict

TRONGRID_KEY = "1fdb965c-fb63-4b31-ad76-c75e59c5bfa4"
BASE_URL     = "https://api.trongrid.io"

HEADERS = {
    "accept":       "application/json",
    "TRON-PRO-API-KEY": TRONGRID_KEY,
}

# ── 已知风险地址 (TRON Base58 格式, T 开头) ─────────────────
TRON_BLACKLIST = {
    # OFAC 制裁 / Lazarus Group
    "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7": "Lazarus Group (TRON)",
    "TMVQHEFMZQhZtRGBe1DJHJeZNBd8HUMZtp": "Lazarus Group (Bybit 2025)",
    "TDTtQSCHFgGwKRxh3GKWZ6YCvvezNLcRSv": "OFAC Sanctioned",
    "TFbTSFvhRmJWwA7HhHMWNAGXFiSdaBbPkH": "OFAC Sanctioned",
    "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": "USDT Contract (Tron)",  # 不是黑名单，但要标注
    # Mixer / 高风险
    "TKHuVq1oKVruCGLvqVexFs6dawKv6fQgFs": "Known TRON Mixer",
    "TGkxzkDKyMeq2T7edKnyjZoFypyzjkkssq": "TRON Gambling/Mixer",
}

TRON_KNOWN_DEX = {
    "TKzxdSv2FZKQrEqkKVgp5DcwEXBEKMg2Ax": "SunSwap V2",
    "TFVisXFaijZfeyeSjCEVkHfex7HGdTxzF9": "SunSwap V1",
    "TXF1xDbVGdxFGbovmmmXvBGu8ZiE3Lq4mR": "JustSwap",
    "TNSBA6KvSesLuLeu6S4rW2S47Mf3At7Hg8": "SunCurve",
    "TGjYzgCyPobsNS9n6WcbdLVR9dH7mWqFx7": "Sun.io",
}

TRON_KNOWN_CEX = {
    "TJDENsfBJs4RFETt1X1W8wMDc8M5XnJhCe": "Binance TRON",
    "TAzsQ9Gx8eqFNFSKbeXrbi45CuVPHzA8wr": "Binance USDT Hot",
    "TKVEHg5hFHEFV9eQqNBBNULnMNaX4TLPWK": "OKX TRON",
    "TWd4WrZ9wn84f5x1hZhL4DHvk738ns5jwb": "Huobi TRON",
    "TYASr5UV6HEcXatwdFQfmLVUqQQQMUxHLS": "Kraken TRON",
}

TRON_KNOWN_BRIDGES = {
    "TBpTbK9KQzagrN7eMKFr5QM2pgZf6FN7KA": "BitTorrent Bridge",
    "TKczxoNuPKg3qHE4tWGzt6SqDqeJfvwhMj": "Multichain TRON",
}


# ── HTTP helper ──────────────────────────────────────────────

def _get(path, params=None, retries=3):
    url = BASE_URL + path
    for i in range(retries):
        try:
            r = requests.get(url, params=params, headers=HEADERS, timeout=20)
            if r.status_code == 200:
                return r.json()
            if r.status_code == 429:
                time.sleep(2 ** i)
            else:
                time.sleep(0.5)
        except Exception:
            time.sleep(1)
    return {}


# ── 采集函数 ─────────────────────────────────────────────────

def fetch_tron_account(address):
    """拉账户基本信息：余额、带宽、能量"""
    data = _get(f"/v1/accounts/{address}")
    accs = data.get("data", [])
    if not accs:
        return {}
    acc = accs[0]
    return {
        "balance_trx":  acc.get("balance", 0) / 1e6,
        "bandwidth":    acc.get("free_net_usage", 0),
        "create_time":  acc.get("create_time", 0),
    }


def fetch_tron_txs(address, limit=200):
    """拉 TRX 普通交易"""
    print(f"    [TronGrid] 拉取 TRX 交易...")
    data = _get(f"/v1/accounts/{address}/transactions", {
        "limit": min(limit, 200),
        "only_confirmed": "true",
    })
    txs = data.get("data", [])
    print(f"      → {len(txs)} 笔")
    return txs


def fetch_tron_trc20(address, limit=200):
    """拉 TRC20 Token 转账（USDT/USDC等）"""
    print(f"    [TronGrid] 拉取 TRC20 转账...")
    data = _get(f"/v1/accounts/{address}/transactions/trc20", {
        "limit": min(limit, 200),
        "only_confirmed": "true",
    })
    txs = data.get("data", [])
    print(f"      → {len(txs)} 笔")
    return txs


def fetch_tron_balance_trc20(address):
    """拉 TRC20 余额列表"""
    data = _get(f"/v1/accounts/{address}")
    accs = data.get("data", [])
    if not accs:
        return []
    trc20_list = accs[0].get("trc20", [])
    result = []
    for item in trc20_list:
        for contract, balance in item.items():
            sym = TRC20_SYMBOL_MAP.get(contract, contract[:8])
            result.append({
                "contract": contract,
                "symbol":   sym,
                "balance":  int(balance),
            })
    return result


# ── TRC20 合约地址 → Symbol ──────────────────────────────────
TRC20_SYMBOL_MAP = {
    "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": "USDT",
    "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8": "USDC",
    "TCFLL5dx5ZJdKnWuesXxi1VPwjLVmWZkZa": "JST",
    "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7": "SUN",
    "TKfjV9RNKJJCqPvBtK8L7Knykh7DNWvnYt": "BTT",
    "TXpw32r12C6Wq6Ef4i2N2BPJStHHm59Cok": "WBTC",
    "TF17EPFW7QFZBEP3FHKBHVTJ2TXCEBFHSZ": "WETH",
    "TAFjULxiVgT4qWk6UZwjqwZXTSaGaqnVp4": "BTC (TRC20)",
    "TN3W4H6rK2ce4vX9YnFQHwKENnHjoxb3m9": "TUSD",
}


# ── 建图 ────────────────────────────────────────────────────

def build_tron_graph(address, trx_txs, trc20_txs):
    """
    从 TRX 和 TRC20 交易建图
    节点/边格式和 ETH graph 兼容
    """
    addr  = address.lower()
    nodes = {}
    edges = []

    def upsert(a, ts):
        a = a.lower()
        if not a:
            return None
        if a not in nodes:
            nodes[a] = {
                "first_seen":   ts,
                "last_seen":    ts,
                "in_count":     0,
                "out_count":    0,
                "in_value":     0,
                "out_value":    0,
                "tokens":       set(),
                "is_blacklist": a in {k.lower() for k in TRON_BLACKLIST},
                "is_mixer":     False,
                "is_gambling":  False,
                "is_bridge":    a in {k.lower() for k in TRON_KNOWN_BRIDGES},
                "is_dex":       a in {k.lower() for k in TRON_KNOWN_DEX},
                "is_cex":       a in {k.lower() for k in TRON_KNOWN_CEX},
                "labels":       _get_tron_labels(a),
            }
        else:
            nodes[a]["first_seen"] = min(nodes[a]["first_seen"], ts)
            nodes[a]["last_seen"]  = max(nodes[a]["last_seen"],  ts)
        return a

    def add_edge(f, t, val, ts, sym):
        f = upsert(f, ts)
        t = upsert(t, ts)
        if not f or not t:
            return
        nodes[f]["out_count"] += 1
        nodes[f]["out_value"] += val
        nodes[t]["in_count"]  += 1
        nodes[t]["in_value"]  += val
        if sym not in ("TRX",):
            nodes[f]["tokens"].add(sym)
            nodes[t]["tokens"].add(sym)
        edges.append((f, t, val, ts, sym))

    # ── TRX 普通交易 ─────────────────────────────────────────
    for tx in trx_txs:
        raw = tx.get("raw_data", {})
        ts  = raw.get("timestamp", 0) // 1000  # ms → s
        contracts = raw.get("contract", [])
        for contract in contracts:
            ctype = contract.get("type", "")
            val   = contract.get("parameter", {}).get("value", {})

            if ctype == "TransferContract":
                frm = val.get("owner_address", "")
                to  = val.get("to_address", "")
                amt = int(val.get("amount", 0))
                # TRON 地址是 hex，需要转 Base58（简化：直接用hex）
                add_edge(frm, to, amt, ts, "TRX")

    # ── TRC20 Token 转账 ─────────────────────────────────────
    for tx in trc20_txs:
        ts  = int(tx.get("block_timestamp", 0)) // 1000
        frm = tx.get("from", "")
        to  = tx.get("to", "")
        val = int(tx.get("value", 0))
        sym = tx.get("token_info", {}).get("symbol", "TRC20")
        add_edge(frm, to, val, ts, sym)

    return nodes, edges


def _get_tron_labels(addr):
    labels = []
    for k, v in TRON_BLACKLIST.items():
        if k.lower() == addr:
            labels.append(v)
    for k, v in TRON_KNOWN_DEX.items():
        if k.lower() == addr:
            labels.append(f"DEX: {v}")
    for k, v in TRON_KNOWN_CEX.items():
        if k.lower() == addr:
            labels.append(f"CEX: {v}")
    for k, v in TRON_KNOWN_BRIDGES.items():
        if k.lower() == addr:
            labels.append(f"Bridge: {v}")
    return labels


# ── 风险检测 ─────────────────────────────────────────────────

def detect_tron_blacklist(address, nodes, edges):
    addr = address.lower()
    hits = []
    for a, info in nodes.items():
        if info.get("is_blacklist"):
            label = next((v for k, v in TRON_BLACKLIST.items() if k.lower() == a), "Blacklist")
            hits.append({"address": a, "label": label, "hop": 0 if a == addr else 1})
    if not hits:
        return {"detected": False}
    return {
        "detected": True,
        "severity": "CRITICAL",
        "hits":     hits,
        "summary":  f"TRON: 命中 {len(hits)} 个已知风险地址",
    }


def detect_tron_usdt_freeze(address):
    """检查地址是否被 Tether 在 TRON 链上冻结"""
    # 直接查 USDT 合约的冻结状态
    # TronGrid 没有直接的冻结查询，用 config 里的 USDT_TRON_BLACKLIST
    try:
        from config import USDT_TRON_BLACKLIST
        addr = address.lower()
        if addr in {k.lower() for k in USDT_TRON_BLACKLIST}:
            label = next((v for k, v in USDT_TRON_BLACKLIST.items() if k.lower() == addr), "USDT Frozen")
            return {
                "detected": True,
                "severity": "CRITICAL",
                "label":    label,
                "summary":  f"地址被 Tether 在 TRON 链冻结: {label}",
            }
    except ImportError:
        pass
    return {"detected": False}


def detect_tron_peel_chain(nodes, edges):
    candidates = {
        addr for addr, info in nodes.items()
        if info["in_count"] == 1 and info["out_count"] == 1
    }
    next_map = {}
    for (f, t, v, ts, typ) in edges:
        if f in candidates:
            next_map[f] = t

    visited, chains = set(), []
    for start in candidates:
        if start in visited:
            continue
        chain, cur = [start], start
        while cur in next_map and next_map[cur] in candidates and next_map[cur] not in visited:
            cur = next_map[cur]
            chain.append(cur)
            visited.add(cur)
        if len(chain) >= 4:
            chains.append(chain)

    if not chains:
        return {"detected": False}
    chains.sort(key=len, reverse=True)
    return {
        "detected":       True,
        "severity":       "HIGH" if len(chains[0]) >= 8 else "MEDIUM",
        "chains":         [c[:6] for c in chains[:3]],
        "chain_count":    len(chains),
        "longest_length": len(chains[0]),
        "summary":        f"TRON Peel Chain: {len(chains)} 条，最长 {len(chains[0])} 跳",
    }


# ── 主入口 ────────────────────────────────────────────────────

def analyze_tron_address(address, limit=200, save_json=True, output_dir=None):
    print(f"\n{'='*55}")
    print(f" TRON 地址分析 — TronGrid")
    print(f"{'='*55}")
    print(f" 地址: {address}\n")

    # 账户信息
    account = fetch_tron_account(address)
    print(f"    TRX 余额: {account.get('balance_trx', 0):.4f} TRX")

    # 交易
    trx_txs   = fetch_tron_txs(address, limit=limit)
    trc20_txs = fetch_tron_trc20(address, limit=limit)

    if not trx_txs and not trc20_txs:
        print("    ⚠️  未拉到交易数据")
        return None

    # TRC20 余额
    trc20_balance = fetch_tron_balance_trc20(address)
    if trc20_balance:
        for b in trc20_balance[:3]:
            dec = 6 if b["symbol"] in ("USDT", "USDC") else 18
            print(f"    {b['symbol']}: {b['balance'] / (10**dec):.4f}")

    # 建图
    nodes, edges = build_tron_graph(address, trx_txs, trc20_txs)
    print(f"    节点: {len(nodes)}  边: {len(edges)}")

    # 检测
    bl_result    = detect_tron_blacklist(address, nodes, edges)
    freeze_res   = detect_tron_usdt_freeze(address)
    peel_result  = detect_tron_peel_chain(nodes, edges)

    # 评分
    risk_score = 0
    if bl_result.get("detected"):   risk_score += 100
    if freeze_res.get("detected"):  risk_score += 100
    if peel_result.get("detected"): risk_score += 30
    risk_score = min(100, risk_score)
    level = ("CRITICAL" if risk_score >= 100 else
             "HIGH"     if risk_score >= 60  else
             "MEDIUM"   if risk_score >= 30  else "LOW")

    BADGE = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    print(f"\n {'='*50}")
    print(f"  TRON 风险报告")
    print(f"  地址:     {address}")
    print(f"  风险等级: {BADGE.get(level,'')} {level}  ({risk_score}/100)")
    print(f"  余额:     {account.get('balance_trx', 0):.6f} TRX")
    print(f"  交易数:   {len(trx_txs)} TRX + {len(trc20_txs)} TRC20")
    if bl_result.get("detected"):
        for h in bl_result.get("hits", []):
            print(f"  🔴 黑名单: {h['label']} ({h['address'][:16]}...)")
    if freeze_res.get("detected"):
        print(f"  🔴 USDT冻结: {freeze_res.get('label','')}")
    if peel_result.get("detected"):
        print(f"  ⛓  Peel Chain: {peel_result['summary']}")
    print(f" {'='*50}\n")

    report = {
        "meta": {
            "address":     address,
            "chain":       "TRON",
            "analyzed_at": datetime.now().isoformat(),
            "engine":      "LucidAML",
        },
        "risk": {
            "risk_level": level,
            "risk_score": risk_score,
        },
        "balance": {
            "trx":    account.get("balance_trx", 0),
            "trc20":  trc20_balance,
        },
        "detectors": {
            "tron_blacklist":  bl_result,
            "tron_usdt_freeze": freeze_res,
            "tron_peel_chain": peel_result,
        },
        "graph": {
            "nodes": [
                {
                    "id":    a,
                    "color": ("#ef4444" if info["is_blacklist"] else
                              "#10b981" if info["is_dex"] else
                              "#06b6d4" if info["is_cex"] else
                              "#3b82f6" if info["is_bridge"] else "#64748b"),
                    "stats": {
                        "in_count":  info["in_count"],
                        "out_count": info["out_count"],
                        "tokens":    list(info["tokens"])[:5],
                    },
                    "labels": info["labels"],
                }
                for a, info in nodes.items()
            ],
            "edges": [
                {"source": f, "target": t, "value": v, "ts": ts, "type": typ}
                for f, t, v, ts, typ in edges
            ],
        },
    }

    if save_json:
        out_dir  = output_dir or os.path.expanduser("~/Desktop/stbc")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir,
            f"tron_report_{address[:12]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(f"  报告已保存 → {out_path}")

    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python collector_tron.py <TRON地址> [limit]")
        print("示例: python collector_tron.py TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7")
        sys.exit(0)
    address = sys.argv[1]
    limit   = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    analyze_tron_address(address, limit=limit, save_json=True)
