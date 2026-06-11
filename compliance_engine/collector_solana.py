# ============================================================
# collector_solana.py
# Solana 地址数据采集 — Helius API
# ============================================================

import sys, os, json, time, requests
from datetime import datetime
from collections import defaultdict

HELIUS_KEY  = "5c0843d0-d748-43a6-8aab-b9df8f19a2de"
BASE_URL    = f"https://api.helius.xyz/v0"
RPC_URL     = f"https://mainnet.helius-rpc.com/?api-key={HELIUS_KEY}"

# ── 已知黑名单 / Mixer (Solana) ─────────────────────────────
SOL_BLACKLIST = {
    # Lazarus Group / 朝鲜黑客
    "CRSmtViACtQkFP1GNm3Xw7ABitEkGnXpJZjdnFnhADnL": "Lazarus Group (Bybit 2025)",
    "HJHNkGj8w4H5oMSNzNZ3jDgWWqCz31qNqN9ooFkuDeyP": "Lazarus Group (Harmony 2022)",
    "Htp9MGP8Tig923ZFY7Qf2zzbMUmYneFRAhSp7vSg4wxV":  "Lazarus Group",
    "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9": "Lazarus Group (Ronin 2022)",
    "8hL4P7oZrfXynroRQfzFbGRQAH3sJbPY5J8YLkK6M9FN": "Sanctioned Entity",
    # Mixer / 洗钱相关
    "EFqYVCPEBxsRkNGPhSJZnWBQ9wCGEbFAGHWG8n5DGJhL": "Tornado Cash Solana Relay",
    "9vPbKmEAHKo5FePDHkzFUqFEB3LcZxRqSBReBaTkouMb": "Known Mixer",
    "GZpS8cY8yjTriaXFGRHKBBkVgALBCBRKBQKRGD4LPFMS": "Blender.io Solana",
}

SOL_KNOWN_DEX = {
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4":  "Jupiter Aggregator V6",
    "JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB":  "Jupiter Aggregator V4",
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc":  "Orca Whirlpool",
    "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP": "Orca V1",
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8": "Raydium AMM",
    "5quBtoiQqxF9Jv6KYKctB59NT3gtJD2Y65kdnB1Uev3h": "Raydium Liquidity",
    "srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX":  "Serum DEX V3",
    "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin": "Serum DEX V2",
    "MERLuDFBMmsHnsBPZw2sDQZHvXFMwp8EdjudcU2pgJuj": "Mercurial Finance",
    "SSwpkEEcbUqx4vtoEByFjSkhKdCT862DNVb52nZg1UZ":  "Saber",
}

SOL_KNOWN_CEX = {
    "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9": "Binance SOL Hot Wallet",
    "H8sMJSCQxfKiFTCfDR3DUMLPwcRbM61LGFJ8N4dK3WjS": "Coinbase",
    "AC5RDfQFmDS1deWZos921JfqscXdByf8BKHs5ACWjtW2": "Binance",
    "2AQdpHJ2NpcBKyyKZUiEkMZTsGQiFZcZ7HbWmwjHtLEF": "Kraken",
    "FWznbcNXWQuHTawe9RxvQ2LdCENssh12dsznf4RiouN5": "OKX",
    "A7tHABbPzZBbcLFVhCFvvbB44RvBFDgL6MNJAcrL3UhZ": "Bybit",
}

# ── HTTP helpers ─────────────────────────────────────────────

def _helius_get(path, params=None, retries=3):
    url = BASE_URL + path
    p   = {"api-key": HELIUS_KEY, **(params or {})}
    for i in range(retries):
        try:
            r = requests.get(url, params=p, timeout=20)
            if r.status_code == 200:
                return r.json()
            if r.status_code == 429:
                time.sleep(2 ** i)
        except Exception as e:
            time.sleep(1)
    return None

def _helius_post(path, body, retries=3):
    url = BASE_URL + path
    for i in range(retries):
        try:
            r = requests.post(
                url, json=body,
                params={"api-key": HELIUS_KEY},
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            if r.status_code == 200:
                return r.json()
            if r.status_code == 429:
                time.sleep(2 ** i)
        except Exception:
            time.sleep(1)
    return None

def _rpc(method, params):
    """直接调 Helius RPC"""
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    try:
        r = requests.post(RPC_URL, json=body, timeout=20)
        return r.json().get("result")
    except Exception:
        return None


# ── 核心采集函数 ──────────────────────────────────────────────

def fetch_sol_transactions(address, limit=100):
    """
    用 Helius Enhanced Transactions API 拉交易
    自动解析 SOL 转账 / SPL Token 转账 / DEX swap
    返回 list of parsed tx dicts
    """
    print(f"    [Helius] 拉取交易记录 (limit={limit})...")
    txs = _helius_get(f"/addresses/{address}/transactions", {
        "limit": min(limit, 100),
        "type":  "TRANSFER,SWAP,STAKE,UNKNOWN",
    })
    if not txs:
        return []
    print(f"      → {len(txs)} 笔")
    return txs


def fetch_sol_balance(address):
    """拉 SOL 余额和 SPL Token 余额"""
    result = _rpc("getBalance", [address, {"commitment": "confirmed"}])
    sol_balance = (result.get("value", 0) if isinstance(result, dict) else 0) / 1e9

    # SPL token accounts
    token_result = _rpc("getTokenAccountsByOwner", [
        address,
        {"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},
        {"encoding": "jsonParsed"},
    ])
    tokens = []
    if token_result and isinstance(token_result, dict):
        for acc in token_result.get("value", []):
            info = acc.get("account", {}).get("data", {}).get("parsed", {}).get("info", {})
            mint  = info.get("mint", "")
            amt   = info.get("tokenAmount", {})
            bal   = float(amt.get("uiAmount") or 0)
            if bal > 0:
                tokens.append({"mint": mint, "balance": bal, "decimals": amt.get("decimals", 0)})
    return {"sol": sol_balance, "tokens": tokens}


def parse_sol_transactions(address, raw_txs):
    """
    把 Helius enhanced tx 解析成标准 edge 格式:
      (from, to, value_lamports, timestamp, token_symbol)
    同时建 nodes
    """
    addr = address.lower()
    nodes = {}
    edges = []

    def upsert(a, ts):
        if not a:
            return
        a = a.lower()
        if a not in nodes:
            nodes[a] = {
                "first_seen":   ts,
                "last_seen":    ts,
                "in_count":     0,
                "out_count":    0,
                "in_value":     0,
                "out_value":    0,
                "tokens":       set(),
                "is_blacklist": a in {k.lower() for k in SOL_BLACKLIST},
                "is_mixer":     False,
                "is_gambling":  False,
                "is_bridge":    False,
                "is_dex":       a in {k.lower() for k in SOL_KNOWN_DEX},
                "is_cex":       a in {k.lower() for k in SOL_KNOWN_CEX},
                "labels":       _get_sol_labels(a),
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
        if sym not in ("SOL", "lamports"):
            nodes[f]["tokens"].add(sym)
            nodes[t]["tokens"].add(sym)
        edges.append((f, t, val, ts, sym))

    for tx in raw_txs:
        ts = tx.get("timestamp", 0)

        # ── SOL 原生转账 ──────────────────────────────────────
        for transfer in tx.get("nativeTransfers", []):
            frm = transfer.get("fromUserAccount", "")
            to  = transfer.get("toUserAccount", "")
            amt = int(transfer.get("amount", 0))  # lamports
            if frm and to and amt > 0:
                add_edge(frm, to, amt, ts, "SOL")

        # ── SPL Token 转账 ────────────────────────────────────
        for transfer in tx.get("tokenTransfers", []):
            frm  = transfer.get("fromUserAccount", "")
            to   = transfer.get("toUserAccount", "")
            amt  = float(transfer.get("tokenAmount", 0))
            sym  = transfer.get("mint", "SPL")[:8]  # 用 mint 前8位作symbol
            # 常见 mint 映射
            mint = transfer.get("mint", "")
            sym  = _mint_to_symbol(mint) or sym
            # 转成最小单位整数
            dec  = int(transfer.get("decimals", 6))
            val  = int(amt * (10 ** dec))
            if frm and to and val > 0:
                add_edge(frm, to, val, ts, sym)

        # ── DEX Swap 事件 ─────────────────────────────────────
        # Helius 解析的 swap 事件有 swaps 字段
        for swap in tx.get("events", {}).get("swap", {}).get("nativeInput", []):
            # 简化：只记录 swap 整体的 from/to
            pass  # 已经被 nativeTransfers / tokenTransfers 覆盖

    return nodes, edges


def _get_sol_labels(addr):
    labels = []
    for k, v in SOL_BLACKLIST.items():
        if k.lower() == addr:
            labels.append(v)
    for k, v in SOL_KNOWN_DEX.items():
        if k.lower() == addr:
            labels.append(f"DEX: {v}")
    for k, v in SOL_KNOWN_CEX.items():
        if k.lower() == addr:
            labels.append(f"CEX: {v}")
    return labels


# ── SPL Token Mint 地址 → Symbol ─────────────────────────────
MINT_MAP = {
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": "USDC",
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB": "USDT",
    "So11111111111111111111111111111111111111112":    "wSOL",
    "7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs": "ETH",
    "9n4nbM75f5Ui33ZbPYXn59EwSgE8CGsHtAeTH5YFeJ9E": "BTC",
    "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So":  "mSOL",
    "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263": "BONK",
    "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN":  "JUP",
    "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R": "RAY",
    "orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE":  "ORCA",
}

def _mint_to_symbol(mint):
    return MINT_MAP.get(mint)


# ── 风险检测（Solana 专用）──────────────────────────────────

def detect_sol_blacklist(address, nodes, edges):
    addr  = address.lower()
    hits  = []
    for a, info in nodes.items():
        if info.get("is_blacklist"):
            label = next((v for k, v in SOL_BLACKLIST.items() if k.lower() == a), "Blacklist")
            hits.append({"address": a, "label": label, "hop": 0 if a == addr else 1})
    if not hits:
        return {"detected": False}
    return {
        "detected":  True,
        "severity":  "CRITICAL",
        "hits":      hits,
        "summary":   f"Solana: 命中 {len(hits)} 个已知风险地址",
    }


def detect_sol_peel_chain(nodes, edges):
    """SOL Peel Chain：入出各1的地址链"""
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
        "summary":        f"Solana Peel Chain: {len(chains)} 条，最长 {len(chains[0])} 跳",
    }


# ── 主入口 ────────────────────────────────────────────────────

def analyze_sol_address(address, limit=100, save_json=True, output_dir=None):
    print(f"\n{'='*55}")
    print(f" Solana 地址分析 — Helius")
    print(f"{'='*55}")
    print(f" 地址: {address}\n")

    # 余额
    balance = fetch_sol_balance(address)
    print(f"    SOL 余额: {balance['sol']:.4f} SOL")
    if balance["tokens"]:
        print(f"    SPL Token: {len(balance['tokens'])} 种")

    # 交易
    raw_txs = fetch_sol_transactions(address, limit=limit)
    if not raw_txs:
        print("    ⚠️  未拉到交易数据")
        return None

    # 建图
    nodes, edges = parse_sol_transactions(address, raw_txs)
    print(f"    节点: {len(nodes)}  边: {len(edges)}")

    # 检测
    bl_result   = detect_sol_blacklist(address, nodes, edges)
    peel_result = detect_sol_peel_chain(nodes, edges)

    # 简单评分
    risk_score = 0
    if bl_result.get("detected"):   risk_score += 100
    if peel_result.get("detected"): risk_score += 30
    risk_score = min(100, risk_score)
    level = ("CRITICAL" if risk_score >= 100 else
             "HIGH"     if risk_score >= 60  else
             "MEDIUM"   if risk_score >= 30  else "LOW")

    BADGE = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    print(f"\n {'='*50}")
    print(f"  Solana 风险报告")
    print(f"  地址:     {address}")
    print(f"  风险等级: {BADGE.get(level,'')} {level}  ({risk_score}/100)")
    print(f"  余额:     {balance['sol']:.6f} SOL")
    print(f"  交易数:   {len(raw_txs)}")
    if bl_result.get("detected"):
        for h in bl_result.get("hits", []):
            print(f"  🔴 黑名单: {h['label']} ({h['address'][:16]}...)")
    if peel_result.get("detected"):
        print(f"  ⛓  Peel Chain: {peel_result['summary']}")
    print(f" {'='*50}\n")

    report = {
        "meta": {
            "address":     address,
            "chain":       "SOL",
            "analyzed_at": datetime.now().isoformat(),
            "engine":      "LucidAML",
        },
        "risk": {
            "risk_level": level,
            "risk_score": risk_score,
        },
        "balance":   balance,
        "detectors": {
            "sol_blacklist":  bl_result,
            "sol_peel_chain": peel_result,
        },
        "graph": {
            "nodes": [
                {
                    "id":    a,
                    "color": ("#ef4444" if info["is_blacklist"] else
                              "#10b981" if info["is_dex"] else
                              "#06b6d4" if info["is_cex"] else "#64748b"),
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
            f"sol_report_{address[:12]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(f"  报告已保存 → {out_path}")

    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python collector_solana.py <SOL地址> [limit]")
        print("示例: python collector_solana.py vines1vzrYbzLMRdu58ou5XTby4qAqVRLmqo36NKPTg")
        sys.exit(0)
    address = sys.argv[1]
    limit   = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    analyze_sol_address(address, limit=limit, save_json=True)
