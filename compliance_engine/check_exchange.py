# ============================================================
# check_exchange.py
# 交易所资金流向检测
# 识别资金流经哪些交易所、交易量、是否合规 vs 制裁
#
# 用法：
#   python check_exchange.py <ETH地址>
#   python check_exchange.py <ETH地址> --hops 2
#   python check_exchange.py <ETH地址> --json
# ============================================================

import sys, os, json, argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collector import fetch_txlist, fetch_tokentx

# ── 合规 CEX ────────────────────────────────────────────────
COMPLIANT_CEX = {
    "0x28c6c06298d514db089934071355e5743bf21d60": ("Binance",  "hot_wallet"),
    "0x21a31ee1afc51d94c2efee98d4c2d258c33d8b61": ("Binance",  "cold_wallet"),
    "0xf977814e90da44bfa03b6295a0616a897441acec": ("Binance",  "cold_wallet"),
    "0xbe0eb53f46cd790cd13851d5eff43d12404d33e8": ("Binance",  "cold_wallet"),
    "0xdfd5293d8e347dfe59e90a3b8c60e8a387a5e4c3": ("Binance",  "cold_wallet"),
    "0x3cd751e6b0078be393132286c442345e5dc49699": ("Binance",  "hot_wallet"),
    "0x4976a4a02f38326660d17bf34b431dc6e2eb2327": ("Binance",  "hot_wallet"),
    "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b": ("OKX",      "hot_wallet"),
    "0x56eddb7aa87536c09ccc9b7a0d9e75e4c0b5c6f2": ("OKX",      "hot_wallet"),
    "0x236f9f97e0e62388479bf9e5ba4889e46b0273c3": ("OKX",      "cold_wallet"),
    "0x1b3cb81e51011b549d78bf720b0d924ac763a7c2": ("Coinbase", "hot_wallet"),
    "0x503828976d22510aad0201ac7ec88293211d23da": ("Coinbase", "cold_wallet"),
    "0x7ad4c1647aa947d1c0543ebdc5ad4b36b7f0a630": ("Coinbase", "hot_wallet"),
    "0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43": ("Coinbase", "cold_wallet"),
    "0x2910543af39aba0cd09dbb2d50200b3e800a63d2": ("Kraken",   "hot_wallet"),
    "0xae2d4617c862309a3d75a0ffb358c7a5009c673f": ("Kraken",   "hot_wallet"),
    "0x43984d578803891dfa9706bdeee6078d80cfc79e": ("Kraken",   "cold_wallet"),
    "0x0d0707963952f2fba59dd06f2b425ace40b492fe": ("Gate.io",  "hot_wallet"),
    "0x7793cd85c11a924478d358d49b05b37e91b5810f": ("Gate.io",  "hot_wallet"),
    "0xab5c66752a9e8167967685f1450532fb96d5d24f": ("HTX",      "hot_wallet"),
    "0x6748f50f686bfbca6fe8ad62b22228b87f31ff2b": ("HTX",      "hot_wallet"),
    "0xf89d7b9c864f589bbf53a82105107622b35eaa40": ("Bybit",    "hot_wallet"),
    "0x01352483f81b87a8e99b27f23c0f95a0ab4fb000": ("Bybit",    "hot_wallet"),
    "0x2b5634c42055806a59e9107ed44d43c426e58258": ("KuCoin",   "hot_wallet"),
    "0xa1d8d972560c2f8144af871db508f0b0b10a3fbf": ("KuCoin",   "hot_wallet"),
    "0x742d35cc6634c0532925a3b844bc454e4438f44e": ("Bitfinex", "hot_wallet"),
    "0x1151314c646ce4e0efd76d1af4760ae66a9fe30f": ("Bitfinex", "cold_wallet"),
    "0x390de26d772d2e2005c6d1d24afc902bae37a4bb": ("Upbit",    "hot_wallet"),
}

# ── 制裁交易所 ───────────────────────────────────────────────
SANCTIONED_CEX = {
    "0x6f6b4e9b7d4f3aca2e9e0afe7f4c0bae9e4e4e4e": ("Garantex",    "OFAC SDN 2022 — 俄罗斯制裁交易所"),
    "0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a": ("Sinbad.io",    "OFAC SDN 2023 — 制裁Mixer/交易所"),
    "0x7f367cc41522ce07553e823bf3be79a889debe1b": ("Blender.io",   "OFAC SDN 2022 — 制裁Mixer"),
    "0x308ed4b7b49797e1a98d3818bff6fe5385410370": ("Huione Group", "OFAC SDN 2024 — 东南亚洗钱网络"),
    "0x3cbded43efdaf0fc77b9c55f6fc9988fcc9b37d9": ("Bitzlato",     "FinCEN 2023 — 主要洗钱关切"),
}

# ── 高风险灰色地带 ───────────────────────────────────────────
GREY_CEX = {
    "0x67d4e6bd676db6a6c7b224fdadfc0e1e73e50ab5": ("Hydra-linked",    "暗网市场关联"),
    "0x8576acc5c05d6ce88f4e49bf65bdf0c62f91353c": ("AlphaBay-linked", "暗网市场关联"),
}

# 合并成统一字典
ALL_EXCHANGES = {}
for a, (n, wt) in COMPLIANT_CEX.items():
    ALL_EXCHANGES[a] = {"name": n, "wallet_type": wt,          "status": "compliant", "note": ""}
for a, (n, note) in SANCTIONED_CEX.items():
    ALL_EXCHANGES[a] = {"name": n, "wallet_type": "sanctioned", "status": "sanctioned", "note": note}
for a, (n, note) in GREY_CEX.items():
    ALL_EXCHANGES[a] = {"name": n, "wallet_type": "grey",       "status": "grey",       "note": note}

WEI = 1e18
BADGE        = {"compliant": "✅", "sanctioned": "🔴", "grey": "🟠"}
STATUS_LABEL = {"compliant": "合规CEX", "sanctioned": "制裁交易所", "grey": "高风险"}


# ============================================================
# 核心检测
# ============================================================

def _update_flow(flows, ex_addr, ex_info, sent, recv, symbol, ts, decimals=18, via=None):
    if ex_addr not in flows:
        flows[ex_addr] = {
            "name": ex_info["name"], "status": ex_info["status"],
            "wallet_type": ex_info.get("wallet_type","unknown"),
            "note": ex_info.get("note",""),
            "sent_wei": 0, "recv_wei": 0, "tx_count": 0,
            "tokens": {}, "via": set(), "first_ts": ts, "last_ts": ts,
        }
    f = flows[ex_addr]
    f["sent_wei"] += sent
    f["recv_wei"] += recv
    f["tx_count"] += 1
    if ts:
        f["first_ts"] = min(f["first_ts"], ts) if f["first_ts"] else ts
        f["last_ts"]  = max(f["last_ts"],  ts) if f["last_ts"]  else ts
    if via:
        f["via"].add(via)
    if symbol not in ("ETH", "INT"):
        tok = f["tokens"].setdefault(symbol, {"sent": 0, "recv": 0, "decimals": decimals})
        tok["sent"] += sent
        tok["recv"] += recv


def find_direct_flows(addr, eth_txs, tok_txs):
    flows = {}
    for tx in eth_txs:
        if tx.get("isError","0") == "1": continue
        frm = tx.get("from","").lower()
        to  = tx.get("to","").lower()
        val = int(tx.get("value",0) or 0)
        ts  = int(tx.get("timeStamp",0) or 0)
        for ex_addr, ex_info in ALL_EXCHANGES.items():
            if frm == addr and to == ex_addr:
                _update_flow(flows, ex_addr, ex_info, val, 0, "ETH", ts)
            elif to == addr and frm == ex_addr:
                _update_flow(flows, ex_addr, ex_info, 0, val, "ETH", ts)
    for tx in tok_txs:
        frm = tx.get("from","").lower()
        to  = tx.get("to","").lower()
        val = int(tx.get("value",0) or 0)
        sym = tx.get("tokenSymbol","?")
        dec = int(tx.get("tokenDecimal",18) or 18)
        ts  = int(tx.get("timeStamp",0) or 0)
        for ex_addr, ex_info in ALL_EXCHANGES.items():
            if frm == addr and to == ex_addr:
                _update_flow(flows, ex_addr, ex_info, val, 0, sym, ts, dec)
            elif to == addr and frm == ex_addr:
                _update_flow(flows, ex_addr, ex_info, 0, val, sym, ts, dec)
    for f in flows.values():
        f["hop"] = 1
    return flows


def find_indirect_flows(addr, eth_txs, tok_txs):
    import time
    counterparts = set()
    for tx in eth_txs:
        frm = tx.get("from","").lower(); to = tx.get("to","").lower()
        if frm == addr: counterparts.add(to)
        if to  == addr: counterparts.add(frm)
    counterparts -= set(ALL_EXCHANGES.keys())
    counterparts.discard(addr)

    indirect = {}
    for cp in list(counterparts)[:15]:
        time.sleep(0.3)
        try:
            cp_eth = fetch_txlist(cp)
            cp_tok = fetch_tokentx(cp)
        except Exception:
            continue
        for tx in cp_eth:
            if tx.get("isError","0") == "1": continue
            frm = tx.get("from","").lower(); to = tx.get("to","").lower()
            val = int(tx.get("value",0) or 0); ts = int(tx.get("timeStamp",0) or 0)
            for ex_addr, ex_info in ALL_EXCHANGES.items():
                if frm == cp and to == ex_addr:
                    _update_flow(indirect, ex_addr, ex_info, val, 0, "ETH", ts, via=cp)
                elif to == cp and frm == ex_addr:
                    _update_flow(indirect, ex_addr, ex_info, 0, val, "ETH", ts, via=cp)
        for tx in cp_tok:
            frm = tx.get("from","").lower(); to = tx.get("to","").lower()
            val = int(tx.get("value",0) or 0)
            sym = tx.get("tokenSymbol","?"); dec = int(tx.get("tokenDecimal",18) or 18)
            ts  = int(tx.get("timeStamp",0) or 0)
            for ex_addr, ex_info in ALL_EXCHANGES.items():
                if frm == cp and to == ex_addr:
                    _update_flow(indirect, ex_addr, ex_info, val, 0, sym, ts, dec, via=cp)
                elif to == cp and frm == ex_addr:
                    _update_flow(indirect, ex_addr, ex_info, 0, val, sym, ts, dec, via=cp)

    for f in indirect.values():
        f["hop"] = 2
    print(f"    → 追踪 {min(len(counterparts),15)} 个中间地址，发现 {len(indirect)} 个间接交互")
    return indirect


def _build_summary(flows):
    compliant  = {k:v for k,v in flows.items() if v["status"]=="compliant"}
    sanctioned = {k:v for k,v in flows.items() if v["status"]=="sanctioned"}
    grey       = {k:v for k,v in flows.items() if v["status"]=="grey"}
    risk = ("CRITICAL" if sanctioned else "HIGH" if grey else "LOW" if compliant else "CLEAN")
    law_refs = []
    if sanctioned:
        law_refs.append({"ref":"§7.5, §7.8, OFAC SDN","title":"制裁实体交互 — 强制处置",
                         "action":"立即冻结，24小时内提交STR，获取高管批准"})
    if grey:
        law_refs.append({"ref":"§5.4, §4.18","title":"高风险交易所 — 触发EDD",
                         "action":"升级至EDD，加强持续监控"})
    return risk, {
        "total_exchanges":  len(flows),
        "compliant_count":  len(compliant),
        "sanctioned_count": len(sanctioned),
        "grey_count":       len(grey),
        "compliant_names":  list({v["name"] for v in compliant.values()}),
        "sanctioned_names": list({v["name"] for v in sanctioned.values()}),
        "grey_names":       list({v["name"] for v in grey.values()}),
    }, law_refs


# ── 供 analyze.py 调用的轻量接口 ──────────────────────────────
def run_exchange_check(address, eth_txs, tok_txs, nodes=None, edges=None):
    addr  = address.lower()
    flows = find_direct_flows(addr, eth_txs, tok_txs)
    if nodes and edges:
        for (f, t, v, ts, typ) in edges:
            for ex_addr, ex_info in ALL_EXCHANGES.items():
                if f == addr and t == ex_addr:
                    _update_flow(flows, ex_addr, ex_info, v, 0, typ, ts)
                elif t == addr and f == ex_addr:
                    _update_flow(flows, ex_addr, ex_info, 0, v, typ, ts)
        for f in flows.values():
            f.setdefault("hop", 1)
    for f in flows.values():
        if isinstance(f.get("via"), set):
            f["via"] = list(f["via"])
    risk, summary, law_refs = _build_summary(flows)
    return {"address": addr, "risk_level": risk,
            "flows": flows, "summary": summary, "law_refs": law_refs}


# ── 独立命令行运行 ─────────────────────────────────────────────
def check_exchange_flows(address, hops=1):
    addr = address.lower()
    print(f"  ▸ 拉取 ETH 交易...")
    eth_txs = fetch_txlist(addr); print(f"    → {len(eth_txs)} 笔")
    print(f"  ▸ 拉取 ERC20 转账...")
    tok_txs = fetch_tokentx(addr); print(f"    → {len(tok_txs)} 笔")
    flows = find_direct_flows(addr, eth_txs, tok_txs)
    if hops >= 2:
        print(f"  ▸ 追踪间接交互（2跳）...")
        indirect = find_indirect_flows(addr, eth_txs, tok_txs)
        for k, v in indirect.items():
            if k not in flows:
                flows[k] = v
    for f in flows.values():
        if isinstance(f.get("via"), set):
            f["via"] = list(f["via"])
    risk, summary, law_refs = _build_summary(flows)
    return {"address": addr, "analyzed_at": datetime.now().isoformat(),
            "risk_level": risk, "flows": flows, "summary": summary, "law_refs": law_refs}


def fmt_amount(wei, symbol="ETH", decimals=18):
    if not wei: return "0"
    val = wei / (10 ** decimals)
    if val >= 1e9:  return f"{val/1e9:.4f}B {symbol}"
    if val >= 1e6:  return f"{val/1e6:.4f}M {symbol}"
    if val >= 1e3:  return f"{val:,.2f} {symbol}"
    return f"{val:.6f} {symbol}"


def print_report(result):
    RISK_ICON = {"CRITICAL":"🔴","HIGH":"🟠","LOW":"🟢","CLEAN":"✅"}
    print(f"\n{'='*60}")
    print(f"  LucidAML — 交易所流向检测报告")
    print(f"{'='*60}")
    print(f"  地址:     {result['address']}")
    print(f"  风险等级: {RISK_ICON.get(result['risk_level'],'')} {result['risk_level']}")
    s = result["summary"]
    print(f"  交易所数: {s['total_exchanges']}  "
          f"合规:{s['compliant_count']}  制裁:{s['sanctioned_count']}  高风险:{s['grey_count']}")
    print(f"{'='*60}")
    if not result["flows"]:
        print("  ✅ 未发现与已知交易所的交互"); return
    order = {"sanctioned":0,"grey":1,"compliant":2}
    for ex_addr, f in sorted(result["flows"].items(), key=lambda x: order.get(x[1]["status"],3)):
        hop_str = f"({f.get('hop',1)}跳)"
        print(f"\n  {BADGE.get(f['status'],'ℹ')} {f['name']} [{STATUS_LABEL.get(f['status'],f['status'])}] {hop_str}")
        if f.get("note"): print(f"     ⚠️  {f['note']}")
        print(f"     地址: {ex_addr}")
        print(f"     ETH 发出: {fmt_amount(f['sent_wei'])}  收入: {fmt_amount(f['recv_wei'])}")
        print(f"     笔数: {f['tx_count']}")
        for sym, td in list(f.get("tokens",{}).items())[:4]:
            dec = td.get("decimals",18)
            print(f"     {sym}: 发出 {fmt_amount(td['sent'],sym,dec)}  收入 {fmt_amount(td['recv'],sym,dec)}")
        via = f.get("via",[])
        if via: print(f"     经由: {', '.join(str(v)[:12]+'...' for v in via[:3])}")
    if result.get("law_refs"):
        print(f"\n  法规处置:")
        for r in result["law_refs"]:
            print(f"  [{r['ref']}] {r['title']}")
            print(f"  ⚡ {r['action']}")
    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LucidAML 交易所流向检测")
    parser.add_argument("address")
    parser.add_argument("--hops", "-n", type=int, default=1)
    parser.add_argument("--json",  action="store_true")
    parser.add_argument("--save",  action="store_true")
    args = parser.parse_args()

    print(f"\n{'='*60}  LucidAML — 交易所流向检测  {'='*60}")
    print(f"  地址: {args.address}  深度: {args.hops}跳")

    result = check_exchange_flows(args.address, hops=args.hops)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    else:
        print_report(result)

    if args.save:
        out_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
        os.makedirs(out_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(out_dir, f"exchange_{args.address[:10]}_{ts}.json")
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(result, fp, indent=2, ensure_ascii=False, default=str)
        print(f"  📄 已保存 → {path}\n")
