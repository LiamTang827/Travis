# ============================================================
# balance.py
# ETH 地址余额 + 历史资金流入/流出汇总
# ============================================================

import time
import requests
from config import ETHERSCAN_KEY, ETHERSCAN_BASE, ETHERSCAN_CHAIN

SESS = requests.Session()
SESS.headers.update({"User-Agent": "LucidAML/3.0"})

WEI = 1e18


def _get(params, retry=3):
    params["chainid"] = ETHERSCAN_CHAIN
    params["apikey"]  = ETHERSCAN_KEY
    for i in range(retry):
        try:
            r = SESS.get(ETHERSCAN_BASE, params=params, timeout=20)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        time.sleep(0.5 * (i + 1))
    return {}


def fetch_balance(address: str) -> dict:
    """拉取 ETH 地址当前余额"""
    res = _get({
        "module":  "account",
        "action":  "balance",
        "address": address.lower(),
        "tag":     "latest",
    })
    raw = res.get("result", "0")
    try:
        wei = int(raw)
    except (ValueError, TypeError):
        wei = 0
    return {
        "balance_wei": wei,
        "balance_eth": round(wei / WEI, 6),
    }


def _fmt_token_display(raw_value: int, decimals: int, symbol: str) -> str:
    """生成可读 token 数量字符串"""
    if decimals <= 0:
        val = float(raw_value)
    else:
        val = raw_value / (10 ** decimals)

    if val >= 1_000_000_000_000:
        s = f"{val/1_000_000_000_000:.4f}T"
    elif val >= 1_000_000_000:
        s = f"{val/1_000_000_000:.4f}B"
    elif val >= 1_000_000:
        s = f"{val/1_000_000:.4f}M"
    elif val >= 1_000:
        s = f"{val:,.2f}"
    else:
        s = f"{val:.6f}"
    return f"{s} {symbol}"


def summarize_fund_flow(address: str, eth_txs: list, token_txs: list) -> dict:
    addr = address.lower()

    # ETH
    eth_in_wei = eth_out_wei = eth_in_cnt = eth_out_cnt = 0
    counterparts_in, counterparts_out = set(), set()

    for tx in eth_txs:
        if tx.get("isError", "0") == "1":
            continue
        val = int(tx.get("value", 0) or 0)
        frm = tx.get("from", "").lower()
        to  = tx.get("to",   "").lower()
        if to == addr and val > 0:
            eth_in_wei  += val; eth_in_cnt  += 1; counterparts_in.add(frm)
        elif frm == addr and val > 0:
            eth_out_wei += val; eth_out_cnt += 1; counterparts_out.add(to)

    # Token — 从每笔交易读取 tokenDecimal
    token_data: dict = {}
    for tx in token_txs:
        sym  = tx.get("tokenSymbol", "?")
        try:    val      = int(tx.get("value", 0) or 0)
        except: val      = 0
        try:    decimals = int(tx.get("tokenDecimal", 18) or 18)
        except: decimals = 18

        frm = tx.get("from", "").lower()
        to  = tx.get("to",   "").lower()

        if sym not in token_data:
            token_data[sym] = {"in": 0, "out": 0, "decimals": decimals}
        token_data[sym]["decimals"] = decimals  # 以最新一笔为准

        if to == addr:
            token_data[sym]["in"]  += val
        elif frm == addr:
            token_data[sym]["out"] += val

    # 格式化
    def make_entry(sym, raw, dec):
        val_f = raw / (10 ** dec) if dec > 0 else float(raw)
        return {
            "symbol":     sym,
            "amount_str": _fmt_token_display(raw, dec, sym),
            "amount":     val_f,  # 用于排序
            "decimals":   dec,
        }

    top_in  = sorted(
        [make_entry(s, d["in"],  d["decimals"]) for s, d in token_data.items() if d["in"]  > 0],
        key=lambda x: x["amount"], reverse=True
    )[:6]
    top_out = sorted(
        [make_entry(s, d["out"], d["decimals"]) for s, d in token_data.items() if d["out"] > 0],
        key=lambda x: x["amount"], reverse=True
    )[:6]

    net = eth_in_wei - eth_out_wei
    return {
        "eth": {
            "in_eth":           round(eth_in_wei  / WEI, 6),
            "out_eth":          round(eth_out_wei / WEI, 6),
            "net_eth":          round(net         / WEI, 6),
            "in_count":         eth_in_cnt,
            "out_count":        eth_out_cnt,
            "unique_senders":   len(counterparts_in),
            "unique_receivers": len(counterparts_out),
        },
        "tokens": {
            "top_in":             top_in,
            "top_out":            top_out,
            "unique_symbols_in":  len([s for s,d in token_data.items() if d["in"]  > 0]),
            "unique_symbols_out": len([s for s,d in token_data.items() if d["out"] > 0]),
        },
    }


def get_full_balance_report(address: str, eth_txs: list, token_txs: list) -> dict:
    bal  = fetch_balance(address)
    flow = summarize_fund_flow(address, eth_txs, token_txs)
    eth  = flow["eth"]
    return {
        "address":   address.lower(),
        "current":   bal,
        "fund_flow": flow,
        "summary": (
            f"余额 {bal['balance_eth']} ETH | "
            f"历史流入 {eth['in_eth']} ETH ({eth['in_count']} 笔) | "
            f"历史流出 {eth['out_eth']} ETH ({eth['out_count']} 笔) | "
            f"净流量 {eth['net_eth']} ETH"
        ),
    }
