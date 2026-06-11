# ============================================================
# scorer.py v2
# 直接交互黑名单 → 100分（标黑）
# 二跳黑名单     → 50分
# 三跳黑名单     → 25分
# 总分 >= 100    → CRITICAL
# ============================================================

from config import BLACKLIST, KNOWN_MIXERS, KNOWN_BRIDGES

# ─── 已知 Token Decimals 注册表 ──────────────────────────────
# 覆盖最常见的 ERC20，不在表里的从 token_txs 实时读取，fallback=18
TOKEN_DECIMALS_DEFAULT = {
    # Stablecoins
    "USDT":   6,  "USDC":  6,  "BUSD":   6,  "TUSD":   6,
    "FRAX":  18,  "DAI":  18,  "LUSD":  18,  "USDD":  18,
    "FDUSD":18,   "PYUSD": 6,  "USDP":  18,  "GUSD":   2,
    "EURS":   2,  "EURT":  6,  "USDE":  18,
    # Wrapped
    "WETH":  18,  "WBTC":   8,  "WBNB":  18,  "WMATIC":18,
    "WAVAX":18,   "WSOL":   9,
    # Major ERC20
    "SHIB":  18,  "LINK":  18,  "UNI":   18,  "AAVE":  18,
    "CRV":   18,  "MKR":   18,  "SNX":   18,  "COMP":  18,
    "BAL":   18,  "YFI":   18,  "SUSHI": 18,  "1INCH": 18,
    "LDO":   18,  "RPL":   18,  "FXS":   18,  "CVX":   18,
    "GRT":   18,  "ENS":   18,  "IMX":   18,  "APE":   18,
    "BLUR":  18,  "ARB":   18,  "OP":    18,  "MATIC": 18,
    "BNB":   18,  "TRX":    6,  "XRP":    6,
    # Exchange tokens
    "OKB":   18,  "HT":    18,  "BGB":   18,  "LEO":   18,
    # NFT/Gaming
    "SAND":  18,  "MANA":  18,  "AXS":   18,  "GALA":  8,
    # Other common
    "ETH":   18,  "INT":   18,
}


def get_token_decimals_map(token_txs: list) -> dict:
    """
    从 token_txs 实时构建 {symbol: decimals} 映射
    优先使用链上数据，fallback 到已知表，再 fallback 到 18
    """
    live = {}
    for tx in token_txs:
        sym = tx.get("tokenSymbol", "")
        try:
            dec = int(tx.get("tokenDecimal", -1) or -1)
        except (ValueError, TypeError):
            dec = -1
        if sym and dec >= 0:
            live[sym] = dec  # 链上数据最准，直接覆盖

    # 合并：链上数据优先，已知表补充
    result = dict(TOKEN_DECIMALS_DEFAULT)
    result.update(live)
    return result


def fmt_token_amount(raw_value: int, symbol: str, decimals_map: dict) -> str:
    """
    把 raw wei 值换算成可读的 token 数量字符串
    """
    dec = decimals_map.get(symbol, 18)
    if dec < 0: dec = 18

    if raw_value == 0:
        return f"0 {symbol}"

    try:
        val = raw_value / (10 ** dec)
    except Exception:
        return f"{raw_value} {symbol} (raw)"

    if val >= 1_000_000_000_000:
        return f"{val/1_000_000_000_000:.4f}T {symbol}"
    elif val >= 1_000_000_000:
        return f"{val/1_000_000_000:.4f}B {symbol}"
    elif val >= 1_000_000:
        return f"{val/1_000_000:.4f}M {symbol}"
    elif val >= 1_000:
        return f"{val:,.2f} {symbol}"
    elif val >= 0.0001:
        return f"{val:.6f} {symbol}"
    else:
        return f"{val:.2e} {symbol}"


SANCTIONED_EXCHANGES = {
    "0x6f6b4e9b7d4f3aca2e9e0afe7f4c0bae9e4e4e4e": "Garantex",
    "0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a": "Sinbad.io",
    "0x7f367cc41522ce07553e823bf3be79a889debe1b": "Blender.io",
}

TRANSPARENT_BRIDGES = {
    "0x1116898dda4015ed8ddefb84b6e8bc24528af2d8": "Harmony Bridge",
    "0x40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf": "Polygon Bridge",
    "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1": "Optimism Bridge",
    "0x3ee18b2214aff97000d974cf647e7c347e8fa585": "Wormhole Bridge",
}

OPAQUE_BRIDGES = {
    "0x8eb2e16f1f0f98f7e6c7a0929e0e7c4b5c6d7a8b": "Arbitrum Bridge",
    "0x9ad122c22b14202b4490edaf288fdb3c7cb3ff5e": "Railgun",
}

KNOWN_CEX = {
    "0x28c6c06298d514db089934071355e5743bf21d60": "Binance 热钱包",
    "0x21a31ee1afc51d94c2efee98d4c2d258c33d8b61": "Binance 冷钱包",
    "0xf977814e90da44bfa03b6295a0616a897441acec": "Binance 冷钱包2",
    "0xbe0eb53f46cd790cd13851d5eff43d12404d33e8": "Binance 冷钱包3",
    "0x0d0707963952f2fba59dd06f2b425ace40b492fe": "Gate.io",
    "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b": "OKX",
    "0x1b3cb81e51011b549d78bf720b0d924ac763a7c2": "Coinbase",
    "0x503828976d22510aad0201ac7ec88293211d23da": "Coinbase 冷钱包",
}


def score(address, nodes, edges, detector_results, eth_txs=None):
    addr = address.lower()
    breakdown = {}
    total = 0

    # 1. 跳数分
    hop_score, hop_detail = _hop_score(addr, nodes, edges)
    total += hop_score
    if hop_score > 0:
        breakdown["hop_distance"] = {"score": hop_score, "detail": hop_detail}

    # 2. 叠加分
    addons = _addon_scores(addr, nodes, edges, detector_results, eth_txs)
    for key, item in addons.items():
        if item["score"] > 0:
            breakdown[key] = item
            total += item["score"]

    # 3. 污染率
    from graph import calculate_taint
    taint = calculate_taint(addr, nodes, edges)

    # 4. 等级
    direct_hit = hop_detail.get("direct_hit", False)
    if total >= 100 or direct_hit:
        risk_level = "CRITICAL"
    elif total >= 60:
        risk_level = "HIGH"
    elif total >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # 5. 触发列表
    triggered = []
    for name, result in detector_results.items():
        if isinstance(result, dict) and result.get("detected"):
            triggered.append({
                "detector": name,
                "severity": result.get("severity", "MEDIUM"),
                "summary":  result.get("summary", ""),
            })
    triggered.sort(key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x["severity"],4))

    display_score = min(100, total)

    # 6. 审计
    audit = audit_fund_flow(addr, nodes, edges, eth_txs)

    return {
        "address":         addr,
        "risk_level":      risk_level,
        "risk_score":      display_score,
        "raw_score":       total,
        "taint_rate":      taint,
        "triggered":       triggered,
        "score_breakdown": breakdown,
        "audit":           audit,
        "summary": f"{risk_level} | 风险分 {display_score}/100 | 污染率 {taint}% | {len(triggered)} 手法命中",
    }


def _hop_score(addr, nodes, edges):
    """BFS 找最近黑名单距离"""
    nb = {}
    for (f, t, v, ts, typ) in edges:
        nb.setdefault(f, set()).add(t)
        nb.setdefault(t, set()).add(f)

    visited  = {addr}
    frontier = {addr}
    detail   = {"direct_hit": False, "hops": {}}

    for hop in range(1, 4):
        nxt = set()
        for node in frontier:
            for n in nb.get(node, set()):
                if n not in visited:
                    nxt.add(n)
                    visited.add(n)

        bl = [n for n in nxt if n in BLACKLIST or n in KNOWN_MIXERS]
        if bl:
            detail["hops"][hop] = bl[:5]
            if hop == 1:
                detail["direct_hit"] = True

        frontier = nxt
        if not frontier:
            break

    s = 0
    if detail["hops"].get(1): s = max(s, 100)
    if detail["hops"].get(2): s = max(s, 50)
    if detail["hops"].get(3): s = max(s, 25)

    return s, detail


def _addon_scores(addr, nodes, edges, detector_results, eth_txs):
    addons = {}

    # 混币器 +30
    mx = detector_results.get("mixer", {})
    if mx.get("detected"):
        cnt = mx.get("results", {}).get("mixer_interactions", {}).get("count", 1)
        addons["mixer"] = {"score": 30, "label": "混币器交互", "detail": f"{cnt} 次"}

    # 主动/被动黑名单
    rt = detector_results.get("reverse_taint", {})
    if rt.get("detected"):
        ac = rt.get("active_count", 0)
        pc = rt.get("passive_count", 0)
        if ac > 2:
            addons["active_bl_multi"]  = {"score": 40, "label": "主动转出给黑名单 >2个", "detail": f"{ac} 次"}
        elif ac == 1:
            addons["active_bl_single"] = {"score": 20, "label": "主动转出给黑名单 =1个", "detail": "1 次"}
        if pc > 2:
            addons["passive_bl_multi"] = {"score": 10, "label": "被动收到黑名单 >2个", "detail": f"{pc} 次"}
        elif pc == 1:
            addons["passive_bl_single"]= {"score": 5,  "label": "被动收到黑名单 =1个", "detail": "1 次"}

    # OFAC制裁交易所 +25
    sx = [a for a in nodes if a in SANCTIONED_EXCHANGES]
    if sx:
        addons["sanctioned_ex"] = {"score": 25, "label": "OFAC制裁交易所",
                                    "detail": str([SANCTIONED_EXCHANGES[a] for a in sx])}

    # 不透明桥 +20
    ob = [a for a in nodes if a in OPAQUE_BRIDGES]
    if ob:
        addons["opaque_bridge"] = {"score": 20, "label": "不透明跨链桥",
                                    "detail": str([OPAQUE_BRIDGES[a] for a in ob])}

    # 透明桥
    tb = [a for a in nodes if a in TRANSPARENT_BRIDGES]
    if tb:
        peers = set()
        for (f, t, v, ts, typ) in edges:
            if f in tb: peers.add(t)
            if t in tb: peers.add(f)
        bl_peers = [p for p in peers if p in BLACKLIST or p in KNOWN_MIXERS]
        if bl_peers:
            addons["transparent_bridge_bl"] = {"score": 15, "label": "透明桥+黑名单关联",
                                                "detail": str(bl_peers[:3])}
        else:
            addons["transparent_bridge"] = {"score": 5, "label": "透明桥（无黑名单）",
                                             "detail": str([TRANSPARENT_BRIDGES[a] for a in tb])}

    # Smurfing +12
    sm = detector_results.get("smurfing", {})
    if sm.get("detected"):
        addons["smurfing"] = {"score": 12, "label": "Smurfing拆单", "detail": sm.get("summary","")}

    # 猪杀盘 +15
    pg = detector_results.get("pig_butchering", {})
    if pg.get("detected"):
        addons["pig_butchering"] = {"score": 15, "label": "猪杀盘三段式", "detail": pg.get("summary","")}

    # DeFi +10
    df = detector_results.get("defi", {})
    if df.get("detected"):
        addons["defi"] = {"score": 10, "label": "DeFi滥用", "detail": df.get("summary","")}

    # NFT +8
    nft = detector_results.get("nft", {})
    if nft.get("detected"):
        addons["nft"] = {"score": 8, "label": "NFT洗钱", "detail": nft.get("summary","")}

    return addons


def audit_fund_flow(addr, nodes, edges, token_txs=None):
    """审计资金进出已知实体（CEX + Mixer）的差额"""
    from config import KNOWN_MIXERS, KNOWN_GAMBLING

    decimals_map = get_token_decimals_map(token_txs or [])

    ALL = {}
    ALL.update({a: ("CEX",      l) for a, l in KNOWN_CEX.items()})
    ALL.update({a: ("Mixer",    l) for a, l in KNOWN_MIXERS.items()})
    ALL.update({a: ("Gambling", l) for a, l in KNOWN_GAMBLING.items()})

    addr = addr.lower()
    flows = {}

    for (f, t, v, ts, typ) in edges:
        for entity_addr, (etype, label) in ALL.items():
            if f == addr and t == entity_addr:
                flows.setdefault(entity_addr, {"name": label, "type": etype,
                    "sent": 0, "recv": 0, "tokens_sent": [], "tokens_recv": [],
                    "token_decimals": {}})
                flows[entity_addr]["sent"] += v
                flows[entity_addr]["tokens_sent"].append(typ)
                if typ not in ("ETH", "INT"):
                    flows[entity_addr]["token_decimals"][typ] = decimals_map.get(typ, 18)
            if t == addr and f == entity_addr:
                flows.setdefault(entity_addr, {"name": label, "type": etype,
                    "sent": 0, "recv": 0, "tokens_sent": [], "tokens_recv": [],
                    "token_decimals": {}})
                flows[entity_addr]["recv"] += v
                flows[entity_addr]["tokens_recv"].append(typ)
                if typ not in ("ETH", "INT"):
                    flows[entity_addr]["token_decimals"][typ] = decimals_map.get(typ, 18)

    suspicious = []
    for ea, fl in flows.items():
        fl["diff"]        = fl["recv"] - fl["sent"]
        fl["address"]     = ea
        fl["sent_tokens"] = list(set(fl["tokens_sent"]))
        fl["recv_tokens"] = list(set(fl["tokens_recv"]))
        token_change      = set(fl["tokens_sent"]) != set(fl["tokens_recv"])
        fl["token_change"]= token_change

        if (fl["type"] == "Mixer"
                or (fl["type"] == "CEX" and fl["diff"] > 0 and fl["sent"] > 0)
                or (token_change and (fl["sent"] > 0 or fl["recv"] > 0))):
            # build human-readable amounts
            tok_dec = fl.get("token_decimals", {})
            is_eth_only = not fl["sent_tokens"] and not fl["recv_tokens"]

            if is_eth_only:
                sent_fmt = f'{fl["sent"]/1e18:.6f} ETH'
                recv_fmt = f'{fl["recv"]/1e18:.6f} ETH'
                diff_fmt = f'{abs(fl["diff"])/1e18:.6f} ETH'
            else:
                # use most common sent token for display
                primary = fl["sent_tokens"][0] if fl["sent_tokens"] else (fl["recv_tokens"][0] if fl["recv_tokens"] else "?")
                dec = tok_dec.get(primary, decimals_map.get(primary, 18))
                sent_fmt = fmt_token_amount(fl["sent"], primary, tok_dec)
                recv_fmt = fmt_token_amount(fl["recv"], primary, tok_dec)
                diff_fmt = fmt_token_amount(abs(fl["diff"]), primary, tok_dec)

            suspicious.append({
                "entity":        fl["name"],
                "type":          fl["type"],
                "address":       ea,
                "sent":          fl["sent"],
                "received":      fl["recv"],
                "diff":          fl["diff"],
                "sent_fmt":      sent_fmt,
                "received_fmt":  recv_fmt,
                "diff_fmt":      diff_fmt,
                "token_change":  token_change,
                "sent_tokens":   fl["sent_tokens"],
                "recv_tokens":   fl["recv_tokens"],
                "token_decimals":tok_dec,
                "risk":          "HIGH" if fl["type"] == "Mixer" else "MEDIUM",
            })

    suspicious.sort(key=lambda x: {"HIGH":0,"MEDIUM":1}.get(x["risk"],2))

    return {
        "entities":   flows,
        "suspicious": suspicious,
        "summary": (f"与 {len(flows)} 个已知实体往来，{len(suspicious)} 个可疑"
                    if flows else "未检测到与已知实体的资金往来"),
    }


def make_report_text(score_result, audit_result=None):
    """生成可读报告文本"""
    r     = score_result
    level = r["risk_level"]
    score_val = r["risk_score"]
    BADGE = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
    lines = [
        "="*55,
        " ChainSentinel 风险评估报告",
        "="*55,
        f" 地址:     {r['address']}",
        f" 风险等级: {BADGE.get(level,'')} {level}",
        f" 风险评分: {score_val} / 100",
        f" 原始得分: {r.get('raw_score', score_val)}",
        f" 污染率:   {r['taint_rate']}%",
        "─"*55,
        " 评分明细:",
    ]
    for key, item in r.get("score_breakdown", {}).items():
        lines.append(f"   +{item['score']:>3}  {item.get('label', key)}")
        if item.get("detail"):
            d = str(item["detail"])
            lines.append(f"         → {d[:70]}")
    lines += ["─"*55, " 命中手法:"]
    for t in r.get("triggered", []):
        b = BADGE.get(t["severity"],"🟡")
        lines.append(f"   {b} [{t['severity']}] {t['detector']}: {t.get('summary','')[:55]}")

    audit = audit_result or r.get("audit", {})
    if audit and audit.get("suspicious"):
        lines += ["─"*55, " 资金审计（可疑实体）:"]
        for s in audit["suspicious"][:5]:
            lines.append(f"   ⚠ {s['entity']} ({s['type']})")
            lines.append(f"     存入 {s['sent']:,} wei → 取出 {s['received']:,} wei")
            if s["token_change"]:
                lines.append(f"     ⚑ 代币变化: {s['sent_tokens']} → {s['recv_tokens']}")

    conclusions = {
        "CRITICAL": "结论：极高风险，建议立即冻结并提交 STR 报告。",
        "HIGH":     "结论：高风险，建议暂停业务并启动人工复核。",
        "MEDIUM":   "结论：可疑行为，建议加强监控收集更多证据。",
        "LOW":      "结论：未见明显风险，建议持续监控。",
    }
    lines += ["="*55, f" {conclusions.get(level,'')}", "="*55]
    return "\n".join(lines)
