# ============================================================
# crosschain_btc.py
# 跨链桥 + BTC 链 三合一追踪分析
# 用法：
#   python crosschain_btc.py <ETH地址>
#   python crosschain_btc.py btc <BTC地址>
# ============================================================

import sys, json, os, time, requests
from datetime import datetime
from collections import defaultdict

# ── 路径 ────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config   import ETHERSCAN_KEY, ETHERSCAN_BASE, ETHERSCAN_CHAIN, BLACKLIST, KNOWN_MIXERS
from collector import fetch_txlist, fetch_tokentx

# ============================================================
# 配置
# ============================================================

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports")

BTC_BASE = "https://blockstream.info/api"

# 透明桥
TRANSPARENT_BRIDGES = {
    "0x1116898dda4015ed8ddefb84b6e8bc24528af2d8": "Harmony Horizon Bridge",
    "0x40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf": "Polygon PoS Bridge",
    "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1": "Optimism Bridge",
    "0x3ee18b2214aff97000d974cf647e7c347e8fa585": "Wormhole Bridge",
    "0x5a58505a96d1dbf8df91cb21b54419fc36e93fde": "Hop Protocol",
    "0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f": "Arbitrum Inbox",
    "0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a": "Arbitrum Bridge",
}

# 不透明桥
OPAQUE_BRIDGES = {
    "0x9ad122c22b14202b4490edaf288fdb3c7cb3ff5e": "Railgun",
    "0x2796317b0ff8538f1925e9b2b8c75c955b9c6bf2": "Synapse Bridge",
    "0xd31a59c85ae9d8edefec411d448f90841571b89c": "Wanchain Bridge",
    "0x48b62137edfa95a428d35c09e44256a739f6b557": "Orbiter Finance",
}

# 制裁桥
SANCTIONED_BRIDGES = {
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": "Tornado Cash Router (OFAC)",
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado Cash 1ETH (OFAC)",
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash Deployer (OFAC)",
}

# 已知 BTC 跨链桥入口（RenBridge、tBTC 等）
CROSSCHAIN_BTC_GATEWAYS = {
    "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h": "RenBridge BTC Gateway",
    "3FupZp77ySr7jwoLYEJ9Ra3KoQnBc13QFN":          "tBTC Deposit",
    "3BMEX7r4yQJE9f4RC1stFBPXAn8sYoELRR":          "WBTC Custody (BitGo)",
}

# BTC 黑名单
BTC_BLACKLIST = {
    "1Lw6QLShKVbWQQB8FpMBDtHqNqEbdqEGE3":          "Lazarus Group BTC",
    "1Kuf2Rd8mDyAViwBozGTNYnvWL8uDUMFMr":          "Lazarus Group BTC 2",
    "1CdpoB3QNbKdnFJmg7mjcq1hWCcVHhKf3s":          "Ronin Bridge BTC Attacker",
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh":  "Lazarus BTC bech32",
}

BTC_MIXERS = {
    "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s": "Chipmixer",
    "1FKDjd6vRKKHiRRHjHR3YVPbNZQxrBc3HG": "Wasabi Wallet",
    "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9wnkny": "JoinMarket",
}

BADGE = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

# ============================================================
# ETH 数据拉取（只拉目标地址本身，快）
# ============================================================

def fetch_eth_fast(address):
    """快速拉取目标 ETH 地址的普通交易 + ERC20，不做 BFS"""
    addr = address.lower()
    print(f"  ▸ 拉取 ETH 普通交易...")
    eth = fetch_txlist(addr)
    print(f"    → {len(eth)} 笔")
    time.sleep(0.3)

    print(f"  ▸ 拉取 ERC20 转账...")
    tok = fetch_tokentx(addr)
    print(f"    → {len(tok)} 笔")
    time.sleep(0.3)

    return eth, tok


# ============================================================
# ETH 跨链桥分析
# ============================================================

def analyze_eth_bridges(address, eth_txs, tok_txs):
    """
    分析目标地址与跨链桥的交互
    返回：bridge_flows, detected_types, risk_level
    """
    addr = address.lower()
    ALL_BRIDGES = {**TRANSPARENT_BRIDGES, **OPAQUE_BRIDGES, **SANCTIONED_BRIDGES}

    # 收集所有对方地址
    counterparts = set()
    for tx in eth_txs:
        f = tx.get("from", "").lower()
        t = tx.get("to",   "").lower()
        if f == addr: counterparts.add(t)
        if t == addr: counterparts.add(f)
    for tx in tok_txs:
        f = tx.get("from", "").lower()
        t = tx.get("to",   "").lower()
        if f == addr: counterparts.add(t)
        if t == addr: counterparts.add(f)

    bridge_flows = []
    detected_sanctions = []

    for bridge_addr, bridge_name in ALL_BRIDGES.items():
        if bridge_addr not in counterparts:
            continue

        # 统计资金流
        sent = sum(
            int(tx.get("value", 0))
            for tx in eth_txs
            if tx.get("from", "").lower() == addr
            and tx.get("to",   "").lower() == bridge_addr
        )
        recv = sum(
            int(tx.get("value", 0))
            for tx in eth_txs
            if tx.get("to",   "").lower() == addr
            and tx.get("from","").lower() == bridge_addr
        )
        tx_count = sum(
            1 for tx in eth_txs
            if tx.get("from","").lower() in (addr, bridge_addr)
            and tx.get("to",  "").lower() in (addr, bridge_addr)
        )

        btype = ("sanctioned" if bridge_addr in SANCTIONED_BRIDGES
                 else "opaque" if bridge_addr in OPAQUE_BRIDGES
                 else "transparent")
        severity = ("CRITICAL" if btype == "sanctioned"
                    else "HIGH" if btype == "opaque"
                    else "MEDIUM")

        entry = {
            "bridge":    bridge_name,
            "address":   bridge_addr,
            "type":      btype,
            "severity":  severity,
            "sent_wei":  sent,
            "recv_wei":  recv,
            "tx_count":  tx_count,
        }
        bridge_flows.append(entry)

        if btype == "sanctioned":
            detected_sanctions.append(bridge_name)

    # 整体风险
    if any(b["severity"] == "CRITICAL" for b in bridge_flows):
        overall = "CRITICAL"
    elif any(b["severity"] == "HIGH" for b in bridge_flows):
        overall = "HIGH"
    elif bridge_flows:
        overall = "MEDIUM"
    else:
        overall = "CLEAN"

    return bridge_flows, detected_sanctions, overall


# ============================================================
# 寻找 BTC 关联地址（通过已知跨链桥 gateway）
# ============================================================

def find_btc_addresses_from_eth(address, eth_txs, tok_txs):
    """
    从 ETH 交易中找出可能关联的 BTC 地址
    方式：
    1. 对方地址是已知跨链桥 BTC gateway
    2. 交易 input data 里嵌入的 BTC 地址（OP_RETURN）
    """
    addr = address.lower()
    hints = []

    # 找目标地址与 BTC gateway 的交互
    for tx in eth_txs:
        f = tx.get("from", "").lower()
        t = tx.get("to",   "").lower()
        counterpart = t if f == addr else (f if t == addr else None)
        if counterpart and counterpart in CROSSCHAIN_BTC_GATEWAYS:
            hints.append({
                "type":        "gateway_interaction",
                "gateway":     CROSSCHAIN_BTC_GATEWAYS[counterpart],
                "gateway_eth": counterpart,
                "txhash":      tx.get("hash", ""),
                "timestamp":   tx.get("timeStamp", ""),
                "note":        "ETH→BTC 跨链桥入口交互，需人工确认对应 BTC 地址",
            })

    # 找 input data 里的 BTC 地址（简单启发式）
    for tx in eth_txs:
        inp = tx.get("input", "")
        if len(inp) > 10:
            # OP_RETURN 通常以 6a 开头
            decoded = _try_decode_btc_addr(inp)
            if decoded:
                hints.append({
                    "type":      "op_return_embed",
                    "btc_addr":  decoded,
                    "txhash":    tx.get("hash", ""),
                    "timestamp": tx.get("timeStamp", ""),
                    "note":      "交易 input data 中发现疑似 BTC 地址",
                })

    return hints


def _try_decode_btc_addr(hex_input):
    """
    简单启发式：尝试在 input data 里找 BTC 地址格式字符串
    BTC 地址 = 26-35 位 Base58 / bech32 字符
    """
    import re
    try:
        # 尝试 hex 解码
        raw = bytes.fromhex(hex_input.replace("0x", ""))
        text = raw.decode("ascii", errors="ignore")
        # 匹配 BTC 地址格式
        pattern = r'\b(bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'
        matches = re.findall(pattern, text)
        return matches[0] if matches else None
    except:
        return None


# ============================================================
# BTC 链分析
# ============================================================

def _btc_get(path, retry=3):
    url = f"{BTC_BASE}/{path}"
    sess = requests.Session()
    sess.headers.update({"User-Agent": "ChainSentinel/2.0"})
    for i in range(retry):
        try:
            r = sess.get(url, timeout=20)
            if r.status_code == 200:
                return r.json()
            if r.status_code == 429:
                print(f"    [BTC限速] 等待 {2**i}s...")
                time.sleep(2 ** i)
        except Exception as e:
            time.sleep(1)
    return None


def analyze_btc_address(btc_address, depth=1):
    """
    分析 BTC 地址
    depth=1: 只分析目标地址
    depth=2: 追踪一跳来源
    """
    print(f"\n  ▸ BTC 地址基本信息...")
    info = _btc_get(f"address/{btc_address}")
    if not info:
        return {"error": "无法获取 BTC 地址信息（API 超时或地址无效）"}

    stats = info.get("chain_stats", {})
    addr_info = {
        "address":        btc_address,
        "tx_count":       stats.get("tx_count", 0),
        "funded_sum":     stats.get("funded_txo_sum", 0),
        "spent_sum":      stats.get("spent_txo_sum", 0),
        "balance_sat":    stats.get("funded_txo_sum", 0) - stats.get("spent_txo_sum", 0),
        "balance_btc":    (stats.get("funded_txo_sum", 0) - stats.get("spent_txo_sum", 0)) / 1e8,
    }
    print(f"    → 交易数: {addr_info['tx_count']} | 余额: {addr_info['balance_btc']:.8f} BTC")

    # 拉交易
    print(f"  ▸ 拉取 BTC 交易（最近50笔）...")
    raw_txs = []
    last_tx = None
    while len(raw_txs) < 50:
        path = f"address/{btc_address}/txs"
        if last_tx:
            path += f"/chain/{last_tx}"
        batch = _btc_get(path)
        if not batch:
            break
        raw_txs.extend(batch)
        if len(batch) < 25:
            break
        last_tx = batch[-1]["txid"]
        time.sleep(0.3)
    print(f"    → 拉取 {len(raw_txs)} 笔")

    # 黑名单检测
    bl_hits, mixer_hits = [], []
    all_counterparts = set()

    for tx in raw_txs:
        # 输入地址
        for vin in tx.get("vin", []):
            a = vin.get("prevout", {}).get("scriptpubkey_address", "")
            if a and a != btc_address:
                all_counterparts.add(a)
        # 输出地址
        for vout in tx.get("vout", []):
            a = vout.get("scriptpubkey_address", "")
            if a and a != btc_address:
                all_counterparts.add(a)

    for cp in all_counterparts:
        if cp in BTC_BLACKLIST:
            bl_hits.append({"address": cp, "label": BTC_BLACKLIST[cp]})
        if cp in BTC_MIXERS:
            mixer_hits.append({"address": cp, "label": BTC_MIXERS[cp]})

    # 是否自身在黑名单
    self_blacklisted = btc_address in BTC_BLACKLIST

    # Peel Chain 检测（简单版）
    peel_chain = _detect_btc_peel(raw_txs, btc_address)

    # 风险评分
    risk_score = 0
    if self_blacklisted:       risk_score += 100
    if bl_hits:                risk_score += 50
    if mixer_hits:             risk_score += 30
    if peel_chain["detected"]: risk_score += 25
    risk_score = min(100, risk_score)

    risk_level = ("CRITICAL" if risk_score >= 100 or self_blacklisted
                  else "HIGH"   if risk_score >= 60
                  else "MEDIUM" if risk_score >= 30
                  else "LOW")

    return {
        "address_info":    addr_info,
        "risk_score":      risk_score,
        "risk_level":      risk_level,
        "self_blacklisted": self_blacklisted,
        "blacklist_hits":  bl_hits,
        "mixer_hits":      mixer_hits,
        "peel_chain":      peel_chain,
        "counterpart_count": len(all_counterparts),
        "raw_tx_count":    len(raw_txs),
    }


def _detect_btc_peel(raw_txs, address):
    """简单 Peel Chain 检测"""
    # 找单输入单输出的交易链
    single_io = []
    for tx in raw_txs:
        inputs  = [v.get("prevout", {}).get("scriptpubkey_address", "") for v in tx.get("vin", [])]
        outputs = [v.get("scriptpubkey_address", "") for v in tx.get("vout", [])]
        inputs  = [a for a in inputs if a]
        outputs = [a for a in outputs if a]
        if len(inputs) == 1 and len(outputs) <= 2:
            single_io.append(tx)

    if len(single_io) >= 5:
        return {
            "detected": True,
            "severity": "HIGH" if len(single_io) >= 10 else "MEDIUM",
            "count":    len(single_io),
            "summary":  f"发现 {len(single_io)} 笔单输入交易，疑似 Peel Chain",
        }
    return {"detected": False}


# ============================================================
# 主流程：ETH + 跨链桥 + BTC 三合一
# ============================================================

def run_crosschain_analysis(eth_address, btc_address=None):
    addr = eth_address.lower()
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{'='*60}")
    print(f"  ChainSentinel — 跨链追踪分析 v2")
    print(f"{'='*60}")
    print(f"  ETH 地址: {eth_address}")
    if btc_address:
        print(f"  BTC 地址: {btc_address}")
    print(f"  时间:     {ts}")
    print(f"{'='*60}\n")

    report = {
        "meta": {
            "eth_address": addr,
            "btc_address": btc_address,
            "analyzed_at": datetime.now().isoformat(),
            "engine":      "ChainSentinel CrossChain v2",
        }
    }

    # ── Step 1: ETH 快速采集 ─────────────────────────────
    print(">>> Step 1: ETH 数据采集（单地址快速模式）")
    eth_txs, tok_txs = fetch_eth_fast(addr)

    # ── Step 2: ETH 黑名单跳数检测 ──────────────────────
    print("\n>>> Step 2: ETH 黑名单关联检测")
    eth_counterparts = set()
    for tx in eth_txs + tok_txs:
        f = tx.get("from","").lower()
        t = tx.get("to",  "").lower()
        if f == addr: eth_counterparts.add(t)
        if t == addr: eth_counterparts.add(f)

    direct_bl = [cp for cp in eth_counterparts if cp in BLACKLIST or cp in KNOWN_MIXERS]
    if direct_bl:
        print(f"  🔴 直接接触黑名单地址 ({len(direct_bl)} 个):")
        for a in direct_bl[:5]:
            label = BLACKLIST.get(a) or KNOWN_MIXERS.get(a, "Unknown")
            print(f"     {a[:18]}... → {label}")
    else:
        print(f"  ✅ 未发现直接黑名单关联")

    report["eth_blacklist"] = {
        "direct_hits":   direct_bl,
        "hit_count":     len(direct_bl),
        "counterparts":  len(eth_counterparts),
    }

    # ── Step 3: 跨链桥检测 ──────────────────────────────
    print("\n>>> Step 3: 跨链桥检测")
    bridge_flows, sanctions, bridge_risk = analyze_eth_bridges(addr, eth_txs, tok_txs)

    if bridge_flows:
        print(f"  发现 {len(bridge_flows)} 个跨链桥交互:")
        for b in bridge_flows:
            icon = BADGE.get(b["severity"], "🟡")
            print(f"  {icon} [{b['severity']}] {b['bridge']} ({b['type']})")
            print(f"       发出: {b['sent_wei']/1e18:.6f} ETH  |  收到: {b['recv_wei']/1e18:.6f} ETH  |  {b['tx_count']} 笔")
        if sanctions:
            print(f"\n  ⚠️  命中制裁桥: {', '.join(sanctions)}")
    else:
        print(f"  ✅ 未发现跨链桥交互")

    report["bridge_analysis"] = {
        "risk_level":    bridge_risk,
        "bridge_flows":  bridge_flows,
        "sanctions":     sanctions,
    }

    # ── Step 4: 寻找 BTC 关联线索 ───────────────────────
    print("\n>>> Step 4: BTC 地址关联线索挖掘")
    btc_hints = find_btc_addresses_from_eth(addr, eth_txs, tok_txs)

    if btc_hints:
        print(f"  发现 {len(btc_hints)} 条 BTC 关联线索:")
        for h in btc_hints:
            print(f"  ▸ [{h['type']}] {h.get('gateway', h.get('btc_addr', ''))}")
            print(f"    → {h['note']}")
    else:
        print(f"  未发现自动可识别的 BTC 关联（需人工结合跨链桥记录查询）")

    report["btc_hints"] = btc_hints

    # ── Step 5: BTC 链分析 ──────────────────────────────
    btc_result = None
    if btc_address:
        print(f"\n>>> Step 5: BTC 链分析 ({btc_address[:20]}...)")
        btc_result = analyze_btc_address(btc_address)

        level = btc_result.get("risk_level", "LOW")
        score = btc_result.get("risk_score", 0)
        info  = btc_result.get("address_info", {})

        print(f"\n  BTC 风险结果:")
        print(f"  {BADGE.get(level,'')} 风险等级: {level} | 评分: {score}/100")
        print(f"  余额:   {info.get('balance_btc', 0):.8f} BTC")
        print(f"  交易数: {info.get('tx_count', 0)}")

        if btc_result.get("blacklist_hits"):
            print(f"  🔴 黑名单关联 ({len(btc_result['blacklist_hits'])} 个):")
            for h in btc_result["blacklist_hits"]:
                print(f"     {h['address'][:20]}... → {h['label']}")
        if btc_result.get("mixer_hits"):
            print(f"  🟠 混币器关联 ({len(btc_result['mixer_hits'])} 个):")
            for h in btc_result["mixer_hits"]:
                print(f"     {h['address'][:20]}... → {h['label']}")
        if btc_result.get("peel_chain", {}).get("detected"):
            pc = btc_result["peel_chain"]
            print(f"  🟠 Peel Chain: {pc.get('summary','')}")
    else:
        print(f"\n>>> Step 5: BTC 链分析（跳过 — 未提供 BTC 地址）")
        print(f"  💡 如有关联 BTC 地址，可运行:")
        print(f"     python crosschain_btc.py {eth_address} <BTC地址>")

    report["btc_analysis"] = btc_result

    # ── 综合风险评估 ─────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  综合风险评估")
    print(f"{'='*60}")

    risks = []
    if direct_bl:                        risks.append("CRITICAL")
    if bridge_risk == "CRITICAL":        risks.append("CRITICAL")
    elif bridge_risk == "HIGH":          risks.append("HIGH")
    elif bridge_risk == "MEDIUM":        risks.append("MEDIUM")
    if btc_result:
        risks.append(btc_result.get("risk_level", "LOW"))

    final_risk = ("CRITICAL" if "CRITICAL" in risks
                  else "HIGH"   if "HIGH"     in risks
                  else "MEDIUM" if "MEDIUM"   in risks
                  else "LOW")

    print(f"  {BADGE.get(final_risk,'')} 最终风险等级: {final_risk}")
    print(f"\n  风险来源:")
    if direct_bl:
        print(f"    🔴 ETH 直接接触黑名单: {len(direct_bl)} 个地址")
    if bridge_flows:
        for b in bridge_flows:
            print(f"    {BADGE.get(b['severity'],'')} 跨链桥: {b['bridge']} ({b['type']})")
    if btc_result and btc_result.get("risk_level") not in ("LOW", None):
        print(f"    {BADGE.get(btc_result['risk_level'],'')} BTC链: {btc_result.get('risk_level')} (评分 {btc_result.get('risk_score',0)}/100)")
    if not direct_bl and not bridge_flows and (not btc_result or btc_result.get("risk_level") == "LOW"):
        print(f"    ✅ 未发现明显风险")

    conclusions = {
        "CRITICAL": "结论：极高风险，建议立即冻结并提交 STR 报告。",
        "HIGH":     "结论：高风险，建议暂停业务并启动人工复核。",
        "MEDIUM":   "结论：可疑行为，建议加强监控收集更多证据。",
        "LOW":      "结论：未见明显风险，建议持续监控。",
    }
    print(f"\n  {conclusions.get(final_risk,'')}")
    print(f"{'='*60}\n")

    report["final_risk"] = {
        "risk_level": final_risk,
        "conclusion": conclusions.get(final_risk, ""),
    }

    # ── 保存 JSON ────────────────────────────────────────
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = f"crosschain_{addr[:10]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_path = os.path.join(OUTPUT_DIR, filename)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    print(f"  📄 报告已保存 → {out_path}\n")

    return report


# ============================================================
# 单独分析 BTC 地址
# ============================================================

def run_btc_only(btc_address):
    print(f"\n{'='*60}")
    print(f"  ChainSentinel — BTC 地址分析")
    print(f"{'='*60}")
    print(f"  BTC 地址: {btc_address}")
    print(f"  时间:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    result = analyze_btc_address(btc_address, depth=2)

    if "error" in result:
        print(f"  ❌ 错误: {result['error']}")
        return

    level = result.get("risk_level", "LOW")
    score = result.get("risk_score", 0)
    info  = result.get("address_info", {})

    print(f"\n  {BADGE.get(level,'')} 风险等级: {level} | 评分: {score}/100")
    print(f"  余额:   {info.get('balance_btc', 0):.8f} BTC")
    print(f"  交易数: {info.get('tx_count', 0)}")
    print(f"  交易对手地址数: {result.get('counterpart_count', 0)}")

    if result.get("blacklist_hits"):
        print(f"\n  🔴 黑名单关联:")
        for h in result["blacklist_hits"]:
            print(f"     {h['address']} → {h['label']}")
    if result.get("mixer_hits"):
        print(f"\n  🟠 混币器关联:")
        for h in result["mixer_hits"]:
            print(f"     {h['address']} → {h['label']}")
    if result.get("peel_chain", {}).get("detected"):
        pc = result["peel_chain"]
        print(f"\n  🟠 Peel Chain 检测: {pc.get('summary','')}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = f"btc_{btc_address[:12]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_path = os.path.join(OUTPUT_DIR, filename)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"meta": {"btc_address": btc_address, "analyzed_at": datetime.now().isoformat()},
                   "btc_analysis": result}, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n  📄 报告已保存 → {out_path}\n")


# ============================================================
# 入口
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法:")
        print("  # ETH + 跨链桥 + BTC 三合一")
        print("  python crosschain_btc.py <ETH地址> [BTC地址]")
        print("")
        print("  # 只分析 BTC 地址")
        print("  python crosschain_btc.py btc <BTC地址>")
        print("")
        print("示例:")
        print("  python crosschain_btc.py 0x098B716B8Aaf21512996dC57EB0615e2383E2f96")
        print("  python crosschain_btc.py 0x098B716B8Aaf21512996dC57EB0615e2383E2f96 1Lw6QLShKVbWQQB8FpMBDtHqNqEbdqEGE3")
        print("  python crosschain_btc.py btc 1Lw6QLShKVbWQQB8FpMBDtHqNqEbdqEGE3")
        sys.exit(0)

    if sys.argv[1].lower() == "btc":
        if len(sys.argv) < 3:
            print("请提供 BTC 地址")
            sys.exit(1)
        run_btc_only(sys.argv[2])
    else:
        eth_addr = sys.argv[1]
        btc_addr = sys.argv[2] if len(sys.argv) > 2 else None
        run_crosschain_analysis(eth_addr, btc_addr)
