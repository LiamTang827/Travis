# ============================================================
# analyze.py — ChainSentinel 主入口 v3
# 新增：余额报告(balance)、法规映射(law)
# ============================================================

import sys, json, os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config    import DEFAULT_HOPS
from collector import collect_hops, summarize_tokens
from collector_v2 import fetch_all_with_method, save_to_db, init_db
from graph     import build_graph, merge_graphs, graph_to_json, graph_summary, tag_edges
from scorer    import score, make_report_text
from balance   import get_full_balance_report
from law       import generate_law_section, format_law_report_text
from tracer          import trace_full
from check_exchange  import run_exchange_check

from detectors import (
    d_blacklist, d_peel_chain, d_smurfing, d_fanout,
    d_bipartite, d_mixer, d_defi, d_nft, d_dusting,
    d_pig_butchering, d_reverse_taint, d_pagerank, d_lof,
    d_crosschain,
)


def tag_nodes_from_detectors(nodes, edges, detector_results):
    """把 detector 结果反标到节点上，给每个节点加 topo_tags list。"""
    for addr in nodes:
        nodes[addr].setdefault("topo_tags", [])

    # peel_chain
    peel = detector_results.get("peel_chain", {})
    if peel.get("detected"):
        for chain in peel.get("chains", []):
            for addr in chain:
                if addr in nodes:
                    nodes[addr]["topo_tags"].append("peel_chain")

    # fan_out hubs
    fanout = detector_results.get("fanout", {})
    if fanout.get("detected"):
        for h in fanout.get("hubs", []):
            addr = h["address"] if isinstance(h, dict) else h
            if addr in nodes:
                nodes[addr]["topo_tags"].append("fan_out_hub")

    # smurfing — 打标所有参与拆单的节点
    smurfing = detector_results.get("smurfing", {})
    if smurfing.get("detected"):
        repeated_vals = {p["value"] for p in smurfing.get("patterns", [])}
        for ef, et, ev, ets, etyp in edges:
            if ev in repeated_vals:
                if ef in nodes:
                    nodes[ef]["topo_tags"].append("smurfing")
                if et in nodes:
                    nodes[et]["topo_tags"].append("smurfing")

    # mixer 交互
    from config import KNOWN_MIXERS as _KM
    for ef, et, ev, ets, etyp in edges:
        if et in _KM and ef in nodes:
            nodes[ef]["topo_tags"].append("to_mixer")
        if ef in _KM and et in nodes:
            nodes[et]["topo_tags"].append("from_mixer")

    # 黑名单
    from config import BLACKLIST as _BL
    for addr in nodes:
        if addr in _BL:
            nodes[addr]["topo_tags"].append("blacklist")

    # 去重
    for addr in nodes:
        nodes[addr]["topo_tags"] = list(set(nodes[addr]["topo_tags"]))

    return nodes


def find_flow_destination(target_addr, nodes, edges, detector_results):
    """追踪资金最终流向终点（peel chain 末端 + fan-out 末端）"""
    addr = target_addr.lower()
    peel_destinations = []
    fanout_destinations = []

    def _label(a):
        n = nodes.get(a, {})
        if n.get("is_cex"):    return "CEX"
        if n.get("is_mixer"):  return "Mixer"
        if n.get("is_dex"):    return "DEX"
        if n.get("is_bridge"): return "Bridge"
        return "Unknown"

    # peel chain 终点
    peel = detector_results.get("peel_chain", {})
    if peel.get("detected"):
        for chain in peel.get("chains", []):
            if chain:
                end = chain[-1]
                peel_destinations.append({
                    "address": end,
                    "type": "peel_end",
                    "label": _label(end),
                    "hops": len(chain) - 1,
                })

    # fan-out 终点（hub 的所有出边终点）
    fanout = detector_results.get("fanout", {})
    if fanout.get("detected"):
        hub_addrs = {
            h["address"] if isinstance(h, dict) else h
            for h in fanout.get("hubs", [])
        }
        out_targets = set()
        for ef, et, ev, ets, etyp in edges:
            if ef in hub_addrs:
                out_targets.add(et)
        for t in out_targets:
            fanout_destinations.append({
                "address": t,
                "type": "fanout_end",
                "label": _label(t),
            })

    all_endpoints = peel_destinations + fanout_destinations
    # 去重（同地址只保留一条）
    seen = set()
    unique_eps = []
    for ep in all_endpoints:
        if ep["address"] not in seen:
            seen.add(ep["address"])
            unique_eps.append(ep)

    return {
        "peel_destinations":   peel_destinations,
        "fanout_destinations": fanout_destinations,
        "all_endpoints":       unique_eps,
    }


def analyze(address, hops=DEFAULT_HOPS, save_json=True, output_dir=None,
            include_btc=False):
    """
    分析一个以太坊地址
    include_btc: 是否同时检查关联 BTC 地址（慢，默认关闭）
    """
    addr = address.lower()

    print(f"\n{'='*55}")
    print(f" ChainSentinel — 地址风险分析 v3")
    print(f"{'='*55}")
    print(f" 地址: {address}")
    print(f" 采集深度: 1跳 (黑名单检测: {hops}跳内存BFS)")
    print(f" 时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}\n")

    # ── Step 1: ETH 数据采集 ──────────────────────────────
    # 数据采集固定1跳（只拉目标地址本身的交易）
    # 多跳黑名单检测在已建图上做内存BFS，不额外调API
    print(">>> Step 1: 数据采集 (ETH, 1跳)")
    eth, int_, tok, logs, visited = collect_hops(addr, hops=1)
    print(f"\n    采集完成: {len(visited)} 个地址")

    # ── Step 1b: 全量采集存库 ────────────────────────────
    print("\n>>> Step 1b: 全量采集 (getLogs + method → SQLite)")
    try:
        records = fetch_all_with_method(addr)
        conn = init_db()
        save_to_db(records, addr, conn)
        conn.close()
        print(f"    全量存库完成: {len(records)} 条记录")
    except Exception as e:
        print(f"    ⚠️  全量采集跳过: {e}")

    # ── Step 2: 建图 ──────────────────────────────────────
    print("\n>>> Step 2: 建图")
    nodes = {}
    edges = []
    for a in visited:
        a_eth = [tx for tx in eth  if tx.get("from","").lower()==a or tx.get("to","").lower()==a]
        a_int = [tx for tx in int_ if tx.get("from","").lower()==a or tx.get("to","").lower()==a]
        a_tok = [tx for tx in tok  if tx.get("from","").lower()==a or tx.get("to","").lower()==a]
        n, e  = build_graph(a_eth, a_int, a_tok)
        nodes, edges = merge_graphs(nodes, edges, n, e)

    edges = list({(f,t,v,ts,typ) for f,t,v,ts,typ in edges})
    edges.sort(key=lambda x: x[3])

    gs = graph_summary(nodes, edges)
    print(f"    节点: {gs['total_nodes']}  边: {gs['total_edges']}")

    # ── Step 2b: 余额报告 ────────────────────────────────
    print("\n>>> Step 2b: 余额 & 资金流水")
    balance_report = get_full_balance_report(addr, eth, tok)
    bal = balance_report["current"]
    flow = balance_report["fund_flow"]["eth"]
    print(f"    当前余额:  {bal['balance_eth']} ETH")
    print(f"    历史流入:  {flow['in_eth']} ETH ({flow['in_count']} 笔，{flow['unique_senders']} 个来源)")
    print(f"    历史流出:  {flow['out_eth']} ETH ({flow['out_count']} 笔，{flow['unique_receivers']} 个去向)")
    print(f"    净流量:    {flow['net_eth']} ETH")
    tok_in = balance_report["fund_flow"]["tokens"]["top_in"]
    if tok_in:
        print(f"    主要流入Token: " + " / ".join(f"{t['symbol']}" for t in tok_in[:3]))

    # ── Step 2c: BTC 采集（可选）─────────────────────────
    btc_result = None
    if include_btc:
        print("\n>>> Step 2c: BTC 链检测")
        btc_result = _run_btc_analysis(addr)

    # ── Step 3: 运行检测器 ────────────────────────────────
    print("\n>>> Step 3: 运行检测器")
    shared = dict(nodes=nodes, edges=edges, eth_txs=eth,
                  token_txs=tok, target_address=addr)

    _detectors = [
        ("blacklist",      d_blacklist),
        ("peel_chain",     d_peel_chain),
        ("smurfing",       d_smurfing),
        ("fanout",         d_fanout),
        ("bipartite",      d_bipartite),
        ("mixer",          d_mixer),
        ("crosschain",     d_crosschain),
        ("defi",           d_defi),
        ("nft",            d_nft),
        ("dusting",        d_dusting),
        ("pig_butchering", d_pig_butchering),
        ("reverse_taint",  d_reverse_taint),
        ("pagerank",       d_pagerank),
        ("lof",            d_lof),
    ]

    detector_results = {}
    for i, (name, mod) in enumerate(_detectors, 1):
        print(f"    [{i:02d}/{len(_detectors)}] {name:<18}", end="", flush=True)
        try:
            result = mod.detect(**shared)
            detector_results[name] = result
            hit_str = "✅ HIT" if result.get("detected") else "   -"
            sev     = result.get("severity", "")
            sev_icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡"}.get(sev, "")
            print(f" {hit_str} {sev_icon}")
        except Exception as e:
            detector_results[name] = {"detected": False}
            print(f" ❌ ERROR: {str(e)[:40]}")

    hit = sum(1 for v in detector_results.values()
              if isinstance(v, dict) and v.get("detected"))
    print(f"\n    完成 ✓  {hit}/{len(_detectors)} 个检测器命中")

    # ── Step 3b: 边打标签（topo_tags）─────────────────────
    print("\n>>> Step 3b: 边标签打标")
    edge_tags = tag_edges(edges, detector_results, nodes)
    tagged_count = sum(1 for v in edge_tags.values() if v)
    print(f"    已打标签的边: {tagged_count} 条")

    # ── Step 3b: 检测结果反标节点 ─────────────────────────
    print("\n>>> Step 3b: 检测结果反标节点 (topo_tags)")
    nodes = tag_nodes_from_detectors(nodes, edges, detector_results)

    # ── Step 3c: 资金最终流向追踪 ─────────────────────────
    print("\n>>> Step 3c: 资金流向追踪")
    try:
        flow_destinations = find_flow_destination(addr, nodes, edges, detector_results)
        ep_count = len(flow_destinations.get("all_endpoints", []))
        print(f"    Peel Chain终点: {len(flow_destinations['peel_destinations'])} 条路径")
        print(f"    Fan-out终点:    {len(flow_destinations['fanout_destinations'])} 条路径")
        print(f"    终点汇总:       {ep_count} 个唯一终点")
        for ep in flow_destinations.get("all_endpoints", [])[:3]:
            print(f"      → {ep['address'][:18]}... [{ep['type']}] {ep['label']}")
    except Exception as e:
        print(f"    ⚠️  跳过: {e}")
        flow_destinations = {"peel_destinations": [], "fanout_destinations": [], "all_endpoints": []}

    # ── Step 4: 评分 ──────────────────────────────────────
    print("\n>>> Step 4: 综合评分")
    score_result = score(addr, nodes, edges, detector_results, tok)  # pass token_txs for decimals
    audit_result = score_result.get("audit", {})

    # ── Step 5: 资金路径追踪 ────────────────────────────────
    print("\n>>> Step 5: 资金路径追踪")
    try:
        trace_result = trace_full(addr, nodes, edges)
        t_stats = trace_result["stats"]
        print(f"    关键路径: {t_stats['critical_paths']} CRITICAL + {t_stats['high_paths']} HIGH")
        print(f"    高亮节点: {t_stats['highlight_nodes']} 个")
        if trace_result["summary"]:
            print(f"    {trace_result['summary']}")
    except Exception as e:
        print(f"    ⚠️  跳过: {e}")
        trace_result = {"highlight_nodes": [], "highlight_edges": [],
                        "risk_paths": [], "peel_paths": [],
                        "stats": {"critical_paths":0,"high_paths":0,
                                  "highlight_nodes":0,"highlight_edges":0},
                        "summary": ""}

    # ── Step 6: 交易所流向检测 ──────────────────────────────
    print("\n>>> Step 6: 交易所流向检测")
    try:
        exchange_result = run_exchange_check(addr, eth, tok, nodes, edges)
        ex_s = exchange_result["summary"]
        print(f"    合规CEX: {ex_s['compliant_count']}  "
              f"制裁: {ex_s['sanctioned_count']}  高风险: {ex_s['grey_count']}")
        if ex_s["compliant_names"]:
            print(f"    合规: {', '.join(ex_s['compliant_names'][:4])}")
        if ex_s["sanctioned_names"]:
            print(f"    🔴 制裁: {', '.join(ex_s['sanctioned_names'])}")
    except Exception as e:
        print(f"    ⚠️  跳过: {e}")
        exchange_result = {"address": addr, "risk_level": "CLEAN",
                           "flows": {}, "summary": {"total_exchanges":0,
                           "compliant_count":0,"sanctioned_count":0,
                           "grey_count":0,"compliant_names":[],
                           "sanctioned_names":[],"grey_names":[]},
                           "law_refs": []}

    # ── Step 7: 法规条款映射 ────────────────────────────────
    print("\n>>> Step 7: 法规条款映射")
    law_section = generate_law_section(
        detector_results,
        score_result["risk_level"],
        score_result.get("score_breakdown", {}),
    )
    print(f"    触发法规条款: {len(law_section['triggered_laws'])} 条")

    # 法规关联到具体违规交易 (问题3)
    law_section["tx_evidence"] = _build_law_tx_evidence(
        law_section, detector_results, edges, addr
    )

    # ── 绑定法规→具体tx_hash ────────────────────────────────
    # 从 detector_results 里提取与每个检测器相关的地址，
    # 再从 edges 里找这些地址的 tx（用 eth 列表的 hash 字段）
    try:
        _tx_by_pair = {}   # (from, to) -> [hash]
        for tx in eth:
            f_ = tx.get("from","").lower()
            t_ = tx.get("to","").lower()
            h_ = tx.get("hash","").lower()
            if f_ and t_ and h_:
                _tx_by_pair.setdefault((f_,t_),[]).append(h_)
        for tx in tok:
            f_ = tx.get("from","").lower()
            t_ = tx.get("to","").lower()
            h_ = tx.get("hash","").lower()
            if f_ and t_ and h_:
                _tx_by_pair.setdefault((f_,t_),[]).append(h_)

        _det_to_addrs = {}
        # peel chain
        pc = detector_results.get("peel_chain",{})
        if pc.get("detected"):
            _det_to_addrs["peel_chain"] = set(a for chain in pc.get("chains",[]) for a in chain)
        # fanout
        fo = detector_results.get("fanout",{})
        if fo.get("detected"):
            _det_to_addrs["fanout"] = set(
                h["address"] if isinstance(h,dict) else h
                for h in fo.get("hubs",[]))
        # blacklist/mixer
        bl = detector_results.get("blacklist",{})
        if bl.get("detected"):
            _det_to_addrs["blacklist"] = set(h["address"] for h in bl.get("hits",[]))
        mx = detector_results.get("mixer",{})
        if mx.get("detected"):
            _det_to_addrs["mixer"] = set(
                h["address"] for h in mx.get("results",{}).get("mixer_interactions",{}).get("hits",[]))
        # smurfing
        sm = detector_results.get("smurfing",{})
        if sm.get("detected"):
            _det_to_addrs["smurfing"] = {addr}

        for tl in law_section.get("triggered_laws",[]):
            related_hashes = []
            for det in tl.get("detectors",[]):
                addrs = _det_to_addrs.get(det, set())
                for (f_,t_), hs in _tx_by_pair.items():
                    if f_ in addrs or t_ in addrs or f_ == addr or t_ == addr:
                        related_hashes.extend(hs[:3])
            # dedup, keep first 5
            seen_h = set()
            tl["tx_hashes"] = []
            for h_ in related_hashes:
                if h_ not in seen_h:
                    seen_h.add(h_)
                    tl["tx_hashes"].append(h_)
                if len(tl["tx_hashes"]) >= 5:
                    break
    except Exception as e:
        print(f"    ⚠️  tx绑定跳过: {e}")

    # 跨链桥审计
    bridge_audit = d_crosschain.audit_bridge_flow(addr, nodes, edges)

    report = {
        "meta": {
            "address":        addr,
            "analyzed_at":    datetime.now().isoformat(),
            "hops":           hops,
            "engine":         "LucidAML",
            "engine_version": "3.2",
        },
        "risk":             score_result,
        "balance":          balance_report,
        "law":              law_section,
        "graph": {
            "summary": gs,
            # 默认只渲染风险子图，前端性能问题解决
            "json":     graph_to_json(nodes, edges,
                            detector_results=detector_results,
                            law_section=law_section,
                            risk_only=True),
            # 全量图放在单独key，前端按需加载
            "json_full": graph_to_json(nodes, edges,
                            detector_results=detector_results,
                            law_section=law_section,
                            risk_only=False),
        },
        "detectors":        detector_results,
        "audit":            audit_result,
        "bridge_audit":     bridge_audit,
        "btc":              btc_result,
        "exchange":         exchange_result,
        "trace":            trace_result,
        "flow_destinations": flow_destinations,
        "tokens":           summarize_tokens(tok),
    }

    # ── 终端输出完整报告 ──────────────────────────────────
    print("\n" + make_report_text(score_result, audit_result))
    print(format_balance_text(balance_report))
    print(format_law_report_text(law_section))

    if save_json:
        out_dir  = output_dir or os.path.expanduser("~/Desktop/stbc")
        out_path = os.path.join(
            out_dir,
            f"report_{addr[:10]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        os.makedirs(out_dir, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n  报告已保存 → {out_path}")

    return report


def format_balance_text(balance_report: dict) -> str:
    """终端输出余额部分"""
    bal  = balance_report.get("current", {})
    flow = balance_report.get("fund_flow", {})
    eth  = flow.get("eth", {})
    tok  = flow.get("tokens", {})

    lines = [
        "─" * 55,
        " 余额 & 资金流水",
        "─" * 55,
        f" 当前余额:    {bal.get('balance_eth', 0)} ETH",
        f" 历史流入:    {eth.get('in_eth', 0)} ETH  ({eth.get('in_count', 0)} 笔 / {eth.get('unique_senders', 0)} 个来源)",
        f" 历史流出:    {eth.get('out_eth', 0)} ETH  ({eth.get('out_count', 0)} 笔 / {eth.get('unique_receivers', 0)} 个去向)",
        f" 净流量:      {eth.get('net_eth', 0)} ETH",
    ]

    top_in  = tok.get("top_in",  [])
    top_out = tok.get("top_out", [])
    if top_in:
        lines.append(f" 主要Token流入: " + "  ".join(
            f"{t['symbol']}({t['amount']:,})" for t in top_in[:4]))
    if top_out:
        lines.append(f" 主要Token流出: " + "  ".join(
            f"{t['symbol']}({t['amount']:,})" for t in top_out[:4]))

    lines.append("─" * 55)
    return "\n".join(lines)


def _run_btc_analysis(eth_addr):
    try:
        from collector_btc import find_crosschain_link
        hints = find_crosschain_link(eth_addr)
        if hints:
            print(f"    发现 {len(hints)} 个 BTC 跨链关联")
            return {"crosschain_hints": hints}
        else:
            print("    未发现 BTC 跨链关联")
            return None
    except Exception as e:
        print(f"    BTC 检测跳过: {e}")
        return None


def analyze_btc(btc_address, save_json=True, output_dir=None):
    from collector_btc import fetch_btc_all, build_btc_graph, detect_btc_blacklist, detect_btc_peel_chain

    print(f"\n{'='*55}")
    print(f" ChainSentinel — BTC 地址分析")
    print(f"{'='*55}")
    print(f" 地址: {btc_address}\n")

    info, edges = fetch_btc_all(btc_address)
    nodes, edges = build_btc_graph(btc_address, edges)

    bl_result   = detect_btc_blacklist(btc_address, nodes, edges)
    peel_result = detect_btc_peel_chain(nodes, edges)

    risk_score = 0
    if bl_result.get("detected"):   risk_score += 100
    if peel_result.get("detected"): risk_score += 30
    risk_score = min(100, risk_score)

    level = ("CRITICAL" if risk_score >= 100
             else "HIGH"   if risk_score >= 60
             else "MEDIUM" if risk_score >= 30
             else "LOW")

    report = {
        "meta": {
            "address":     btc_address,
            "chain":       "BTC",
            "analyzed_at": datetime.now().isoformat(),
            "engine":      "ChainSentinel",
        },
        "risk": {
            "risk_level": level,
            "risk_score": risk_score,
            "taint_rate": 100.0 if bl_result.get("detected") else 0.0,
            "triggered":  [r for r in [
                {"detector":"btc_blacklist","severity":"CRITICAL","summary":bl_result.get("summary","")} if bl_result.get("detected") else None,
                {"detector":"btc_peel_chain","severity":"HIGH","summary":peel_result.get("summary","")} if peel_result.get("detected") else None,
            ] if r],
        },
        "address_info": info,
        "detectors": {
            "btc_blacklist":  bl_result,
            "btc_peel_chain": peel_result,
        },
    }

    BADGE = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
    print(f"\n {'='*50}")
    print(f"  BTC 风险报告")
    print(f"  地址:     {btc_address}")
    print(f"  风险等级: {BADGE.get(level,'')} {level}")
    print(f"  风险评分: {risk_score}/100")
    print(f"  余额:     {info.get('balance',0)/1e8:.8f} BTC")
    print(f"  交易数:   {info.get('tx_count',0)}")
    print(f" {'='*50}\n")

    if save_json:
        out_dir  = output_dir or os.path.expanduser("~/Desktop/stbc")
        out_path = os.path.join(out_dir,
            f"btc_report_{btc_address[:12]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        os.makedirs(out_dir, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(f"  报告已保存 → {out_path}")

    return report


def _build_law_tx_evidence(law_section, detector_results, edges, target_addr):
    """
    把法规条款关联到具体违规交易hash (问题3)
    每条法规 → 触发它的检测器 → 对应的具体边(tx_hash/地址对)
    """
    from config import BLACKLIST, KNOWN_MIXERS
    addr = target_addr.lower()
    evidence = {}

    for tl in law_section.get("triggered_laws", []):
        ref = tl.get("ref", "")
        det_names = tl.get("detectors", [])
        txs = []

        for det in det_names:
            res = detector_results.get(det, {})
            if not res.get("detected"):
                continue

            if det == "blacklist":
                # 找与黑名单地址的直接边
                bl_addrs = {h["address"] for h in res.get("hits", [])}
                for f, t, v, ts, typ in edges:
                    if (f in bl_addrs or t in bl_addrs) and (f == addr or t == addr):
                        txs.append({
                            "from": f, "to": t, "value": v,
                            "ts": ts, "token": typ,
                            "reason": f"直接与黑名单地址交互"
                        })

            elif det == "mixer":
                mixer_addrs = {h["address"] for h in
                               res.get("results",{}).get("mixer_interactions",{}).get("hits",[])}
                for f, t, v, ts, typ in edges:
                    if (f in mixer_addrs or t in mixer_addrs) and (f == addr or t == addr):
                        txs.append({
                            "from": f, "to": t, "value": v,
                            "ts": ts, "token": typ,
                            "reason": "向Mixer转账/从Mixer收款"
                        })

            elif det == "peel_chain":
                chains = res.get("chains", [])
                for chain in chains[:2]:
                    for i in range(len(chain)-1):
                        for f, t, v, ts, typ in edges:
                            if f == chain[i] and t == chain[i+1]:
                                txs.append({
                                    "from": f, "to": t, "value": v,
                                    "ts": ts, "token": typ,
                                    "reason": f"Peel Chain第{i+1}跳"
                                })
                                break

            elif det == "smurfing":
                for pat in res.get("patterns", [])[:3]:
                    val = pat.get("value", 0)
                    for f, t, v, ts, typ in edges:
                        if f == addr and v == val:
                            txs.append({
                                "from": f, "to": t, "value": v,
                                "ts": ts, "token": typ,
                                "reason": f"拆单重复金额 (×{pat.get('count','')})"
                            })

            elif det == "crosschain":
                for sub in res.get("results", {}).values():
                    for hit in sub.get("hits", []) if isinstance(sub, dict) else []:
                        bridge_addr = hit.get("address","")
                        for f, t, v, ts, typ in edges:
                            if (f == addr and t == bridge_addr) or (t == addr and f == bridge_addr):
                                txs.append({
                                    "from": f, "to": t, "value": v,
                                    "ts": ts, "token": typ,
                                    "reason": f"跨链桥交互: {hit.get('bridge','')}"
                                })

        if txs:
            # 去重 + 限制数量
            seen = set()
            unique_txs = []
            for tx in txs:
                key = (tx["from"], tx["to"], tx["value"])
                if key not in seen:
                    seen.add(key)
                    unique_txs.append(tx)
            evidence[ref] = unique_txs[:10]

    return evidence


def analyze_sol(sol_address: str, save_json: bool = True, output_dir: str = None):
    """分析 Solana 地址"""
    from collector_solana import analyze_sol_address
    return analyze_sol_address(sol_address, limit=100,
                               save_json=save_json, output_dir=output_dir)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法:")
        print("  python analyze.py <ETH地址> [hops]")
        print("  python analyze.py btc <BTC地址>")
        sys.exit(1)

    if sys.argv[1] == "btc":
        analyze_btc(sys.argv[2])
    elif sys.argv[1] == "sol":
        analyze_sol(sys.argv[2])
    else:
        analyze(sys.argv[1],
                int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_HOPS)


