#!/usr/bin/env python3
"""终端报告输出与 JSON 导出（只读 RiskReport，不参与评分）。"""

import json
from typing import Optional, Dict, List

from .models import RiskReport
from .chains import EVM_CHAIN_REGISTRY
from .config import decode_method, STABLECOIN_SYMBOLS

# ==================== 报告输出 ====================
LEVEL_COLORS = {
    "LOW":      "\033[92m",
    "MEDIUM":   "\033[93m",
    "HIGH":     "\033[91m",
    "CRITICAL": "\033[95m",
    "RESET":    "\033[0m",
}


def print_transactions(report: RiskReport, show_all: bool = False) -> None:
    """打印完整稳定币流水表格（--full 时调用）。"""
    txs = sorted(report.transactions, key=lambda x: x.get("ts", ""), reverse=True)
    if not txs:
        print("  （无稳定币流水记录）")
        return

    # 构建风险地址集合用于标注
    risk_cps = {ind.counterparty: ind.category for ind in report.indicators if ind.amount_usdt > 0}

    limit = len(txs) if show_all else min(len(txs), 200)
    print(f"\n{'='*90}")
    print(f"  完整稳定币流水（共 {len(txs)} 笔，显示 {limit} 笔）")
    print(f"{'='*90}")
    # 把方向直接写出来：IN ← / OUT →，比单纯 ±/箭头直观
    print(f"  {'时间(UTC)':<20} {'方向':<6} {'金额':>14} {'资产':<6} {'链':<10} {'对手方地址':<44} {'风险标签'}")
    print(f"  {'─'*88}")

    for tx in txs[:limit]:
        ts = tx.get("ts", "")
        try:
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            dt = ts
        direction = tx.get("direction", "")
        amount    = tx.get("amount", 0.0)
        sym       = tx.get("sym", "")
        chain     = tx.get("chain", "")
        cp        = tx.get("counterparty", "")
        label     = risk_cps.get(cp, "")
        # IN/OUT 直接写出来，arrow 当辅助记号
        if direction == "IN":
            dir_str = "IN ←"
        elif direction == "OUT":
            dir_str = "OUT→"
        else:
            dir_str = direction or "─"
        print(f"  {dt:<20} {dir_str:<6} {amount:>14,.4f} {sym:<6} {chain:<10} {cp:<44} {label}")

    if limit < len(txs):
        print(f"  ... 还有 {len(txs)-limit} 笔，加 --full 显示全部")


def _short_addr(addr: str, head: int = 8, tail: int = 6) -> str:
    if not addr:
        return "—"
    if len(addr) <= head + tail + 3:
        return addr
    return f"{addr[:head]}…{addr[-tail:]}"


def print_contract_interactions(report: RiskReport, limit: int = 30) -> None:
    """打印合约交互明细：每条 tx 一行外层 + 每条 token effect 一条子行，
    显式标注 IN/OUT + from/to，方便排查 TOKEN_ONLY 类异常。"""
    inters = report.contract_interactions or []
    if not inters:
        return

    total = len(inters)
    shown = min(limit, total)
    print(f"\n{'='*100}")
    print(f"  合约交互明细（共 {total} 笔，显示 {shown} 笔；TOKEN_ONLY = 没匹到外壳交易）")
    print(f"{'='*100}")

    for it in inters[:shown]:
        ts = it.get("ts", "")
        try:
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if ts else "—"
        except Exception:
            dt = str(ts)
        direction = it.get("direction", "")
        action    = it.get("action_type", "")
        method_lb_raw = it.get("method_label") or it.get("method") or ""
        # 兼容旧数据：methodId 可能是 "0x"（input data 占位），不当作 selector 显示
        if method_lb_raw.strip().lower() in ("", "0x"):
            method_lb_raw = "Transfer" if it.get("native_value", 0) >= 0 and not it.get("input_present") else "—"
        method_lb = method_lb_raw
        method_id = it.get("method_id", "")
        if method_id.strip().lower() == "0x":
            method_id = ""
        tx_hash   = it.get("tx_hash", "")
        status    = it.get("status", "")
        chain     = it.get("chain", "")

        # 外层方向：TOKEN_ONLY 时单独标识
        if direction == "IN":
            dir_str = "IN ←"
        elif direction == "OUT":
            dir_str = "OUT→"
        elif direction == "TOKEN_ONLY":
            dir_str = "TOKEN"   # 没匹到外壳，资金动作全部看下方 effects
        else:
            dir_str = direction or "—"

        # method_label 已是可读名；如果还是 unknown(0x..) 顺带带出 action_type 帮助理解
        method_show = method_lb
        if method_id and method_id.lower() not in method_show.lower() and method_show.startswith("unknown"):
            pass   # 已包含 selector
        elif method_id and method_id.lower() not in method_show.lower():
            method_show = f"{method_lb} ({method_id})"

        print(f"\n  [{dt}] {dir_str:<6} {action:<32}  method: {method_show}")
        print(f"     tx:    {tx_hash}  chain={chain}  status={status}")

        # token effects：每条单独打印，显式 from / to
        effects = it.get("token_effects", []) or []
        if not effects and direction in ("IN", "OUT") and it.get("native_value", 0) > 0:
            nv = it["native_value"]
            print(f"     └─ {dir_str:<5} {nv:>14,.6f} ETH   (native value)")
        for eff in effects:
            e_dir = eff.get("direction", "")
            if e_dir == "IN":
                edir_str = "IN ←"
            elif e_dir == "OUT":
                edir_str = "OUT→"
            else:
                edir_str = e_dir or "OTHER"
            amt   = eff.get("amount", 0.0)
            sym   = eff.get("sym", "")
            frm_a = eff.get("from", "") or "—"
            to_a  = eff.get("to", "") or "—"
            stable_mark = " ★stable" if eff.get("is_stablecoin") else ""
            inner_mid = eff.get("method_id", "")
            inner_lbl = eff.get("method_label", "") or ""
            inner_show = f"  inner-method: {inner_lbl}" if inner_lbl and inner_lbl != method_show else ""
            print(f"     └─ {edir_str:<5} {amt:>14,.6f} {sym:<8}{stable_mark}  "
                  f"from {_short_addr(frm_a)}  →  to {_short_addr(to_a)}{inner_show}")

    if shown < total:
        print(f"\n  ... 还有 {total - shown} 笔未显示")


def print_report(report: RiskReport, use_color: bool = True, output_dir: str = ""):
    c  = LEVEL_COLORS if use_color else {k: "" for k in LEVEL_COLORS}
    lc = c.get(report.risk_level, "")
    rc = c["RESET"]

    print(f"\n{'='*60}")
    print(f"  AML 风险分析报告")
    print(f"{'='*60}")
    print(f"  地址:     {report.address}")
    if report.tron_address:
        print(f"  Tron地址: {report.tron_address}")
    print(f"  链:       {report.chain}")
    if len(report.chains_analyzed) > 1:
        print(f"  已分析链: {', '.join(report.chains_analyzed)}")
    print(f"  余额:     {report.account_info.get('balance', 'N/A')}")
    print(f"  是否合约: {'是' if report.account_info.get('is_contract') else '否'}")
    print(f"  交易数量: {report.total_transactions}  |  对手方: {report.total_counterparties}")
    print(f"  稳定币流入: {report.total_inflow_usdt:>12,.2f}  |  流出: {report.total_outflow_usdt:>12,.2f}")
    # 每种稳定币明细
    if report.per_asset:
        print(f"  {'─'*66}")
        print(f"  {'资产':<10} {'流入(窗口内)':>14} {'流出(窗口内)':>14} {'当前余额':>12} {'窗口前余额':>12} {'笔数':>6}")
        for key in sorted(report.per_asset):
            a = report.per_asset[key]
            transit = " ⚡" if a.get("is_fast_transit") else ""
            trunc   = " !" if a.get("truncated") else ""
            pre = a.get("pre_window_balance", 0.0)
            pre_str = f"{pre:>12,.2f}" + (" [?]" if pre < -1 else "")
            sym_label = f"{a['sym']}@{a['chain']}"
            print(f"  {sym_label:<10} {a['flow_in']:>14,.2f} {a['flow_out']:>14,.2f} "
                  f"{a['balance']:>12,.2f} {pre_str} {a.get('tx_count',0):>6}{transit}{trunc}")

    # 多链分链明细
    if len(report.chains_analyzed) > 1:
        print(f"  {'─'*54}")
        print(f"  各链 USDT 流量:")
        for cn in report.chains_analyzed:
            inf = report.per_chain_inflow.get(cn, 0.0)
            out = report.per_chain_outflow.get(cn, 0.0)
            cfg = EVM_CHAIN_REGISTRY.get(cn)
            label = cfg.name if cfg else cn
            print(f"    {label:<12} 流入 {inf:>10,.2f}  流出 {out:>10,.2f}")

    print()
    print(f"  {'─'*54}")
    print(f"  风险等级:   {lc}{report.risk_level}{rc}")
    print(f"  风险分数:   {lc}{report.risk_score}/100{rc}")
    print(f"  {'─'*54}")

    # 评分分解（可解释性）
    bd = report.score_breakdown
    if bd:
        print(f"  【评分分解】")
        print(f"    收入侧污染:   {bd['received_taint_pct']:>6.2f}%  "
              f"(收到来自风险地址的稳定币占总流入的比例 × 类别权重)")
        print(f"    转出侧污染:   {bd['sent_taint_pct']:>6.2f}%  "
              f"(转入风险地址的稳定币占总流出的比例 × 类别权重)")
        print(f"    最终得分:     {lc}{bd['final_score']}/100{rc}")
        print(f"  {'─'*54}")

    if report.is_blacklisted:
        print(f"\n  {lc}[!!!] 该地址已被 USDT 直接封禁{rc}")
        print(f"        封禁时间: {report.blacklist_time}")

    if report.warnings:
        print(f"\n  警告:")
        for w in report.warnings:
            print(f"    ⚠ {w}")

    # ── 对手方风险明细表 ─────────────────────────────────────────────────
    if report.counterparty_table:
        rows = report.counterparty_table
        # 收集出现过的币种，固定顺序
        sym_order = ["USDT", "USDC", "DAI", "BUSD", "USDC.E", "USDCE", "USDB", "DOLA"]
        active_syms = [s for s in sym_order
                       if any(s in r["by_sym"] for r in rows)]
        # 如果有未在 sym_order 里的币种，追加
        extra = sorted({s for r in rows for s in r["by_sym"]} - set(sym_order))
        active_syms += extra

        total_in_all  = report.total_inflow_usdt
        total_out_all = report.total_outflow_usdt

        tag_label = {
            "blacklist":          "黑名单",
            "ofac_sanctioned":    "OFAC制裁",
            "mixer":              "混币器",
            "opaque_bridge":      "不透明桥",
            "high_risk_exchange": "高风险所",
        }
        tag_color = {
            "blacklist":          "\033[91m",
            "ofac_sanctioned":    "\033[91m",
            "mixer":              "\033[93m",
            "opaque_bridge":      "\033[93m",
            "high_risk_exchange": "\033[33m",
        } if use_color else {}
        RESET = "\033[0m" if use_color else ""

        # 动态计算地址列宽（最长地址 vs 列头 "地址"）
        max_addr_len = max((len(r["address"]) for r in rows), default=10)
        addr_w = max(max_addr_len, 10)

        # 币种列宽
        sym_w = {s: max(len(s), 10) for s in active_syms}

        # 表头：方向直接写 IN/OUT，比 ←/→ 直观
        header_parts = [
            f"{'方向':<6}",
            f"{'地址':<{addr_w}}",
            f"{'USD总额':>12}",
            f"{'占总流量':>8}",
        ]
        for s in active_syms:
            header_parts.append(f"{s:>{sym_w[s]}}")
        header_parts += ["  风险标签", "  → 污染贡献"]
        header = "  " + "  ".join(header_parts)

        sep_len = len(header) + 4
        print(f"\n  【对手方风险明细】")
        print(f"  {'─' * (sep_len - 2)}")
        print(header)
        print(f"  {'─' * (sep_len - 2)}")

        # 尘埃过滤：金额 < $1 且无风险标签的行不显示，但在末尾汇总
        DUST_THRESHOLD = 1.0
        dust_rows = [r for r in rows if r["total_usd"] < DUST_THRESHOLD and not r["risk_tags"]]
        visible_rows = [r for r in rows if r["total_usd"] >= DUST_THRESHOLD or r["risk_tags"]]

        for r in visible_rows:
            direction = r["direction"]
            basis = total_in_all if direction == "IN" else total_out_all
            flow_pct = (r["total_usd"] / basis * 100) if basis > 0 else 0.0
            # 显式 IN/OUT，比 ←/→ 直观
            if direction == "IN":
                dir_arrow = "IN ←"
            elif direction == "OUT":
                dir_arrow = "OUT→"
            else:
                dir_arrow = direction or "—"

            # 风险标签字符串（带颜色）
            tag_str = ""
            if r["risk_tags"]:
                parts = []
                for t in r["risk_tags"]:
                    col = tag_color.get(t, "")
                    lbl = tag_label.get(t, t)
                    parts.append(f"{col}[{lbl}]{RESET}")
                tag_str = " ".join(parts)
            else:
                tag_str = "─"

            # 污染贡献
            taint_str = f"★{r['taint_pct']:.2f}%" if r["taint_pct"] > 0 else "─"
            if use_color and r["taint_pct"] > 0:
                taint_str = f"\033[91m★{r['taint_pct']:.2f}%{RESET}"

            row_parts = [
                f"{dir_arrow:<6}",
                f"{r['address']:<{addr_w}}",
                f"{r['total_usd']:>12,.2f}",
                f"{flow_pct:>7.1f}%",
            ]
            for s in active_syms:
                v = r["by_sym"].get(s, 0.0)
                cell = f"{v:>{sym_w[s]},.2f}" if v > 0 else f"{'─':>{sym_w[s]}}"
                row_parts.append(cell)
            row_parts += [f"  {tag_str}", f"  {taint_str}"]
            print("  " + "  ".join(row_parts))

        if dust_rows:
            dust_in  = sum(r["total_usd"] for r in dust_rows if r["direction"] == "IN")
            dust_out = sum(r["total_usd"] for r in dust_rows if r["direction"] == "OUT")
            dust_n   = len(dust_rows)
            print(f"  {'─' * (sep_len - 2)}")
            print(f"  （另有 {dust_n} 个尘埃地址已折叠，"
                  f"收入合计 ${dust_in:,.2f} / 支出合计 ${dust_out:,.2f}，均 < ${DUST_THRESHOLD:.0f}）")
        print(f"  {'─' * (sep_len - 2)}")

    # ── 风险证据明细 ────────────────────────────────────────────────────
    if report.indicators:
        sorted_inds = sorted(report.indicators, key=lambda x: (x.hop, -x.amount_usdt))
        hop1_inds = [i for i in sorted_inds if i.hop == 1 and i.amount_usdt > 0]
        hop2_inds = [i for i in sorted_inds if i.hop == 2 and i.amount_usdt > 0]
        pres_inds = [i for i in sorted_inds if i.amount_usdt == 0]

        total_in  = report.total_inflow_usdt
        total_out = report.total_outflow_usdt

        # 地址缩写辅助函数
        def _short(addr: str, n: int = 10) -> str:
            return addr[:6] + "..." + addr[-4:] if len(addr) > n else addr

        x = _short(report.address)

        if hop1_inds:
            print(f"\n  {'─'*54}")
            print(f"  1-Hop 风险证据（直接交互，衰减系数 1.0）")
            print(f"  {'─'*54}")
            for ind in hop1_inds:
                basis   = total_in if ind.direction == "IN" else total_out
                contrib = (ind.amount_usdt * ind.category_weight / basis * 100) if basis > 0 else 0
                chain_tag = f"[{ind.chain}] " if ind.chain else ""
                cp = _short(ind.counterparty)
                # 路径：资金流向箭头从来源指向目的地
                if ind.direction == "IN":
                    path = f"{cp} --{ind.amount_usdt:,.0f} USDT--> {x}"
                else:
                    path = f"{x} --{ind.amount_usdt:,.0f} USDT--> {cp}"
                print(f"    {chain_tag}[{ind.category}]  {ind.amount_usdt:>12,.2f} USDT  "
                      f"污染贡献 {contrib:.2f}%")
                print(f"      路径: {path}")
                print(f"      完整地址: {ind.counterparty}")
                if ind.tx_hashes:
                    txs_str = ind.tx_hashes[0][:20] + "..."
                    if len(ind.tx_hashes) > 1:
                        txs_str += f" 等{len(ind.tx_hashes)}笔"
                    print(f"      证据tx:   {txs_str}")

        if hop2_inds:
            print(f"\n  {'─'*54}")
            print(f"  2-Hop 风险证据（间接关联，衰减系数 0.3）")
            print(f"  {'─'*54}")
            for ind in hop2_inds:
                basis   = total_in if ind.direction == "IN" else total_out
                contrib = (ind.amount_usdt * ind.category_weight * 0.3 / basis * 100) if basis > 0 else 0
                chain_tag = f"[{ind.chain}] " if ind.chain else ""
                cp  = _short(ind.counterparty)
                via = _short(ind.via_address) if ind.via_address else "?"
                if ind.direction == "IN":
                    path = f"{cp} --> {via} --> {x}"
                else:
                    path = f"{x} --> {via} --> {cp}"
                print(f"    {chain_tag}[{ind.category}]  {ind.amount_usdt:>12,.2f} USDT  "
                      f"污染贡献 {contrib:.2f}%（×0.3衰减）")
                print(f"      路径: {path}")
                print(f"      中间节点: {ind.via_address}")
                print(f"      风险终点: {ind.counterparty}")
                if ind.tx_hashes:
                    print(f"      证据tx:   {ind.tx_hashes[0][:20]}...")

        if pres_inds:
            print(f"\n  {'─'*54}")
            print(f"  非稳定币关联（无 USDT/USDC/DAI 金额，不参与污染计算）")
            print(f"  {'─'*54}")
            for ind in pres_inds:
                chain_tag = f"[{ind.chain}] " if ind.chain else ""
                cp = _short(ind.counterparty)
                if ind.hop == 1:
                    path = (f"{cp} ──▶ {x}" if ind.direction == "IN"
                            else f"{x} ──▶ {cp}" if ind.direction == "OUT"
                            else f"{x} ↔ {cp}")
                elif ind.hop == 2:
                    via = _short(ind.via_address) if ind.via_address else "?"
                    path = (f"{cp} ──▶ {via} ──▶ {x}" if ind.direction == "IN"
                            else f"{x} ──▶ {via} ──▶ {cp}" if ind.direction == "OUT"
                            else f"{x} ↔ {via} ↔ {cp}")
                else:
                    via = _short(ind.via_address) if ind.via_address else "?"
                    path = (f"{cp} ──▶ … ──▶ {x}" if ind.direction == "IN"
                            else f"{x} ──▶ … ──▶ {cp}" if ind.direction == "OUT"
                            else f"{x} ↔ … ↔ {cp}")
                note_str = f"  [{ind.note}]" if ind.note else ""
                print(f"    {chain_tag}[{ind.hop}-hop][{ind.category}]  {path}{note_str}")
                if ind.tx_hashes:
                    print(f"      证据tx: {ind.tx_hashes[0][:20]}..."
                          + (f" 等{len(ind.tx_hashes)}笔" if len(ind.tx_hashes) > 1 else ""))
                print(f"      完整地址: {ind.counterparty}")

    # ── 桥交互 ────────────────────────────────────────────────────────
    if report.bridge_interactions:
        print(f"\n  透明跨链桥（{len(report.bridge_interactions)} 笔，资金可追踪）:")
        shown: Dict[str, dict] = {}
        for b in report.bridge_interactions:
            shown.setdefault(b["bridge"], {"count": 0, "dirs": set(), "tokens": set(),
                                           "dst_chains": b.get("dst_chains", []),
                                           "method": b.get("method", ""), "contract": b["contract"]})
            shown[b["bridge"]]["count"] += 1
            shown[b["bridge"]]["dirs"].add(b.get("direction", "?"))
            shown[b["bridge"]]["tokens"].add(b.get("token", "?"))
        for name, info in shown.items():
            dirs   = "/".join(sorted(info["dirs"]))
            tokens = "/".join(sorted(info["tokens"]))
            dst    = "/".join(info["dst_chains"]) if info["dst_chains"] else "多链"
            print(f"    - {name}  [{dirs}]  {tokens}  {info['count']}笔  → {dst}")

    if report.opaque_bridge_interactions:
        print(f"\n  {lc}不透明桥（{len(report.opaque_bridge_interactions)} 笔，资金不可追踪）:{rc}")
        shown_op: Dict[str, dict] = {}
        for b in report.opaque_bridge_interactions:
            shown_op.setdefault(b["bridge"], {"count": 0, "dirs": set()})
            shown_op[b["bridge"]]["count"] += 1
            shown_op[b["bridge"]]["dirs"].add(b.get("direction", "?"))
        for name, info in shown_op.items():
            dirs = "/".join(sorted(info["dirs"]))
            print(f"    - {name}  [{dirs}]  {info['count']}笔")

    if report.mixer_interactions:
        print(f"\n  {lc}混币器（{len(report.mixer_interactions)} 笔）:{rc}")
        for m in report.mixer_interactions[:5]:
            chain_tag = f"[{m.get('chain', '')}] " if m.get('chain') else ""
            print(f"    - {chain_tag}{m['mixer']}  [{m['direction']}]  tx:{m['tx'][:20]}...")

    if report.high_risk_exchanges:
        print(f"\n  高风险交易所:")
        for e in report.high_risk_exchanges[:5]:
            chain_tag = f"[{e.get('chain', '')}] " if e.get('chain') else ""
            print(f"    - {chain_tag}{e['exchange']}  [{e['direction']}]")

    if report.cross_chain_findings:
        print(f"\n  跨链追踪（{len(report.cross_chain_findings)} 条）:")
        for f in report.cross_chain_findings:
            dst = f.get("dst_address", "?")
            ch  = f.get("dst_chain", "?")
            br  = f.get("bridge", "")
            src = f.get("src_chain", "")
            src_tag = f"[{src}→{ch}] " if src else f"[→{ch}] "
            if f.get("blacklisted"):
                bl_time = f.get("blacklist_info", {}).get("time", "")[:10]
                print(f"  {lc}  {src_tag}{br}: {dst}  [黑名单 {bl_time}]{rc}")
            elif f.get("hop1_blacklisted"):
                n = len(f["hop1_blacklisted"])
                print(f"    {src_tag}{br}: {dst[:18]}...  [1跳内 {n} 个黑名单]")
            else:
                print(f"    {src_tag}{br}: {dst[:18]}...  [无直接黑名单]")

    # 合约交互明细（含 TOKEN_ONLY，方向/from/to 都显式）
    if report.contract_interactions:
        print_contract_interactions(report, limit=30)

    print(f"\n{'='*60}\n")

    # 保存到文件
    if output_dir:
        import io, os
        os.makedirs(output_dir, exist_ok=True)
        fname = os.path.join(output_dir, f"{report.address}.txt")
        buf = io.StringIO()
        import sys as _sys
        _orig = _sys.stdout
        _sys.stdout = buf
        print_report(report, use_color=False, output_dir="")   # 无色版写入文件
        _sys.stdout = _orig
        with open(fname, "w", encoding="utf-8") as fh:
            fh.write(buf.getvalue())
        print(f"  [已保存] {fname}")


def export_json(report: RiskReport, path: str):
    import dataclasses
    with open(path, "w") as f:
        json.dump(dataclasses.asdict(report), f, ensure_ascii=False, indent=2)
    print(f"[INFO] JSON 报告已保存: {path}")


