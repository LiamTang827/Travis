"""
make_notebook.py — Convert aml_analyzer.py --json output → Colab notebook
Usage:
    PYTHONPATH=src python3 -m cripto_analyst.aml_analyzer --batch addresses.txt --json artifacts/reports/results.json
    python3 experiments/notebooks/make_notebook.py artifacts/reports/results.json [--out artifacts/reports/report.ipynb]
"""
import argparse
import json
import sys
from pathlib import Path
from typing import Optional
import nbformat as nbf

# ── Risk entity labels (mirrored from gen_colab_notebook.py) ─────────────────
ENTITY_LABELS = {
    "blacklist":               "🚫 Blacklist",
    "ofac_sanctioned":         "🛑 OFAC",
    "mixer":                   "🌀 Mixer",
    "high_risk_exchange":      "⚠ Hi-Risk Exch.",
    "exchange":                "🏦 Exchange",
    "opaque_bridge":           "🌉 Opaque Bridge",
    "transparent_bridge":      "🌉 Bridge",
    "2hop_blacklist":          "🔗 2-hop · Blacklist",
    "2hop_mixer":              "🔗 2-hop · Mixer",
    "2hop_opaque_bridge":      "🔗 2-hop · Opaque Bridge",
    "2hop_high_risk_exchange": "🔗 2-hop · Hi-Risk Exch.",
}

CATEGORY_WEIGHTS_1HOP = {
    "blacklist": 1.0, "ofac_sanctioned": 1.0,
    "ransomware": 1.0, "theft_hack": 1.0, "darknet": 1.0,
    "mixer": 0.5, "opaque_bridge": 0.5, "high_risk_exchange": 0.5,
    "transparent_bridge": 0.3,
    "exchange": None,
}

# ── Formatting helpers ────────────────────────────────────────────────────────
def _fmt_usd(v: float) -> str:
    if v == 0:
        return "$0.00"
    if v >= 1_000:
        return f"${v:,.2f}"
    return f"${v:.2f}"

def _fmt_pct(v: float) -> str:
    return f"{v:.2f}%"

def _fmt_entity(tags: list) -> str:
    if not tags:
        return "─"
    return " | ".join(ENTITY_LABELS.get(t, t) for t in tags)

def _fmt_eth_bal(account_info: dict) -> str:
    raw = account_info.get("balance", "")
    if not raw or raw == "─":
        return "─"
    try:
        parts = raw.split()
        val   = float(parts[0])
        token = parts[1] if len(parts) > 1 else "ETH"
        return f"{val:.3f} {token}"
    except Exception:
        return raw

def _weight_str(direct_tags: list, cp_taint: Optional[float]) -> str:
    """Return weight label for a counterparty row."""
    if direct_tags:
        for tag in direct_tags:
            w = CATEGORY_WEIGHTS_1HOP.get(tag)
            if w is not None:
                return str(w)
        return "─"
    if cp_taint is not None:
        return f"{cp_taint * 100:.2f}%"
    return "─"

# ── Core conversion: one RiskReport dict → notebook data dicts ───────────────
def report_to_data(r: dict) -> dict:
    addr   = r["address"]
    sb     = r.get("score_breakdown", {})
    assets = r.get("per_asset", {})
    inds   = r.get("indicators", [])
    cpt    = r.get("counterparty_table", [])

    total_in  = r.get("total_inflow_usdt",  0.0)   # 稳定币，用于污染分母
    total_out = r.get("total_outflow_usdt", 0.0)
    # % of Flow 分母：稳定币 + ETH（否则纯ETH地址分母为0）
    flow_in_all  = total_in  + r.get("total_eth_usd_in",  0.0)
    flow_out_all = total_out + r.get("total_eth_usd_out", 0.0)
    total_bal = round(sum(a.get("balance", 0) for a in assets.values()), 2)

    # ── SAMPLE_ROWS entry ─────────────────────────────────────────────
    chains     = r.get("chains_analyzed") or [r.get("chain", "ethereum")]
    chain_key  = chains[0] if len(chains) == 1 else "ethereum"
    warnings   = " // ".join(w for w in r.get("warnings", []) if w)

    row = {
        "address":              addr,
        "chain":                chain_key,
        "risk_level":           r["risk_level"],
        "score":                r["risk_score"],
        "stablecoin_inflow":    round(total_in,  2),
        "stablecoin_outflow":   round(total_out, 2),
        "stablecoin_balance":   total_bal,
        "eth_balance":          _fmt_eth_bal(r.get("account_info", {})),
        "blacklisted":          r.get("is_blacklisted", False),
        "fast_transit":         any(a.get("is_fast_transit") for a in assets.values()),
        "direct_blacklist_txs": sum(1 for i in inds if i["category"] in ("blacklist","ofac_sanctioned") and i["hop"] == 1),
        "mixer_txs":            sum(1 for i in inds if i["category"] == "mixer"         and i["hop"] == 1),
        "opaque_bridge_txs":    sum(1 for i in inds if i["category"] == "opaque_bridge" and i["hop"] == 1),
        "hop2_categories":      ",".join(sorted({i["category"] for i in inds if i["hop"] == 2 and i["amount_usdt"] > 0})),
        "received_taint_pct":   sb.get("received_taint_pct", 0.0),
        "sent_taint_pct":       sb.get("sent_taint_pct",     0.0),
        "warnings":             warnings,
    }

    # ── SAMPLE_ASSETS entries ─────────────────────────────────────────
    _STABLECOINS = {"USDT", "USDC", "DAI", "BUSD", "USDC.E", "USDCE", "USDB", "DOLA"}
    multi_chain = len({a["chain"] for a in assets.values()}) > 1
    asset_rows = []
    for key in sorted(assets.keys()):
        a = assets[key]
        if a["flow_in"] == 0 and a["flow_out"] == 0 and a["balance"] == 0:
            continue
        label = a["sym"] + (f" ({a['chain']})" if multi_chain else "")
        is_native = a["sym"] not in _STABLECOINS
        if is_native:
            sym = a["sym"]
            def _fmt_native(v, key=sym):
                return f"{v:,.4f} {key}" if v else "─"
            asset_rows.append({
                "Asset":    label,
                "Decimals": a.get("decimals", "native"),
                "Inflow":   _fmt_native(a.get("eth_amount_in",  a["flow_in"])),
                "Outflow":  _fmt_native(a.get("eth_amount_out", a["flow_out"])),
                "Balance":  _fmt_native(a.get("eth_balance",    a["balance"])),
                "Fast Transit": "⚡ Yes" if a.get("is_fast_transit") else "No",
            })
        else:
            asset_rows.append({
                "Asset":    label,
                "Decimals": a.get("decimals", "unknown"),
                "Inflow":   _fmt_usd(a["flow_in"]),
                "Outflow":  _fmt_usd(a["flow_out"]),
                "Balance":  _fmt_usd(a["balance"]),
                "Fast Transit": "⚡ Yes" if a.get("is_fast_transit") else "No",
            })

    # ── Extra asset rows from CP table (non-stable ERC20 not in per_asset) ──
    existing_syms = {a["sym"] for a in assets.values()}
    erc20_tok_in:  dict = {}
    erc20_tok_out: dict = {}
    for cp_row in cpt:
        if cp_row.get("contract_only"):
            continue
        direction = cp_row["direction"]
        for sym, amt in cp_row.get("by_sym", {}).items():
            if sym in _STABLECOINS or sym == "ETH" or sym in existing_syms:
                continue
            if direction == "IN":
                erc20_tok_in[sym]  = erc20_tok_in.get(sym, 0.0)  + amt
            else:
                erc20_tok_out[sym] = erc20_tok_out.get(sym, 0.0) + amt
    for sym in sorted(set(erc20_tok_in) | set(erc20_tok_out)):
        flow_in  = erc20_tok_in.get(sym,  0.0)
        flow_out = erc20_tok_out.get(sym, 0.0)
        asset_rows.append({
            "Asset":        sym,
            "Inflow":       f"{flow_in:,.4f} {sym}"  if flow_in  else "─",
            "Outflow":      f"{flow_out:,.4f} {sym}" if flow_out else "─",
            "Balance":      "─",
            "Fast Transit": "─",
        })

    # ── Build hop-2 index from indicators ─────────────────────────────
    # For 2-hop indicators, category_weight = cp's actual taint ratio (not
    # the constant category weight) — see aml_analyzer.py line 1267.
    hop2_idx = {}  # type: dict
    for ind in inds:
        if ind["hop"] != 2 or ind["amount_usdt"] == 0:  # skip presence_only
            continue
        cp  = ind["counterparty"].lower()
        cat = ind["category"]
        if cp not in hop2_idx:
            hop2_idx[cp] = {"cats": set(), "cp_taint": ind["category_weight"], "via": ind.get("via_address", "")}
        hop2_idx[cp]["cats"].add(cat)
        # Keep the highest cp_taint seen (in case of multiple risk contacts)
        hop2_idx[cp]["cp_taint"] = max(hop2_idx[cp]["cp_taint"], ind["category_weight"])

    # ── SAMPLE_HOP2 rows (deduplicated per intermediate) ─────────────
    seen_cp_dir = set()
    hop2_rows = []
    for ind in inds:
        if ind["hop"] != 2 or ind["amount_usdt"] == 0:
            continue
        key2 = (ind["counterparty"].lower(), ind["direction"], ind["category"])
        if key2 in seen_cp_dir:
            continue
        seen_cp_dir.add(key2)
        dir_sym = "←" if ind["direction"] == "IN" else "→"
        hop2_rows.append({
            "Dir":          dir_sym,
            "Intermediate": ind["counterparty"],
            "Risk Entity":  ind.get("via_address", "─") or "─",
            "Category":     _fmt_entity([ind["category"]]),
            "CP Taint %":   _fmt_pct(ind["category_weight"] * 100),
            "Amount (USD)": _fmt_usd(ind["amount_usdt"]),
        })

    # ── SAMPLE_COUNTERPARTIES rows ────────────────────────────────────
    MICRO_THRESHOLD = 0.01   # rows below this with no risk tags → collapsed

    # Helpers shared by both tables
    def _build_cp_entity(cp_lower):
        direct_tags   = next((r["risk_tags"] for r in cpt if r["address"].lower() == cp_lower), [])
        indirect_tags = []
        if cp_lower in hop2_idx:
            for cat in sorted(hop2_idx[cp_lower]["cats"]):
                tag = f"2hop_{cat}"
                if tag not in direct_tags:
                    indirect_tags.append(tag)
        return direct_tags, indirect_tags, direct_tags + indirect_tags

    # ── Stable CP table (stablecoins + contract interactions) ────────
    stable_cpt  = [r for r in cpt if r.get("stable_usd", 0) > 0]
    micro_stable = []
    vis_stable   = []
    for cp_row in stable_cpt:
        has_risk = bool(cp_row.get("risk_tags") or cp_row.get("contract_only"))
        if not has_risk and cp_row.get("stable_usd", cp_row["total_usd"]) < MICRO_THRESHOLD:
            micro_stable.append(cp_row)
        else:
            vis_stable.append(cp_row)

    cp_stable_rows = []
    for cp_row in vis_stable:
        cp_lower  = cp_row["address"].lower()
        direction = cp_row["direction"]
        dir_sym   = "←" if direction == "IN" else "→"
        stable_usd = cp_row.get("stable_usd", cp_row["total_usd"])
        basis      = total_in if direction == "IN" else total_out
        pct_flow   = (stable_usd / basis * 100) if basis > 0 else 0.0
        direct_tags, _, all_tags = _build_cp_entity(cp_lower)
        cp_taint_val = hop2_idx[cp_lower]["cp_taint"] if (cp_lower in hop2_idx and not direct_tags) else None
        by_sym = cp_row.get("by_sym", {})
        is_contact_only = cp_row.get("contract_only", False)
        cp_stable_rows.append({
            "Dir":       "📞" if is_contact_only else dir_sym,
            "Address":   cp_row["address"],
            "Total":     "contract interaction" if is_contact_only else _fmt_usd(stable_usd),
            "% of Flow": "─" if is_contact_only else _fmt_pct(pct_flow),
            "USDT":      _fmt_usd(by_sym["USDT"]) if "USDT" in by_sym else "─",
            "USDC":      _fmt_usd(by_sym["USDC"]) if "USDC" in by_sym else "─",
            "DAI":       _fmt_usd(by_sym["DAI"])  if "DAI"  in by_sym else "─",
            "Entity":    _fmt_entity(all_tags),
            "Weight":    _weight_str(direct_tags, cp_taint_val),
            "Taint %":   _fmt_pct(cp_row["taint_pct"]) if cp_row.get("taint_pct", 0) > 0 else "─",
        })
    if micro_stable:
        micro_in  = sum(r.get("stable_usd", 0) for r in micro_stable if r["direction"] == "IN")
        micro_out = sum(r.get("stable_usd", 0) for r in micro_stable if r["direction"] == "OUT")
        parts = []
        if micro_in  > 0: parts.append(f"in ${micro_in:.4f}")
        if micro_out > 0: parts.append(f"out ${micro_out:.4f}")
        cp_stable_rows.append({
            "Dir": "─",
            "Address": f"({len(micro_stable)} others, each < $0.01 — {' / '.join(parts) or '$0.00'})",
            "Total": "─", "% of Flow": "─",
            "USDT": "─", "USDC": "─", "DAI": "─",
            "Entity": "─", "Weight": "─", "Taint %": "─",
        })

    # ── Per-token CP tables (one per non-stable token found in any CP row) ───
    # ETH has USD equivalent stored; other tokens show raw amounts only
    eth_in_total  = r.get("total_eth_usd_in",  0.0)
    eth_out_total = r.get("total_eth_usd_out", 0.0)

    # Collect all non-stable tokens that appear in CP rows (excluding contract-only rows)
    all_tokens = sorted({
        sym
        for cp_row in cpt
        if not cp_row.get("contract_only")
        for sym in cp_row.get("by_sym", {})
        if sym not in _STABLECOINS
    })

    cp_tokens: dict = {}   # token → list of formatted rows
    for token in all_tokens:
        token_cpt = [
            cp_row for cp_row in cpt
            if token in cp_row.get("by_sym", {}) and not cp_row.get("contract_only")
        ]
        is_eth = (token == "ETH")
        # 计算该 token 的总 IN / OUT，作为 % of Flow 分母
        tok_total_in  = sum(cr["by_sym"].get(token, 0.0) for cr in token_cpt if cr["direction"] == "IN")
        tok_total_out = sum(cr["by_sym"].get(token, 0.0) for cr in token_cpt if cr["direction"] == "OUT")
        micro_tok, vis_tok = [], []
        for cp_row in token_cpt:
            tok_amt = cp_row["by_sym"].get(token, 0.0)
            has_risk = bool(cp_row.get("risk_tags"))
            # micro filter: for ETH use USD equivalent; for others use raw amount < 1e-6
            if is_eth:
                tok_usd = cp_row.get("native_usd", 0.0)
                is_micro = not has_risk and tok_usd < MICRO_THRESHOLD
            else:
                is_micro = not has_risk and tok_amt < 1e-6
            if is_micro:
                micro_tok.append(cp_row)
            else:
                vis_tok.append(cp_row)

        rows = []
        for cp_row in vis_tok:
            cp_lower  = cp_row["address"].lower()
            direction = cp_row["direction"]
            dir_sym   = "←" if direction == "IN" else "→"
            tok_amt   = cp_row["by_sym"].get(token, 0.0)
            direct_tags, _, all_tags = _build_cp_entity(cp_lower)
            cp_taint_val = hop2_idx[cp_lower]["cp_taint"] if (cp_lower in hop2_idx and not direct_tags) else None
            if is_eth:
                tok_usd  = cp_row.get("native_usd", 0.0)
                basis    = eth_in_total if direction == "IN" else eth_out_total
                pct_flow = _fmt_pct(tok_usd / basis * 100) if basis > 0 else "─"
                dec = 6
            else:
                basis    = tok_total_in if direction == "IN" else tok_total_out
                pct_flow = _fmt_pct(tok_amt / basis * 100) if basis > 0 else "─"
                dec = 6
            rows.append({
                "Dir":       dir_sym,
                "Address":   cp_row["address"],
                token:       f"{tok_amt:,.{dec}f} {token}",
                "% of Flow": pct_flow,
                "Entity":    _fmt_entity(all_tags),
                "Weight":    _weight_str(direct_tags, cp_taint_val),
                "Taint %":   _fmt_pct(cp_row["taint_pct"]) if cp_row.get("taint_pct", 0) > 0 else "─",
            })
        if micro_tok:
            in_amt  = sum(cr["by_sym"].get(token, 0) for cr in micro_tok if cr["direction"] == "IN")
            out_amt = sum(cr["by_sym"].get(token, 0) for cr in micro_tok if cr["direction"] == "OUT")
            parts = []
            if in_amt  > 0: parts.append(f"in {in_amt:.6f} {token}")
            if out_amt > 0: parts.append(f"out {out_amt:.6f} {token}")
            rows.append({
                "Dir": "─",
                "Address": f"({len(micro_tok)} others, each negligible — {' / '.join(parts) or '0'})",
                token: "─", "% of Flow": "─",
                "Entity": "─", "Weight": "─", "Taint %": "─",
            })
        if rows:
            cp_tokens[token] = rows

    return {"row": row, "assets": asset_rows,
            "cp_stable": cp_stable_rows, "cp_tokens": cp_tokens,
            "hop2": hop2_rows}


# ── Cell content strings ──────────────────────────────────────────────────────
DISPLAY_FUNCTIONS_CELL = '''\
RISK_CONFIG = {
    "LOW":      {"bg": "#d4edda", "border": "#28a745", "text": "#155724", "label": "LOW RISK"},
    "MEDIUM":   {"bg": "#fff3cd", "border": "#ffc107", "text": "#856404", "label": "MEDIUM RISK"},
    "HIGH":     {"bg": "#f8d7da", "border": "#dc3545", "text": "#721c24", "label": "HIGH RISK"},
    "CRITICAL": {"bg": "#721c24", "border": "#491217", "text": "#ffffff", "label": "CRITICAL RISK"},
}

ENTITY_LABELS = {
    "blacklist":               "🚫 Blacklist",
    "ofac_sanctioned":         "🛑 OFAC",
    "mixer":                   "🌀 Mixer",
    "high_risk_exchange":      "⚠ Hi-Risk Exch.",
    "exchange":                "🏦 Exchange",
    "opaque_bridge":           "🌉 Opaque Bridge",
    "transparent_bridge":      "🌉 Bridge",
    "2hop_blacklist":          "🔗 2-hop · Blacklist",
    "2hop_mixer":              "🔗 2-hop · Mixer",
    "2hop_opaque_bridge":      "🔗 2-hop · Opaque Bridge",
    "2hop_high_risk_exchange": "🔗 2-hop · Hi-Risk Exch.",
}

def _score_color(score):
    if score >= 80: return "#dc3545"
    if score >= 45: return "#fd7e14"
    if score >= 20: return "#ffc107"
    return "#28a745"

def _fmt_entity(tags):
    if not tags:
        return "─"
    return " | ".join(ENTITY_LABELS.get(t, t) for t in tags)

def _style_dir(val):
    if val == "←": return "color:#28a745;font-weight:bold;font-size:1.1em"
    if val == "→": return "color:#dc3545;font-weight:bold;font-size:1.1em"
    return ""

def _style_taint(val):
    if str(val) in ("─", "", "nan"): return ""
    try:
        v = float(str(val).replace("%", "").strip())
        if v >= 50: return "color:#dc3545;font-weight:bold"
        if v >= 20: return "color:#fd7e14;font-weight:bold"
        if v >  0:  return "color:#856404"
    except Exception:
        pass
    return ""

def _style_entity(val):
    if "Blacklist" in str(val) or "OFAC" in str(val):
        return "color:#dc3545;font-weight:bold"
    if "Mixer" in str(val) or "Opaque" in str(val):
        return "color:#fd7e14;font-weight:bold"
    if "Hi-Risk" in str(val):
        return "color:#fd7e14"
    return ""

def display_address_report(row, asset_rows=None, cp_stable=None, cp_tokens=None, hop2_rows=None):
    level = row["risk_level"]
    cfg   = RISK_CONFIG.get(level, RISK_CONFIG["LOW"])
    score = row["score"]
    addr  = row["address"]
    bg, border, text_col, label = cfg["bg"], cfg["border"], cfg["text"], cfg["label"]
    if level == "CRITICAL":
        text_col = "#fff"
    sc = _score_color(score)
    chain_map = {
        "ethereum": "Ethereum", "bsc": "BSC", "tron": "Tron",
        "polygon": "Polygon", "arbitrum": "Arbitrum", "optimism": "Optimism",
        "avalanche": "Avalanche", "base": "Base",
    }
    chain_label = chain_map.get(row.get("chain", "ethereum"), row.get("chain", "Ethereum"))
    score_str = f"{float(score):.2f}"

    display(HTML(
        f"<div style=\'background:{bg};border-left:5px solid {border};"
        f"border-radius:6px;padding:14px 18px;margin:28px 0 10px 0\'>"
        f"<div style=\'display:flex;justify-content:space-between;align-items:center\'>"
        f"<div>"
        f"  <div style=\'font-size:0.8em;color:#888;margin-bottom:4px\'>{chain_label}</div>"
        f"  <code style=\'font-size:0.92em;color:#333;word-break:break-all\'>{addr}</code>"
        f"</div>"
        f"<div style=\'text-align:right;flex-shrink:0;margin-left:16px\'>"
        f"  <span style=\'background:{border};color:{text_col};"
        f"  padding:3px 12px;border-radius:20px;font-weight:bold;font-size:0.82em\'>{label}</span>"
        f"  <div style=\'margin-top:6px\'>"
        f"    <span style=\'font-size:2.2em;font-weight:bold;color:{sc}\'>{score_str}</span>"
        f"    <span style=\'color:#aaa;font-size:0.85em\'> / 100</span>"
        f"  </div>"
        f"</div></div></div>"
    ))

    inflow  = float(row.get("stablecoin_inflow",  0) or 0)
    outflow = float(row.get("stablecoin_outflow", 0) or 0)
    balance = float(row.get("stablecoin_balance", 0) or 0)
    eth_bal = row.get("eth_balance", "─")

    df_s = pd.DataFrame({
        "Item": [
            "Total Stablecoin Inflow (USD)",
            "Total Stablecoin Outflow (USD)",
            "Stablecoin Balance (USD)",
            "ETH Balance",
        ],
        "Value": [
            f"$ {inflow:>20,.2f}",
            f"$ {outflow:>20,.2f}",
            f"$ {balance:>20,.2f}",
            eth_bal,
        ]
    })
    display(df_s.style
        .set_caption("📊 Summary")
        .hide(axis="index")
        .set_properties(**{"padding": "7px 16px", "text-align": "left", "white-space": "pre-wrap"})
        .set_table_styles([
            {"selector": "th",
             "props": [("background", "#f5f5f5"), ("font-weight", "bold"), ("padding", "8px 16px")]},
            {"selector": "caption",
             "props": [("font-size", "1em"), ("font-weight", "bold"),
                       ("padding", "8px 0"), ("text-align", "left")]},
        ])
    )

    if asset_rows:
        df_a = pd.DataFrame(asset_rows)
        display(df_a.style
            .set_caption("💰 Asset Breakdown")
            .hide(axis="index")
            .set_properties(**{"padding": "7px 16px", "text-align": "right"})
            .set_table_styles([
                {"selector": "th",
                 "props": [("background", "#f5f5f5"), ("font-weight", "bold"),
                           ("padding", "8px 16px"), ("text-align", "left")]},
                {"selector": "td:first-child",
                 "props": [("text-align", "left"), ("font-weight", "bold")]},
                {"selector": "caption",
                 "props": [("font-size", "1em"), ("font-weight", "bold"),
                           ("padding", "8px 0"), ("text-align", "left")]},
            ])
        )

    def _render_cp_table(rows, caption, num_cols, bg="#f5f5f5"):
        if not rows:
            return
        df = pd.DataFrame(rows)
        styled = (df.style
            .set_caption(caption)
            .hide(axis="index")
            .map(_style_dir,    subset=["Dir"])
            .map(_style_taint,  subset=["Taint %"])
            .map(_style_entity, subset=["Entity"])
            .set_properties(**{
                "padding":     "7px 14px",
                "font-family": "monospace",
                "font-size":   "0.88em",
                "text-align":  "left",
            })
            .set_table_styles([
                {"selector": "th",
                 "props": [("background", bg), ("font-weight", "bold"),
                           ("padding", "8px 14px"), ("white-space", "nowrap")]},
                {"selector": "td",
                 "props": [("white-space", "nowrap")]},
                {"selector": "caption",
                 "props": [("font-size", "1em"), ("font-weight", "bold"),
                           ("padding", "8px 0"), ("text-align", "left")]},
            ])
        )
        existing_num = [c for c in num_cols if c in df.columns]
        if existing_num:
            styled = styled.set_properties(subset=existing_num, **{"text-align": "right"})
        display(styled)

    _render_cp_table(
        cp_stable,
        "💵 Counterparty Flow — Stablecoins",
        ["Total", "% of Flow", "USDT", "USDC", "DAI", "Weight", "Taint %"],
    )
    for token, token_rows in (cp_tokens or {}).items():
        _render_cp_table(
            token_rows,
            f"🔷 Counterparty Flow — {token}",
            [token, "% of Flow", "Weight", "Taint %"],
            bg="#f0f8f0",
        )

    if hop2_rows:
        display(HTML(
            "<div style=\'background:#f0f4ff;border-left:4px solid #6c8ebf;"
            "border-radius:4px;padding:8px 14px;margin:12px 0 6px 0;"
            "font-size:0.85em;color:#3a4a6b\'>"
            "<b>🔗 2-hop Indirect Exposure</b> — "
            "We did not transact directly with the risk entity. "
            "The <i>intermediate</i> address we dealt with itself had exposure to a risk entity. "
            "Contribution to score is weighted by the intermediate\'s own taint ratio."
            "</div>"
        ))
        df_h2 = pd.DataFrame(hop2_rows)
        styled2 = (df_h2.style
            .set_caption("🔗 2-hop Indirect Exposure")
            .hide(axis="index")
            .map(_style_dir,    subset=["Dir"])
            .map(_style_taint,  subset=["CP Taint %"])
            .map(_style_entity, subset=["Category"])
            .set_properties(**{
                "padding":     "7px 14px",
                "font-family": "monospace",
                "font-size":   "0.88em",
                "text-align":  "left",
            })
            .set_table_styles([
                {"selector": "th",
                 "props": [("background", "#eef2ff"), ("font-weight", "bold"),
                           ("padding", "8px 14px"), ("white-space", "nowrap")]},
                {"selector": "td",
                 "props": [("white-space", "nowrap")]},
                {"selector": "caption",
                 "props": [("font-size", "1em"), ("font-weight", "bold"),
                           ("padding", "8px 0"), ("text-align", "left")]},
            ])
        )
        num2 = ["Amount (USD)", "CP Taint %"]
        existing2 = [c for c in num2 if c in df_h2.columns]
        if existing2:
            styled2 = styled2.set_properties(subset=existing2, **{"text-align": "right"})
        display(styled2)

    rec_pct  = float(row.get("received_taint_pct", 0) or 0)
    sent_pct = float(row.get("sent_taint_pct",     0) or 0)
    final    = max(rec_pct, sent_pct)
    dominant = "Received" if rec_pct >= sent_pct else "Sent"
    rec_col  = _score_color(rec_pct)  if rec_pct  > 0 else "#888"
    sent_col = _score_color(sent_pct) if sent_pct > 0 else "#888"
    fin_col  = _score_color(final)
    display(HTML(
        f"<div style=\'background:#f8f9fa;border:1px solid #dee2e6;border-radius:6px;"
        f"padding:12px 18px;margin:10px 0;font-family:monospace;font-size:0.9em\'>"
        f"<div style=\'font-weight:bold;margin-bottom:8px;color:#495057\'>"
        f"📐 Score Breakdown"
        f"<span style=\'font-size:0.8em;font-weight:normal;color:#888\'>"
        f" &nbsp;(score = max of received / sent taint, each = Σ Weight × % of flow)</span></div>"
        f"<table style=\'border-collapse:collapse;width:auto\'>"
        f"<tr>"
        f"<td style=\'padding:4px 16px 4px 0;color:#555\'>Received Side</td>"
        f"<td style=\'padding:4px 16px 4px 0;font-weight:bold;color:{rec_col}\'>{rec_pct:.2f}%</td>"
        f"<td style=\'padding:4px 0;color:#aaa;font-size:0.85em\'>"
        f"Σ (Weight × % of inflow) across risky counterparties</td>"
        f"</tr>"
        f"<tr>"
        f"<td style=\'padding:4px 16px 4px 0;color:#555\'>Sent Side</td>"
        f"<td style=\'padding:4px 16px 4px 0;font-weight:bold;color:{sent_col}\'>{sent_pct:.2f}%</td>"
        f"<td style=\'padding:4px 0;color:#aaa;font-size:0.85em\'>"
        f"Σ (Weight × % of outflow) across risky counterparties</td>"
        f"</tr>"
        f"<tr style=\'border-top:1px solid #dee2e6\'>"
        f"<td style=\'padding:8px 16px 4px 0;color:#333;font-weight:bold\'>Final Score</td>"
        f"<td style=\'padding:8px 16px 4px 0;font-weight:bold;font-size:1.15em;color:{fin_col}\'>"
        f"{final:.2f} / 100</td>"
        f"<td style=\'padding:8px 0 4px 0;color:#aaa;font-size:0.85em\'>"
        f"max({rec_pct:.2f}, {sent_pct:.2f}) — {dominant}-side driven</td>"
        f"</tr>"
        f"</table></div>"
    ))

    warn_str = str(row.get("warnings", "")).strip()
    if warn_str and warn_str not in ("", "nan"):
        parts   = [p.strip() for p in warn_str.split("//") if p.strip()]
        li_html = "".join(f"<li style=\'margin:4px 0\'>{p}</li>" for p in parts)
        display(HTML(
            f"<div style=\'background:#fff3cd;border:1px solid #ffc107;"
            f"border-radius:4px;padding:10px 16px;margin:8px 0\'>"
            f"<strong>⚠ System Flags</strong>"
            f"<ul style=\'margin:6px 0 0 16px;padding:0\'>{li_html}</ul>"
            f"</div>"
        ))

    display(HTML("<hr style=\'border:none;border-top:2px solid #efefef;margin:28px 0\'>"))

print("✅ Display functions ready")
'''

# ── Notebook builder ──────────────────────────────────────────────────────────
RISK_EMOJI = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "⛔"}

def build_notebook(reports: list, title: str = "On-Chain AML Risk Analysis Report") -> nbf.NotebookNode:
    nb = nbf.v4.new_notebook()
    nb.metadata = {
        "colab": {"provenance": []},
        "kernelspec": {"display_name": "Python 3", "name": "python3"},
        "language_info": {"name": "python"},
    }
    cells = []

    # Cell 0 — Title
    cells.append(nbf.v4.new_markdown_cell(
        f"# {title}\n\n"
        f"**Addresses analysed:** {len(reports)}  \n"
        f"**Analysis window:** last 365 days of on-chain activity\n\n"
        f"Stablecoin amounts are normalized using the token decimals saved by the analyzer.\n\n"
        f"> Run all cells (`Runtime → Run all`) to render all reports.\n"
    ))

    # Cell 1 — Imports
    cells.append(nbf.v4.new_code_cell(
        "import pandas as pd\n"
        "from IPython.display import display, HTML\n"
        "pd.set_option('display.max_colwidth', None)\n"
        "print('✅ Dependencies loaded')\n"
    ))

    # Cell 2 — Display functions
    cells.append(nbf.v4.new_code_cell(DISPLAY_FUNCTIONS_CELL))

    # Cell 3 — Data cell: REPORTS dict keyed by address
    data_lines = ["# Auto-generated from AML analysis — do not edit manually\n", "REPORTS = {}"]
    for d in reports:
        addr = d["row"]["address"]
        data_lines.append(f"\nREPORTS[{repr(addr)}] = {{")
        data_lines.append(f"    'row':       {repr(d['row'])},")
        data_lines.append(f"    'assets':    {repr(d['assets'])},")
        data_lines.append(f"    'cp_stable': {repr(d['cp_stable'])},")
        data_lines.append(f"    'cp_tokens': {repr(d['cp_tokens'])},")
        data_lines.append(f"    'hop2':      {repr(d['hop2'])},")
        data_lines.append("}")
    data_lines.append(f"\nprint(f'✅ Loaded {{len(REPORTS)}} addresses')")
    cells.append(nbf.v4.new_code_cell("\n".join(data_lines)))

    # Cell 4+ — One markdown + one code cell per address
    for i, d in enumerate(reports, start=1):
        row    = d["row"]
        addr   = row["address"]
        level  = row["risk_level"]
        score  = row["score"]
        short  = addr[:6] + "..." + addr[-4:]
        emoji  = RISK_EMOJI.get(level, "⚪")

        cells.append(nbf.v4.new_markdown_cell(
            f"## Address {i} · {short} &nbsp; {emoji} {level} ({float(score):.2f}/100)\n"
            f"\n`{addr}`"
        ))
        cells.append(nbf.v4.new_code_cell(
            f'd = REPORTS[{repr(addr)}]\n'
            f'display_address_report(d["row"], d["assets"], d["cp_stable"], d["cp_tokens"], d["hop2"])\n'
        ))

    nb.cells = cells
    return nb


# ── CLI entry point ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Convert AML JSON results to Colab notebook")
    parser.add_argument("json_file", help="JSON file produced by aml_analyzer.py --json")
    parser.add_argument("--out", default="", help="Output .ipynb path (default: same name as JSON)")
    parser.add_argument("--title", default="On-Chain AML Risk Analysis Report", help="Notebook title")
    args = parser.parse_args()

    json_path = Path(args.json_file)
    if not json_path.exists():
        print(f"[ERROR] File not found: {json_path}", file=sys.stderr)
        sys.exit(1)

    out_path = Path(args.out) if args.out else json_path.with_suffix(".ipynb")

    print(f"[*] Reading {json_path} ...")
    with open(json_path, encoding="utf-8") as f:
        raw = json.load(f)

    # Accept both a list of reports and a single report dict
    if isinstance(raw, dict):
        raw = [raw]

    print(f"[*] Converting {len(raw)} reports ...")
    reports_data = []
    for r in raw:
        try:
            reports_data.append(report_to_data(r))
        except Exception as e:
            print(f"[WARN] Skipping {r.get('address','?')}: {e}")

    nb = build_notebook(reports_data, title=args.title)

    with open(out_path, "w", encoding="utf-8") as f:
        nbf.write(nb, f)

    print(f"[✓] Notebook written: {out_path}  ({len(reports_data)} addresses)")


if __name__ == "__main__":
    main()
