"""Generate Colab sample notebook (English version)"""
import nbformat as nbf

nb = nbf.v4.new_notebook()
nb.metadata = {
    "colab": {"provenance": []},
    "kernelspec": {"display_name": "Python 3", "name": "python3"},
    "language_info": {"name": "python"},
}

cells = []

# ── Cell 0: Title ─────────────────────────────────────────────────────────────
cells.append(nbf.v4.new_markdown_cell("""\
# On-Chain AML Risk Analysis Report

Each address is analyzed and displayed independently with:
- Risk score & level
- Stablecoin flow summary (inflows / outflows / balance)
- Per-asset breakdown (USDT / USDC / DAI / ...)
- Counterparty risk detail table

> **Analysis window**: last 365 days of on-chain activity.
>
> **How to use**: Run all cells (`Runtime → Run all`).
> To analyze your own addresses, replace the data in the **Sample Data** cell.
"""))

# ── Cell 1: Imports ───────────────────────────────────────────────────────────
cells.append(nbf.v4.new_code_cell("""\
import pandas as pd
from IPython.display import display, HTML
pd.set_option('display.max_colwidth', None)
print('✅ Dependencies loaded')
"""))

# ── Cell 2: Display functions ─────────────────────────────────────────────────
cells.append(nbf.v4.new_code_cell('''\
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

def display_address_report(row, asset_rows=None, cp_rows=None, hop2_rows=None):
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

    if cp_rows:
        df_cp = pd.DataFrame(cp_rows)
        styled = (df_cp.style
            .set_caption("🔍 Counterparty Risk Detail (Direct / 1-hop)")
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
                 "props": [("background", "#f5f5f5"), ("font-weight", "bold"),
                           ("padding", "8px 14px"), ("white-space", "nowrap")]},
                {"selector": "td",
                 "props": [("white-space", "nowrap")]},
                {"selector": "caption",
                 "props": [("font-size", "1em"), ("font-weight", "bold"),
                           ("padding", "8px 0"), ("text-align", "left")]},
            ])
        )
        num_cols = ["Total (USD)", "% of Flow", "USDT", "USDC", "DAI", "Weight", "Taint %", "ETH Bal."]
        existing_num = [c for c in num_cols if c in df_cp.columns]
        if existing_num:
            styled = styled.set_properties(subset=existing_num, **{"text-align": "right"})
        display(styled)

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

    # ── Scoring summary ───────────────────────────────────────────────
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
'''))

# ── Cell 3: Sample data ───────────────────────────────────────────────────────
cells.append(nbf.v4.new_code_cell('''\
# ══════════════════════════════════════════════════════════════════════
#  Replace with your own analysis results.
#
#  Weight reference (counterparty table):
#    1.0       : blacklist / OFAC (direct / 1-hop)
#    0.5       : mixer / opaque_bridge / high_risk_exchange (direct / 1-hop)
#    0.3       : transparent_bridge (direct / 1-hop)
#    CP Taint% : for 2-hop intermediates (their own contamination ratio)
#    "─"       : clean counterparty — no taint contribution
#
#  Taint % = Weight × (% of Flow)   → contribution to the address score
#  Score   = max(received_taint_pct, sent_taint_pct)   (capped at 100)
# ══════════════════════════════════════════════════════════════════════

SAMPLE_ROWS = [
    {
        "address": "0x7e0ff1c8a125164c802de93b5e15e9474b3bb9b0",
        "chain": "ethereum", "risk_level": "LOW", "score": 15.20,
        "stablecoin_inflow": 353770.5, "stablecoin_outflow": 353770.5, "stablecoin_balance": 0.0,
        "eth_balance": "0.003 ETH",
        "blacklisted": False, "ofac_sanctioned": False, "fast_transit": True,
        "direct_blacklist_txs": 1, "mixer_txs": 0, "opaque_bridge_txs": 0,
        "hop2_categories": "",
        "received_taint_pct": 15.20, "sent_taint_pct": 0.0,
        "warnings": "[Ethereum][USDT] Fast transit: inflow $353,771 / outflow $353,771 / balance $0.00",
    },
    {
        "address": "0xbbe73a38b834c5434ebce85eb0fbe6556f528250",
        "chain": "ethereum", "risk_level": "LOW", "score": 6.77,
        "stablecoin_inflow": 363025574.63, "stablecoin_outflow": 362223193.0, "stablecoin_balance": 2381.63,
        "eth_balance": "1.240 ETH",
        "blacklisted": False, "ofac_sanctioned": False, "fast_transit": True,
        "direct_blacklist_txs": 0, "mixer_txs": 0, "opaque_bridge_txs": 0,
        "hop2_categories": "",
        "received_taint_pct": 5.09, "sent_taint_pct": 6.77,
        "warnings": (
            "[Ethereum][USDT] Fast transit: inflow $143,120,696 / outflow $143,119,062 / balance $1,634.02 //"
            " [Ethereum][USDC] Fast transit: inflow $219,904,879 / outflow $219,104,131 / balance $747.61"
        ),
    },
    {
        "address": "0x6666ea71b7c52b61fde5faed791902937986ee1c",
        "chain": "ethereum", "risk_level": "CRITICAL", "score": 99.99,
        "stablecoin_inflow": 5617.58, "stablecoin_outflow": 5617.58, "stablecoin_balance": 0.0,
        "eth_balance": "0.000 ETH",
        "blacklisted": False, "ofac_sanctioned": False, "fast_transit": False,
        "direct_blacklist_txs": 2, "mixer_txs": 0, "opaque_bridge_txs": 0,
        "hop2_categories": "",
        "received_taint_pct": 99.99, "sent_taint_pct": 0.0,
        "warnings": "",
    },
    {
        "address": "0xd21711a50be597d1a4368bc13fe3e0eb543cdff3",
        "chain": "ethereum", "risk_level": "MEDIUM", "score": 30.30,
        "stablecoin_inflow": 1400990.4, "stablecoin_outflow": 1400990.4, "stablecoin_balance": 0.0,
        "eth_balance": "0.011 ETH",
        "blacklisted": False, "ofac_sanctioned": False, "fast_transit": True,
        "direct_blacklist_txs": 1, "mixer_txs": 0, "opaque_bridge_txs": 0,
        "hop2_categories": "",
        "received_taint_pct": 30.30, "sent_taint_pct": 0.0,
        "warnings": (
            "[Ethereum][USDT] Fast transit: inflow $199,990 / outflow $199,990 / balance $0.00 //"
            " [Ethereum][DAI] Fast transit: inflow $1,201,000 / outflow $1,201,000 / balance $0.00"
        ),
    },
    {
        "address": "0xe4d67f9404ccafdb1c83a003583fb5062b9bc32e",
        "chain": "ethereum", "risk_level": "HIGH", "score": 52.30,
        "stablecoin_inflow": 5523.16, "stablecoin_outflow": 5523.16, "stablecoin_balance": 0.0,
        "eth_balance": "0.215 ETH",
        "blacklisted": False, "ofac_sanctioned": False, "fast_transit": False,
        "direct_blacklist_txs": 0, "mixer_txs": 0, "opaque_bridge_txs": 0,
        "hop2_categories": "blacklist",
        "received_taint_pct": 0.0, "sent_taint_pct": 52.30,
        "warnings": "",
    },
    {
        "address": "0x5e8e3925cd81f0839812db5e373b5a7f7098bc37",
        "chain": "ethereum", "risk_level": "LOW", "score": 0.0,
        "stablecoin_inflow": 199.95, "stablecoin_outflow": 199.95, "stablecoin_balance": 0.0,
        "eth_balance": "0.008 ETH",
        "blacklisted": False, "ofac_sanctioned": False, "fast_transit": False,
        "direct_blacklist_txs": 0, "mixer_txs": 0, "opaque_bridge_txs": 0,
        "hop2_categories": "",
        "received_taint_pct": 0.0, "sent_taint_pct": 0.0,
        "warnings": "",
    },
    {
        "address": "0x4dcb190f5a3b0a66a4fb88ea6b3b950ac506bb3d",
        "chain": "ethereum", "risk_level": "LOW", "score": 0.0,
        "stablecoin_inflow": 0.0, "stablecoin_outflow": 0.0, "stablecoin_balance": 0.0,
        "eth_balance": "0.000 ETH",
        "blacklisted": False, "ofac_sanctioned": False, "fast_transit": False,
        "direct_blacklist_txs": 0, "mixer_txs": 0, "opaque_bridge_txs": 0,
        "hop2_categories": "",
        "received_taint_pct": 0.0, "sent_taint_pct": 0.0,
        "warnings": "No stablecoin transactions found. Score based on association only — accuracy limited.",
    },
]

# ── Per-asset breakdown ───────────────────────────────────────────────────────
SAMPLE_ASSETS = {
    "0x7e0ff1c8a125164c802de93b5e15e9474b3bb9b0": [
        {"Asset": "USDT", "Inflow (USD)": "$353,770", "Outflow (USD)": "$353,770", "Balance": "$0.00", "Fast Transit": "⚡ Yes"},
    ],
    "0xbbe73a38b834c5434ebce85eb0fbe6556f528250": [
        {"Asset": "USDC", "Inflow (USD)": "$219,904,879", "Outflow (USD)": "$219,104,131", "Balance": "$747.61", "Fast Transit": "⚡ Yes"},
        {"Asset": "USDT", "Inflow (USD)": "$143,120,696", "Outflow (USD)": "$143,119,062", "Balance": "$1,634.02", "Fast Transit": "⚡ Yes"},
    ],
    "0x6666ea71b7c52b61fde5faed791902937986ee1c": [
        {"Asset": "USDC", "Inflow (USD)": "$5,284", "Outflow (USD)": "$5,284", "Balance": "$0.00", "Fast Transit": "No"},
        {"Asset": "USDT", "Inflow (USD)": "$334",   "Outflow (USD)": "$334",   "Balance": "$0.00", "Fast Transit": "No"},
    ],
    "0xd21711a50be597d1a4368bc13fe3e0eb543cdff3": [
        {"Asset": "DAI",  "Inflow (USD)": "$1,201,000", "Outflow (USD)": "$1,201,000", "Balance": "$0.00", "Fast Transit": "⚡ Yes"},
        {"Asset": "USDT", "Inflow (USD)": "$199,990",   "Outflow (USD)": "$199,990",   "Balance": "$0.00", "Fast Transit": "⚡ Yes"},
    ],
    "0xe4d67f9404ccafdb1c83a003583fb5062b9bc32e": [
        {"Asset": "USDT", "Inflow (USD)": "$5,523", "Outflow (USD)": "$5,523", "Balance": "$0.00", "Fast Transit": "No"},
    ],
    "0x5e8e3925cd81f0839812db5e373b5a7f7098bc37": [
        {"Asset": "USDT", "Inflow (USD)": "$200", "Outflow (USD)": "$200", "Balance": "$0.00", "Fast Transit": "No"},
    ],
}

# ── Counterparty risk detail ──────────────────────────────────────────────────
# Weight : 1.0 = blacklist/OFAC | 0.5 = mixer/opaque_bridge/hi-risk exch.
#          CP Taint% for 2-hop intermediates | "─" for clean
# Taint %: Weight × (% of Flow) — taint contribution from this counterparty
SAMPLE_COUNTERPARTIES = {
    "0x7e0ff1c8a125164c802de93b5e15e9474b3bb9b0": [
        {"Dir": "←", "Address": "0xa3c2f1e8d4b7c9a0f5e2d1b8c4a7e3f6d9b2a5c8",
         "Total (USD)": "$300,000", "% of Flow": "84.80%",
         "USDT": "$300,000", "USDC": "─", "DAI": "─",
         "Entity": _fmt_entity([]), "Weight": "─", "Taint %": "─", "ETH Bal.": "2.310 ETH"},
        {"Dir": "←", "Address": "0xf2e4b6d8a0c1e3f5b7d9a2c4e6f8b0d2a4c6e8f0",
         "Total (USD)": "$53,770",  "% of Flow": "15.20%",
         "USDT": "$53,770",  "USDC": "─", "DAI": "─",
         "Entity": _fmt_entity(["blacklist"]), "Weight": "1.0", "Taint %": "15.20%", "ETH Bal.": "0.000 ETH"},
        {"Dir": "→", "Address": "0xb1d3f5a7c9e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0",
         "Total (USD)": "$353,770", "% of Flow": "100.0%",
         "USDT": "$353,770", "USDC": "─", "DAI": "─",
         "Entity": _fmt_entity([]), "Weight": "─", "Taint %": "─", "ETH Bal.": "0.540 ETH"},
    ],
    "0xbbe73a38b834c5434ebce85eb0fbe6556f528250": [
        {"Dir": "←", "Address": "0x3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c",
         "Total (USD)": "$219,904,879", "% of Flow": "60.58%",
         "USDT": "─", "USDC": "$219,904,879", "DAI": "─",
         "Entity": _fmt_entity(["2hop_high_risk_exchange"]),
         "Weight": "8.40%", "Taint %": "5.09%", "ETH Bal.": "12.450 ETH"},
        {"Dir": "←", "Address": "0x9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7",
         "Total (USD)": "$143,120,696", "% of Flow": "39.42%",
         "USDT": "$143,120,696", "USDC": "─", "DAI": "─",
         "Entity": _fmt_entity([]), "Weight": "─", "Taint %": "─", "ETH Bal.": "8.120 ETH"},
        {"Dir": "→", "Address": "0xc2e4f6a8b0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0",
         "Total (USD)": "$219,104,131", "% of Flow": "60.49%",
         "USDT": "─", "USDC": "$219,104,131", "DAI": "─",
         "Entity": _fmt_entity(["exchange", "2hop_opaque_bridge"]),
         "Weight": "11.2%", "Taint %": "6.77%", "ETH Bal.": "450.000 ETH"},
        {"Dir": "→", "Address": "0xd4f6a8b0c2e4f6a8b0d2e4f6a8b0c2d4e6f8a0b2",
         "Total (USD)": "$143,119,062", "% of Flow": "39.51%",
         "USDT": "$143,119,062", "USDC": "─", "DAI": "─",
         "Entity": _fmt_entity(["exchange"]), "Weight": "─", "Taint %": "─", "ETH Bal.": "380.000 ETH"},
    ],
    "0x6666ea71b7c52b61fde5faed791902937986ee1c": [
        {"Dir": "←", "Address": "0xe1f3b5d7a9c1e3f5b7d9a1c3e5f7b9d1a3c5e7f9",
         "Total (USD)": "$3,000", "% of Flow": "53.41%",
         "USDT": "─", "USDC": "$3,000", "DAI": "─",
         "Entity": _fmt_entity(["blacklist"]), "Weight": "1.0", "Taint %": "53.41%", "ETH Bal.": "0.000 ETH"},
        {"Dir": "←", "Address": "0xf2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0",
         "Total (USD)": "$2,617", "% of Flow": "46.58%",
         "USDT": "$334", "USDC": "$2,283", "DAI": "─",
         "Entity": _fmt_entity(["blacklist"]), "Weight": "1.0", "Taint %": "46.58%", "ETH Bal.": "0.000 ETH"},
        {"Dir": "→", "Address": "0xa3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1",
         "Total (USD)": "$5,617", "% of Flow": "100.0%",
         "USDT": "$334", "USDC": "$5,283", "DAI": "─",
         "Entity": _fmt_entity([]), "Weight": "─", "Taint %": "─", "ETH Bal.": "0.872 ETH"},
    ],
    "0xd21711a50be597d1a4368bc13fe3e0eb543cdff3": [
        {"Dir": "←", "Address": "0xb4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2",
         "Total (USD)": "$1,201,000", "% of Flow": "85.73%",
         "USDT": "─", "USDC": "─", "DAI": "$1,201,000",
         "Entity": _fmt_entity(["2hop_mixer"]),
         "Weight": "18.7%", "Taint %": "16.03%", "ETH Bal.": "5.603 ETH"},
        {"Dir": "←", "Address": "0xc5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3",
         "Total (USD)": "$199,990",   "% of Flow": "14.27%",
         "USDT": "$199,990", "USDC": "─", "DAI": "─",
         "Entity": _fmt_entity(["blacklist"]), "Weight": "1.0", "Taint %": "14.27%", "ETH Bal.": "0.000 ETH"},
        {"Dir": "→", "Address": "0xd6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4",
         "Total (USD)": "$1,400,990", "% of Flow": "100.0%",
         "USDT": "$199,990", "USDC": "─", "DAI": "$1,201,000",
         "Entity": _fmt_entity([]), "Weight": "─", "Taint %": "─", "ETH Bal.": "1.240 ETH"},
    ],
    "0xe4d67f9404ccafdb1c83a003583fb5062b9bc32e": [
        {"Dir": "←", "Address": "0xe7f9a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5",
         "Total (USD)": "$5,523", "% of Flow": "100.0%",
         "USDT": "$5,523", "USDC": "─", "DAI": "─",
         "Entity": _fmt_entity([]), "Weight": "─", "Taint %": "─", "ETH Bal.": "0.341 ETH"},
        {"Dir": "→", "Address": "0xf8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6",
         "Total (USD)": "$5,523", "% of Flow": "100.0%",
         "USDT": "$5,523", "USDC": "─", "DAI": "─",
         "Entity": _fmt_entity(["2hop_blacklist"]),
         "Weight": "52.30%", "Taint %": "52.30%", "ETH Bal.": "0.341 ETH"},
    ],
    "0x5e8e3925cd81f0839812db5e373b5a7f7098bc37": [
        {"Dir": "←", "Address": "0x68b5cb42531e30acaa761a1be79cca8e23bf2ea0",
         "Total (USD)": "$199.95", "% of Flow": "100.0%",
         "USDT": "$199.95", "USDC": "─", "DAI": "─",
         "Entity": _fmt_entity([]), "Weight": "─", "Taint %": "─", "ETH Bal.": "0.042 ETH"},
        {"Dir": "→", "Address": "0x4f3059ce288ab90acfcf87ed8413aeb148ed6be1",
         "Total (USD)": "$199.95", "% of Flow": "100.0%",
         "USDT": "$199.95", "USDC": "─", "DAI": "─",
         "Entity": _fmt_entity([]), "Weight": "─", "Taint %": "─", "ETH Bal.": "0.017 ETH"},
    ],
}

# ── 2-hop indirect exposure data ─────────────────────────────────────────────
SAMPLE_HOP2 = {
    "0xe4d67f9404ccafdb1c83a003583fb5062b9bc32e": [
        {
            "Dir":          "→",
            "Intermediate": "0xf8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6",
            "Risk Entity":  "0x9b3c1a7f2d4e8c0f5a2b6d8e0f3a7c1b5d9e3f7a",
            "Category":     _fmt_entity(["blacklist"]),
            "CP Taint %":   "52.30%",
            "Amount (USD)": "$5,523",
        },
    ],
    "0xd21711a50be597d1a4368bc13fe3e0eb543cdff3": [
        {
            "Dir":          "←",
            "Intermediate": "0xb4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2",
            "Risk Entity":  "0x7a3f1c9b5e2d8f0a4c6b8e1d3f7a9c2b4e6d8f0a",
            "Category":     _fmt_entity(["mixer"]),
            "CP Taint %":   "18.7%",
            "Amount (USD)": "$1,201,000",
        },
    ],
    "0xbbe73a38b834c5434ebce85eb0fbe6556f528250": [
        {
            "Dir":          "←",
            "Intermediate": "0x3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c",
            "Risk Entity":  "0xc1e3f5a7b9d1e3f5a7c9b1d3f5a7c9e1b3d5f7a9",
            "Category":     _fmt_entity(["high_risk_exchange"]),
            "CP Taint %":   "8.4%",
            "Amount (USD)": "$219,904,879",
        },
        {
            "Dir":          "→",
            "Intermediate": "0xc2e4f6a8b0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0",
            "Risk Entity":  "0xd4f6b8a0c2e4b6d8f0a2c4e6b8d0a2c4e6b8d0f2",
            "Category":     _fmt_entity(["opaque_bridge"]),
            "CP Taint %":   "11.2%",
            "Amount (USD)": "$219,104,131",
        },
    ],
}

print(f"✅ Sample data loaded: {len(SAMPLE_ROWS)} addresses")
'''))

# ── Cell 4+: One markdown section + one code cell per address ────────────────
ADDRESS_LIST = [
    ("0x7e0ff1c8a125164c802de93b5e15e9474b3bb9b0", "LOW",      15.20),
    ("0xbbe73a38b834c5434ebce85eb0fbe6556f528250", "LOW",       6.77),
    ("0x6666ea71b7c52b61fde5faed791902937986ee1c", "CRITICAL", 99.99),
    ("0xd21711a50be597d1a4368bc13fe3e0eb543cdff3", "MEDIUM",   30.30),
    ("0xe4d67f9404ccafdb1c83a003583fb5062b9bc32e", "HIGH",     52.30),
    ("0x5e8e3925cd81f0839812db5e373b5a7f7098bc37", "LOW",       0.0),
    ("0x4dcb190f5a3b0a66a4fb88ea6b3b950ac506bb3d", "LOW",       0.0),
]

RISK_EMOJI = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "⛔"}

for i, (addr, level, score) in enumerate(ADDRESS_LIST, start=1):
    short = addr[:6] + "..." + addr[-4:]
    emoji = RISK_EMOJI.get(level, "⚪")

    cells.append(nbf.v4.new_markdown_cell(
        f"## Address {i} · {short} &nbsp; {emoji} {level} ({score}/100)\n"
        f"\n`{addr}`"
    ))

    cells.append(nbf.v4.new_code_cell(
        f'row   = next(r for r in SAMPLE_ROWS if r["address"] == "{addr}")\n'
        f'assets = SAMPLE_ASSETS.get("{addr}")\n'
        f'cp    = SAMPLE_COUNTERPARTIES.get("{addr}")\n'
        f'hop2  = SAMPLE_HOP2.get("{addr}")\n'
        f'display_address_report(row, assets, cp, hop2)\n'
    ))

nb.cells = cells

out_path = "/Users/tangliam/CriptoAnalyst/aml_sample_report.ipynb"
with open(out_path, "w", encoding="utf-8") as f:
    nbf.write(nb, f)

print(f"✅ Notebook generated: {out_path}")
