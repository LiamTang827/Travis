#!/usr/bin/env python3
"""
make_pretty_v2.py - Render results.json into a display-only notebook.
The notebook emphasizes ERC20 Transfer effects with explicit IN/OUT direction
and decodes known method selectors such as 0xbc4a02e4.

Usage:
    PYTHONPATH=src python3 experiments/notebooks/make_pretty_v2.py \
        artifacts/reports/eth_test_10_preview/results.json \
        --out artifacts/reports_v2/eth_test_10_report_v2.ipynb
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cripto_analyst.aml_analyzer import decode_method   # noqa: E402

STABLECOINS = {"USDT", "USDC", "DAI", "BUSD", "USDC.E", "USDCE", "USDB", "DOLA"}
DUST_NATIVE_ETH = 0.000001

STYLE = (
    "<style>"
    ".report-wrap{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
    "color:#172033;line-height:1.35}"
    ".addr-head{border:1px solid #d8dee9;border-radius:10px;padding:16px 18px;background:#fbfcfe}"
    ".line{display:flex;justify-content:space-between;gap:16px}"
    ".addr{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:#445064;"
    "word-break:break-all}"
    ".cards{display:grid;grid-template-columns:repeat(4,minmax(120px,1fr));gap:12px;margin:16px 0}"
    ".card{border:1px solid #d8dee9;border-radius:8px;padding:13px 15px;background:#fff}"
    ".label{color:#647084;font-size:12px;text-transform:uppercase}"
    ".value{font-size:20px;font-weight:700;margin-top:6px}"
    ".section{margin:22px 0 10px;font-size:18px;font-weight:700}"
    "table.clean{width:100%;border-collapse:collapse;font-size:13px;background:#fff;"
    "border:1px solid #d8dee9;border-radius:8px;overflow:hidden}"
    "table.clean th{background:#f2f5f9;color:#3d4758;text-align:left;padding:9px 10px;"
    "border-bottom:1px solid #d8dee9}"
    "table.clean td{padding:9px 10px;border-bottom:1px solid #edf0f5;vertical-align:top}"
    ".badge{display:inline-block;border-radius:999px;padding:3px 9px;font-size:12px;"
    "font-weight:700;color:white}"
    ".explain{background:#f8fafc;border:1px solid #d8dee9;border-radius:8px;padding:11px 13px;"
    "color:#3d4758;font-size:13px}"
    ".warn{border-left:4px solid #d97706;background:#fff7ed;padding:10px 12px;margin:10px 0;"
    "border-radius:6px;color:#7c2d12}"
    ".note{color:#647084;font-size:12px;margin-top:8px}"
    ".dir-in{color:#0e7a4d;font-weight:700}"
    ".dir-out{color:#b91c1c;font-weight:700}"
    ".dir-tok{color:#6b21a8;font-weight:700}"
    ".muted{color:#647084}"
    "</style>"
)

LEVEL_COLOR = {
    "LOW": "#1f8a5b",
    "MEDIUM": "#d97706",
    "HIGH": "#dc2626",
    "CRITICAL": "#7f1d1d",
}


def _short(addr: str, head: int = 6, tail: int = 6) -> str:
    if not addr:
        return "—"
    if len(addr) <= head + tail + 3:
        return addr
    return f"{addr[:head]}…{addr[-tail:]}"


def _fmt_amount(amt: float, sym: str) -> str:
    if sym in STABLECOINS:
        if amt >= 1000:
            return f"${amt/1000:,.2f}K"
        return f"${amt:,.2f}"
    if amt == 0:
        return f"0 {sym}"
    if abs(amt) >= 1:
        return f"{amt:,.4f} {sym}"
    return f"{amt:.8f} {sym}"


def _fmt_ts(ts: str) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts or "—"


def _token_status_label(status: str) -> str:
    status_l = (status or "").lower()
    if status_l in {"trusted_stablecoin", "configured_stablecoin_contract"}:
        return "configured stablecoin contract"
    if status_l == "other_erc20":
        return "non-configured ERC20"
    return status or ""


def _dir_html(direction: str) -> str:
    if direction == "IN":
        return "<span class='dir-in'>IN ←</span>"
    if direction == "OUT":
        return "<span class='dir-out'>OUT →</span>"
    if direction == "TOKEN_ONLY":
        return "<span class='dir-tok'>TOKEN</span>"
    return direction or "—"


def _upgrade_effect(eff: Dict[str, Any], interaction: Dict[str, Any]) -> Dict[str, Any]:
    """Backfill fields for older result schemas."""
    out = dict(eff)
    if "from" not in out or "to" not in out:
        d = out.get("direction", "")
        cp = out.get("counterparty", "")
        if d == "IN":
            out["from"] = out.get("from") or cp
            out["to"]   = out.get("to")   or interaction.get("to", "") or ""
        elif d == "OUT":
            out["from"] = out.get("from") or interaction.get("from", "") or ""
            out["to"]   = out.get("to")   or cp
        else:
            out["from"] = out.get("from") or ""
            out["to"]   = out.get("to")   or ""
    if not out.get("method_label"):
        out["method_label"] = decode_method(out.get("method_id", ""), out.get("method", ""))
    return out


def _upgrade_interaction(it: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(it)
    if not out.get("method_label"):
        out["method_label"] = decode_method(out.get("method_id", ""), out.get("method", ""))
    if (not out["method_label"]) and not out.get("input_present"):
        out["method_label"] = "Transfer"
    if out.get("method_id", "").strip().lower() == "0x":
        out["method_id"] = ""
    out["token_effects"] = [_upgrade_effect(e, out) for e in (out.get("token_effects") or [])]
    return out


def _render_effects_cell(effects: List[Dict[str, Any]]) -> str:
    """Render one token effect per line with explicit direction and endpoints."""
    if not effects:
        return "—"
    parts = []
    for eff in effects:
        direction = eff.get("direction", "")
        amt = eff.get("amount", 0.0)
        sym = eff.get("sym", "")
        frm = _short(eff.get("from", ""))
        to  = _short(eff.get("to", ""))
        status = _token_status_label(eff.get("token_status", ""))
        amount_str = _fmt_amount(amt, sym)
        dir_lbl = _dir_html(direction)
        flow = (
            f"<div>{dir_lbl} <b>{amount_str}</b> "
            f"<span class='addr'>from {frm} → to {to}</span>"
            + (f" <span class='note'>· {status}</span>" if status else "")
            + "</div>"
        )
        parts.append(flow)
    return "".join(parts)


def _interaction_priority(it: Dict[str, Any]) -> tuple:
    effects = it.get("token_effects") or []
    stable = any(e.get("is_stablecoin") for e in effects)
    has_effect = bool(effects)
    native = abs(float(it.get("native_value") or 0))
    is_dust_native = (not effects) and native and native < DUST_NATIVE_ETH
    try:
        ts_sort = -int(it.get("ts") or 0)
    except Exception:
        ts_sort = 0
    return (
        0 if stable else 1 if has_effect else 3 if is_dust_native else 2,
        ts_sort,
    )


def _iter_token_effect_rows(interactions: List[Dict[str, Any]], stable_only: bool) -> List[Dict[str, Any]]:
    rows = []
    for it in interactions:
        for eff in it.get("token_effects") or []:
            is_stable = bool(eff.get("is_stablecoin"))
            if stable_only != is_stable:
                continue
            row = dict(eff)
            row["_interaction"] = it
            rows.append(row)
    rows.sort(
        key=lambda e: (
            0 if e.get("is_stablecoin") else 1,
            -float(e.get("amount") or 0),
            -(int(e.get("ts") or e.get("_interaction", {}).get("ts") or 0)),
        )
    )
    return rows


def _render_token_effect_table(title: str, interactions: List[Dict[str, Any]],
                               stable_only: bool, limit: int) -> str:
    effects = _iter_token_effect_rows(interactions, stable_only=stable_only)
    if not effects:
        return ""
    rows = []
    for eff in effects[:limit]:
        it = eff.get("_interaction", {})
        direction = eff.get("direction", "")
        sym = eff.get("sym", "")
        amount = _fmt_amount(float(eff.get("amount") or 0), sym)
        method = it.get("method_label") or eff.get("method_label") or "—"
        token_contract = _short(eff.get("token_contract", ""), 8, 6)
        rows.append(
            "<tr>"
            f"<td>{_fmt_ts(eff.get('ts') or it.get('ts',''))}</td>"
            f"<td>{_dir_html(direction)}</td>"
            f"<td><b>{amount}</b></td>"
            f"<td>{sym}</td>"
            f"<td>{eff.get('token_decimals', '—')}</td>"
            f"<td><span class='addr'>{_short(eff.get('from',''),8,6)}</span></td>"
            f"<td><span class='addr'>{_short(eff.get('to',''),8,6)}</span></td>"
            f"<td>{method}</td>"
            f"<td>{it.get('action_type','—')}</td>"
            f"<td><span class='addr'>{token_contract}</span></td>"
            f"<td><span class='addr'>{_short(it.get('tx_hash',''),8,6)}</span></td>"
            "</tr>"
        )
    html = (
        f"<div class='section'>{title}</div>"
        "<table class='clean'><thead><tr>"
        "<th>Time</th><th>Dir</th><th>Amount</th><th>Token</th><th>Decimals</th>"
        "<th>From</th><th>To</th><th>Outer Method</th><th>Interpretation</th>"
        "<th>Token Contract</th><th>Tx</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )
    if len(effects) > limit:
        html += f"<div class='note'>... {len(effects) - limit} more token effects not shown.</div>"
    return html


def _render_native_context(interactions: List[Dict[str, Any]], limit: int = 12) -> str:
    dust = [
        it for it in interactions
        if not (it.get("token_effects") or [])
        and 0 < abs(float(it.get("native_value") or 0)) < DUST_NATIVE_ETH
    ]
    context = [
        it for it in interactions
        if not (it.get("token_effects") or [])
        and not (0 < abs(float(it.get("native_value") or 0)) < DUST_NATIVE_ETH)
    ]
    parts = []
    if dust:
        total = sum(abs(float(it.get("native_value") or 0)) for it in dust)
        parts.append(
            "<div class='explain'>"
            f"Collapsed {len(dust)} native dust transfers below {DUST_NATIVE_ETH:g} ETH, "
            f"totaling {total:.8f} ETH. These are not ERC20 stablecoin movements; "
            "the raw records remain in results.json."
            "</div>"
        )
    rows = []
    for it in context[:limit]:
        native = float(it.get("native_value") or 0)
        rows.append(
            "<tr>"
            f"<td>{_fmt_ts(it.get('ts',''))}</td>"
            f"<td>{_dir_html(it.get('direction',''))}</td>"
            f"<td>{it.get('action_type','—')}</td>"
            f"<td>{it.get('method_label') or it.get('method') or '—'}</td>"
            f"<td>{native:,.8f} ETH" if native else "<td>—"
            f"</td><td><span class='addr'>{_short(it.get('from',''),8,6)}</span></td>"
            f"<td><span class='addr'>{_short(it.get('to',''),8,6)}</span></td>"
            f"<td><span class='addr'>{_short(it.get('tx_hash',''),8,6)}</span></td>"
            "</tr>"
        )
    if rows:
        parts.append(
            "<table class='clean'><thead><tr>"
            "<th>Time</th><th>Dir</th><th>Type</th><th>Method</th>"
            "<th>Native Value</th><th>From</th><th>To</th><th>Tx</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
    if not parts:
        return ""
    return "<div class='section'>Native ETH / Non-token Context</div>" + "".join(parts)


def _fmt_dt_from_ts(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts or "-")


def _render_analysis_window(r: Dict[str, Any]) -> str:
    windows = r.get("analysis_windows") or {}
    rows = []
    for chain, w in windows.items():
        rows.append(
            "<tr>"
            f"<td>{chain}</td>"
            f"<td>{w.get('days', '-')}</td>"
            f"<td>{w.get('from_block', '-')}</td>"
            f"<td>{_fmt_dt_from_ts(w.get('from_timestamp'))}</td>"
            f"<td>{w.get('to_block', '-')}</td>"
            f"<td>{_fmt_dt_from_ts(w.get('to_timestamp'))}</td>"
            "</tr>"
        )
    if not rows:
        return ""
    return (
        "<div class='section'>Analysis Window</div>"
        "<table class='clean'><thead><tr>"
        "<th>Chain</th><th>Days</th><th>Start Block</th><th>Start Time</th>"
        "<th>End Block</th><th>End Time</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _fmt_balance_value(asset: Dict[str, Any], key: str) -> str:
    sym = asset.get("sym", "")
    val = asset.get(key)
    if val is None:
        return "-"
    if sym == "ETH":
        native_key = "start_native_balance" if key == "start_balance" else "end_native_balance"
        native = asset.get(native_key)
        if native is not None:
            return f"{float(native):,.6f} ETH"
    if sym in STABLECOINS:
        return f"${float(val):,.2f}"
    return f"{float(val):,.6f} {sym}"


def _render_asset_balances(r: Dict[str, Any]) -> str:
    assets = r.get("per_asset") or {}
    rows = []
    for key in sorted(assets):
        a = assets[key]
        rows.append(
            "<tr>"
            f"<td>{a.get('sym', key)}</td>"
            f"<td>{a.get('chain', '-')}</td>"
            f"<td>{a.get('decimals', 'native' if a.get('sym') == 'ETH' else '-')}</td>"
            f"<td>{a.get('start_block', '-')}</td>"
            f"<td>{_fmt_balance_value(a, 'start_balance')}</td>"
            f"<td>{a.get('end_block', '-')}</td>"
            f"<td>{_fmt_balance_value(a, 'end_balance')}</td>"
            f"<td>{a.get('historical_balance_verified', False)}</td>"
            f"<td>{a.get('balance_source', '-')}</td>"
            "</tr>"
        )
    if not rows:
        return ""
    note = (
        "<div class='explain'>"
        "End balances are latest/current balance queries. Start balances are reconstructed as "
        "<code>end balance + outflow - inflow</code> because historical balance verification "
        "requires Etherscan Pro historical balance endpoints or an archive RPC."
        "</div>"
    )
    return (
        "<div class='section'>Asset Balances by Block</div>"
        + note
        + "<table class='clean'><thead><tr>"
        "<th>Asset</th><th>Chain</th><th>Decimals</th><th>Start Block</th><th>Start Balance</th>"
        "<th>End Block</th><th>End Balance</th><th>Historical Verified</th><th>Source</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _render_address_cell(r: Dict[str, Any], idx: int) -> str:
    addr = r.get("address", "")
    level = r.get("risk_level", "LOW")
    score = float(r.get("risk_score", 0) or 0)
    level_color = LEVEL_COLOR.get(level, "#647084")

    # Header
    head = (
        f"<div class='addr-head'><div class='line'>"
        f"<div>"
        f"<div style='font-size:18px;font-weight:700'>Address {idx}: {addr[:8]}…{addr[-6:]}</div>"
        f"<div class='addr'>{addr}</div>"
        f"</div>"
        f"<div><span class='badge' style='background:{level_color}'>{level} {score:.1f}/100</span></div>"
        f"</div></div>"
    )

    # Cards
    assets = r.get("per_asset", {}) or {}
    stable_in  = r.get("total_inflow_usdt",  0.0)
    stable_out = r.get("total_outflow_usdt", 0.0)
    stable_bal = sum(a.get("balance", 0) for a in assets.values()) if assets else 0.0
    n_inter = len(r.get("contract_interactions") or [])
    cards = (
        "<div class='cards'>"
        f"<div class='card'><div class='label'>Stable Inflow</div><div class='value'>${stable_in:,.0f}</div></div>"
        f"<div class='card'><div class='label'>Stable Outflow</div><div class='value'>${stable_out:,.0f}</div></div>"
        f"<div class='card'><div class='label'>Stable Balance</div><div class='value'>${stable_bal:,.2f}</div></div>"
        f"<div class='card'><div class='label'>Contract Interactions</div><div class='value'>{n_inter}</div></div>"
        "</div>"
    )

    # Model explanation
    explain = (
        "<div class='section'>Model</div>"
        "<div class='explain'>"
        "This report separates native ETH value from ERC20 Transfer events. "
        "An outer transaction with 0 ETH native value can still create ERC20 asset movement. "
        "The stablecoin section means ERC20 Transfer events whose token contract matches this project's "
        "configured stablecoin contract list for the chain; it is not a chain-native property. "
        "All other token contracts are shown separately as non-configured ERC20 effects. "
        "Each effect explicitly shows "
        "<span class='dir-in'>IN ←</span> / <span class='dir-out'>OUT →</span> direction, "
        "with from/to addresses instead of relying on +/- signs. "
        "The Method column prefers Etherscan's functionName; otherwise known selectors are decoded locally, "
        "and unknown selectors are shown as <code>unknown(0x...)</code>."
        "</div>"
    )

    # Warnings
    warnings = [
        w for w in (r.get("warnings", []) or [])
        if "fast transit" not in str(w).lower()
    ]
    warn_html = ""
    if warnings:
        warn_html = "<div class='section'>Warnings</div>" + "".join(
            f"<div class='warn'>{w}</div>" for w in warnings
        )

    interactions = [
        _upgrade_interaction(it) for it in (r.get("contract_interactions") or [])
    ]
    interactions = sorted(interactions, key=_interaction_priority)

    stable_effects_table = _render_token_effect_table(
        "Configured Stablecoin Contract Effects", interactions, stable_only=True, limit=40
    )
    other_effects_table = _render_token_effect_table(
        "Non-configured ERC20 Effects", interactions, stable_only=False, limit=15
    )
    native_context = _render_native_context(interactions)
    analysis_window = _render_analysis_window(r)
    asset_balances = _render_asset_balances(r)

    # Compact interaction context table
    rows = []
    visible_interactions = [
        it for it in interactions
        if (it.get("token_effects") or [])
        or abs(float(it.get("native_value") or 0)) >= DUST_NATIVE_ETH
        or it.get("input_present")
    ]
    for it in visible_interactions[:20]:
        tm = _fmt_ts(it.get("ts", ""))
        action = it.get("action_type", "—")
        method_lb = it.get("method_label") or "—"
        method_id = it.get("method_id", "")
        if method_id and method_id.lower() not in method_lb.lower():
            method_show = f"{method_lb} <span class='note'>({method_id})</span>"
        else:
            method_show = method_lb
        native = it.get("native_value", 0) or 0
        native_str = f"{native:,.6f} ETH" if native else "—"
        cp = it.get("counterparty") or it.get("to") or "—"
        dir_lbl = _dir_html(it.get("direction", ""))
        effects_html = _render_effects_cell(it.get("token_effects") or [])
        tx = it.get("tx_hash", "")
        rows.append(
            f"<tr>"
            f"<td>{tm}</td>"
            f"<td>{dir_lbl}</td>"
            f"<td>{action}</td>"
            f"<td>{method_show}</td>"
            f"<td>{native_str}</td>"
            f"<td><span class='addr'>{_short(cp,8,6) if cp != '—' else '—'}</span></td>"
            f"<td>{effects_html}</td>"
            f"<td><span class='addr'>{_short(tx,8,6)}</span></td>"
            f"</tr>"
        )
    interactions_table = (
        "<div class='section'>Outer Transaction Context</div>"
    )
    if rows:
        interactions_table += (
            "<table class='clean'><thead><tr>"
            "<th>Time</th><th>Dir</th><th>Action</th><th>Method</th>"
            "<th>Native Value</th><th>Counterparty</th>"
            "<th>Token Effects (IN ← / OUT →, from / to)</th><th>Tx</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
        if len(visible_interactions) > 20:
            interactions_table += (
                f"<div class='note'>... {len(visible_interactions) - 20} more outer context rows not shown.</div>"
            )
    else:
        interactions_table += "<div class='explain'>No contract interaction records for this address.</div>"

    # Stable counterparties
    cpt = r.get("counterparty_table", []) or []
    cp_rows = []
    for row in sorted(cpt, key=lambda x: x.get("total_usd", 0), reverse=True)[:15]:
        if row.get("total_usd", 0) <= 0:
            continue
        tags = " ".join(f"<span class='badge' style='background:#475569'>{t}</span>"
                        for t in row.get("risk_tags", []))
        cp_rows.append(
            f"<tr>"
            f"<td>{_dir_html(row.get('direction',''))}</td>"
            f"<td><span class='addr'>{row.get('address','')}</span></td>"
            f"<td>${row.get('total_usd',0):,.2f}</td>"
            f"<td>{tags or '—'}</td>"
            f"<td>{row.get('taint_pct',0):.2f}%</td>"
            f"</tr>"
        )
    cp_table = ""
    if cp_rows:
        cp_table = (
            "<div class='section'>Counterparty Flow — Stablecoins</div>"
            "<table class='clean'><thead><tr>"
            "<th>Dir</th><th>Address</th><th>Total (USD)</th><th>Tags</th><th>Taint %</th>"
            "</tr></thead><tbody>" + "".join(cp_rows) + "</tbody></table>"
        )

    return (
        STYLE
        + f"<div class='report-wrap'>{head}{cards}{explain}{warn_html}"
        f"{analysis_window}{asset_balances}"
        f"{stable_effects_table}{other_effects_table}{native_context}{interactions_table}{cp_table}</div>"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results", help="results.json from aml_analyzer batch run")
    ap.add_argument("--out", required=True, help="output ipynb path")
    args = ap.parse_args()

    with open(args.results) as f:
        reports = json.load(f)
    if isinstance(reports, dict):
        reports = [reports]

    nb = {
        "cells": [],
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    # Top note
    nb["cells"].append({
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "# AML Risk Report — v2 (explicit direction)\n\n",
            f"{len(reports)} addresses; one address per cell.\n\n",
            "**What changed**: Token Effects no longer use +/- as an implicit direction. "
            "They now show `IN ←` / `OUT →` with from/to addresses. "
            "Stablecoin rows mean configured stablecoin contract matches, not chain-native status. "
            "Unknown selectors are shown as `unknown(0x..)` instead of being dropped.\n",
        ],
    })
    for idx, r in enumerate(reports, 1):
        nb["cells"].append({
            "cell_type": "markdown",
            "metadata": {},
            "source": [_render_address_cell(r, idx)],
        })

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(nb, ensure_ascii=False, indent=1))
    print(f"[OK] wrote {out_path} ({out_path.stat().st_size:,} bytes, {len(nb['cells'])} cells)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
