#!/usr/bin/env python3
"""Render a display-only notebook comparing our report with an archive JSON."""
from __future__ import annotations

import argparse
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import nbformat as nbf

ZERO = "0x0000000000000000000000000000000000000000"
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
UNI = "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"
HEX = "0x2b591e99afe9f32eaa6214f7b7629768c40eeb39"
TECH_LABELS = {
    ZERO: "zero/null address",
    USDT: "USDT token contract",
    UNI: "UNI token contract",
    HEX: "HEX token contract",
}

STYLE = """
<style>
.wrap{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#172033;line-height:1.38;max-width:1280px}
.hero{border:1px solid #d8dee9;border-radius:10px;padding:16px 18px;background:#fbfcfe;margin-bottom:14px}
.line{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}
.addr{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:#445064;word-break:break-all}
.cards{display:grid;grid-template-columns:repeat(4,minmax(140px,1fr));gap:12px;margin:16px 0}
.card{border:1px solid #d8dee9;border-radius:8px;padding:13px 15px;background:#fff}
.label{color:#647084;font-size:12px;text-transform:uppercase}
.value{font-size:20px;font-weight:700;margin-top:6px}
.section{margin:22px 0 10px;font-size:18px;font-weight:700}
table.clean{width:100%;border-collapse:collapse;font-size:13px;background:#fff;border:1px solid #d8dee9;border-radius:8px;overflow:hidden}
table.clean th{background:#f2f5f9;color:#3d4758;text-align:left;padding:9px 10px;border-bottom:1px solid #d8dee9}
table.clean td{padding:9px 10px;border-bottom:1px solid #edf0f5;vertical-align:top}
.note{background:#f8fafc;border:1px solid #d8dee9;border-radius:8px;padding:11px 13px;color:#3d4758;font-size:13px}
.warn{border-left:4px solid #d97706;background:#fff7ed;padding:10px 12px;margin:10px 0;border-radius:6px;color:#7c2d12}
.ok{border-left:4px solid #1f8a5b;background:#f0fdf4;padding:10px 12px;margin:10px 0;border-radius:6px;color:#14532d}
.badge{display:inline-block;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:700;color:white}
.low{background:#1f8a5b}.critical{background:#7f1d1d}.tech{background:#475569}.risk{background:#dc2626}.muted{color:#647084}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
</style>
"""


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def short(addr: str, head: int = 8, tail: int = 6) -> str:
    if not addr:
        return "-"
    if len(addr) <= head + tail + 3:
        return addr
    return f"{addr[:head]}...{addr[-tail:]}"


def fmt_num(value: Any, digits: int = 6) -> str:
    try:
        f = float(value)
    except Exception:
        return esc(value)
    if abs(f) >= 1000:
        return f"{f:,.{min(digits, 6)}f}".rstrip("0").rstrip(".")
    return f"{f:.{digits}f}".rstrip("0").rstrip(".")


def fmt_ts(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return esc(ts)


def raw_to_amount(value: Any, typ: str) -> str:
    try:
        raw = int(value)
    except Exception:
        return esc(value)
    decimals = 6 if typ in {"USDT", "USDC", "aEthUSDT"} else 18
    amount = raw / (10 ** decimals)
    return f"{fmt_num(amount, 8)} {typ}"


def table(headers: list[str], rows: list[list[Any]]) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = []
    for row in rows:
        body.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")
    return f"<table class='clean'><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def find_token_amount(archive: dict[str, Any], symbol: str, direction: str) -> float:
    key = "top_in" if direction == "in" else "top_out"
    rows = archive.get("balance", {}).get("fund_flow", {}).get("tokens", {}).get(key, [])
    for row in rows:
        if row.get("symbol") == symbol:
            return float(row.get("amount") or 0)
    return 0.0


def classify_blacklist(addr: str) -> tuple[str, str]:
    a = (addr or "").lower()
    if a in TECH_LABELS:
        return TECH_LABELS[a], "technical address"
    return "wallet/protocol address", "needs review"


def build_notebook(ours: dict[str, Any], archive: dict[str, Any], out: Path) -> None:
    target = ours["address"].lower()
    arch_risk = archive.get("risk", {})
    arch_balance = archive.get("balance", {})
    arch_flow = arch_balance.get("fund_flow", {})
    arch_eth = arch_flow.get("eth", {})
    our_assets = ours.get("per_asset", {})
    our_eth = our_assets.get("ETH@ethereum", {})
    our_usdt = our_assets.get("USDT@ethereum", {})
    window = (ours.get("analysis_windows") or {}).get("ethereum", {})

    cells = []
    cells.append(nbf.v4.new_markdown_cell(
        STYLE
        + "<div class='wrap'><div class='hero'><div class='line'><div>"
        + "<div style='font-size:20px;font-weight:700'>Our Report vs Archive Report</div>"
        + f"<div class='addr'>{esc(target)}</div>"
        + "<div class='muted'>Same address, different scope and different risk interpretation.</div>"
        + "</div><div>"
        + f"<span class='badge low'>OUR {esc(ours.get('risk_level'))} {esc(ours.get('risk_score'))}</span> "
        + f"<span class='badge critical'>ARCHIVE {esc(arch_risk.get('risk_level'))} {esc(arch_risk.get('risk_score'))}</span>"
        + "</div></div></div>"
        + "<div class='cards'>"
        + f"<div class='card'><div class='label'>Our Window</div><div class='value'>{esc(window.get('from_block'))} -> {esc(window.get('to_block'))}</div></div>"
        + f"<div class='card'><div class='label'>Current ETH</div><div class='value'>{fmt_num(our_eth.get('end_native_balance', arch_balance.get('current', {}).get('balance_eth')), 6)} ETH</div></div>"
        + f"<div class='card'><div class='label'>Our USDT Flow</div><div class='value'>{fmt_num(our_usdt.get('flow_in'), 4)} / {fmt_num(our_usdt.get('flow_out'), 4)}</div></div>"
        + f"<div class='card'><div class='label'>Archive Graph</div><div class='value'>{esc(archive.get('graph', {}).get('summary', {}).get('total_nodes'))} nodes</div></div>"
        + "</div>"
        + "<div class='note'>This comparison does not rerun chain queries. It lines up our first eth_test_10 result against the archive JSON for the same address.</div></div>"
    ))

    cells.append(nbf.v4.new_markdown_cell(
        STYLE + "<div class='wrap'><div class='section'>Scope and Amount Comparison</div>"
        + table(
            ["Metric", "Our eth_test_10 result", "Archive JSON", "Why different"],
            [
                ["Analysis scope", f"365-day window<br><span class='mono'>block {esc(window.get('from_block'))} -> {esc(window.get('to_block'))}</span>", "Full-history style fund flow plus 3-hop graph", "Different time scope"],
                ["Risk score", f"{esc(ours.get('risk_level'))} / {esc(ours.get('risk_score'))}", f"{esc(arch_risk.get('risk_level'))} / {esc(arch_risk.get('risk_score'))}<br>raw score {esc(arch_risk.get('raw_score'))}", "Archive scores graph hits; ours scores configured exposure"],
                ["ETH current balance", f"{fmt_num(our_eth.get('end_native_balance'), 6)} ETH", f"{fmt_num(arch_balance.get('current', {}).get('balance_eth'), 6)} ETH", "These match"],
                ["ETH inflow", f"{fmt_num(our_eth.get('eth_amount_in'), 6)} ETH", f"{fmt_num(arch_eth.get('in_eth'), 6)} ETH", "Our window has no native ETH inflow"],
                ["ETH outflow", f"{fmt_num(our_eth.get('eth_amount_out'), 6)} ETH", f"{fmt_num(arch_eth.get('out_eth'), 6)} ETH", "Archive includes older history"],
                ["USDT inflow", f"{fmt_num(our_usdt.get('flow_in'), 6)} USDT", f"{fmt_num(find_token_amount(archive, 'USDT', 'in'), 6)} USDT", "Archive includes older USDT activity"],
                ["USDT outflow", f"{fmt_num(our_usdt.get('flow_out'), 6)} USDT", f"{fmt_num(find_token_amount(archive, 'USDT', 'out'), 6)} USDT", "Archive includes older USDT activity"],
                ["Counterparty scale", f"{esc(ours.get('total_counterparties'))} counterparties", f"{esc(archive.get('graph', {}).get('summary', {}).get('total_nodes'))} graph nodes / {esc(archive.get('graph', {}).get('summary', {}).get('total_edges'))} edges", "Archive expands the graph beyond direct counterparties"],
            ],
        )
        + "</div>"
    ))

    hits = archive.get("detectors", {}).get("blacklist", {}).get("hits", [])
    hit_rows = []
    for hit in hits:
        addr = (hit.get("address") or "").lower()
        kind, action = classify_blacklist(addr)
        badge = "tech" if action == "technical address" else "risk"
        hit_rows.append([
            f"<span class='addr'>{esc(short(addr, 10, 8))}</span>",
            esc(hit.get("label")),
            esc(hit.get("hop")),
            f"<span class='badge {badge}'>{esc(kind)}</span>",
            esc("Do not score as wallet risk" if action == "technical address" else "Needs counterparty review"),
        ])
    cells.append(nbf.v4.new_markdown_cell(
        STYLE + "<div class='wrap'><div class='section'>Archive Blacklist Hits Reclassified</div>"
        + "<div class='warn'>The archive report treats every blacklist node as risk evidence. Several hits are technical nodes, not real wallet counterparties.</div>"
        + table(["Address", "Archive label", "Hop", "Reclassified as", "Interpretation"], hit_rows)
        + "</div>"
    ))

    path_rows = []
    for p in archive.get("trace", {}).get("risk_paths", [])[:12]:
        addr = (p.get("address") or "").lower()
        kind, _ = classify_blacklist(addr)
        path = " -> ".join(short(x, 8, 6) for x in p.get("path", []))
        path_rows.append([
            esc(p.get("direction")),
            esc(p.get("hops")),
            f"<span class='addr'>{esc(short(addr, 10, 8))}</span>",
            esc(kind),
            f"<span class='mono'>{esc(path)}</span>",
        ])
    cells.append(nbf.v4.new_markdown_cell(
        STYLE + "<div class='wrap'><div class='section'>Archive Risk Paths</div>"
        + table(["Direction", "Hops", "Risk node", "Node type", "Path"], path_rows)
        + "</div>"
    ))

    edge_rows = []
    for edge in archive.get("graph", {}).get("json_full", {}).get("edges", []):
        s = str(edge.get("source", "")).lower()
        t = str(edge.get("target", "")).lower()
        tags = edge.get("topo_tags") or []
        if target not in {s, t} or not tags:
            continue
        typ = edge.get("type") or "ETH"
        edge_rows.append([
            esc(fmt_ts(edge.get("ts"))),
            f"<span class='addr'>{esc(short(s))}</span> -> <span class='addr'>{esc(short(t))}</span>",
            esc(typ),
            f"<span class='mono'>{esc(edge.get('value'))}</span>",
            esc(raw_to_amount(edge.get("value"), typ)),
            esc(", ".join(tags)),
        ])
        if len(edge_rows) >= 18:
            break
    cells.append(nbf.v4.new_markdown_cell(
        STYLE + "<div class='wrap'><div class='section'>Direct Archive Evidence Edges</div>"
        + "<div class='note'>Raw values are shown beside converted amounts. Conversion uses 18 decimals for ETH-like assets and 6 decimals for USDT/aEthUSDT/USDC.</div>"
        + table(["Time", "Edge", "Asset type", "Raw value", "Converted", "Tags"], edge_rows)
        + "</div>"
    ))

    cp_rows = []
    for row in (ours.get("counterparty_table") or [])[:12]:
        cp_rows.append([
            f"<span class='addr'>{esc(short(row.get('address', '')))}</span>",
            esc(row.get("direction")),
            f"{fmt_num(row.get('total_usd'), 4)}",
            f"{fmt_num(row.get('stable_usd'), 4)}",
            esc(", ".join(f"{k}: {fmt_num(v, 6)}" for k, v in (row.get("by_sym") or {}).items())),
            esc(", ".join(row.get("risk_tags") or [])) or "-",
        ])
    cells.append(nbf.v4.new_markdown_cell(
        STYLE + "<div class='wrap'><div class='section'>Our Direct Counterparty View</div>"
        + table(["Counterparty", "Direction", "Total USD-like", "Stablecoin USD", "Assets", "Risk tags"], cp_rows)
        + "</div>"
    ))

    cells.append(nbf.v4.new_markdown_cell(
        STYLE + "<div class='wrap'><div class='section'>Bottom Line</div>"
        + "<div class='ok'>The matching current ETH balance suggests both reports identify the same address correctly.</div>"
        + "<div class='warn'>The archive risk score is heavily driven by graph nodes that include token contracts and the zero address. Those are useful technical context, but they should not be counted as direct risky wallet counterparties without reclassification.</div>"
        + "<div class='note'>A better final report should keep archive-style evidence paths, but score only real counterparties after classifying token contracts, protocol contracts, zero address, exchanges, bridges, and ordinary wallets separately.</div>"
        + "</div>"
    ))

    nb = nbf.v4.new_notebook()
    nb["cells"] = cells
    nb["metadata"] = {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}}
    out.parent.mkdir(parents=True, exist_ok=True)
    nbf.write(nb, out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ours", required=True)
    ap.add_argument("--archive", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    ours_data = json.loads(Path(args.ours).read_text())
    ours = ours_data[0] if isinstance(ours_data, list) else ours_data
    archive = json.loads(Path(args.archive).read_text())
    build_notebook(ours, archive, Path(args.out))


if __name__ == "__main__":
    main()
