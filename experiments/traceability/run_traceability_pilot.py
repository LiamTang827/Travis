#!/usr/bin/env python3
"""Lightweight stablecoin traceability pilot experiment.

This script is intentionally small enough to run on a laptop. It uses the
cached USDT/USDC transfer JSON files already present in experiments/ml/data
and checks whether direct counterparties are known risk anchors or
traceability boundary/continuation mechanisms.

Scope note (2026-06-12): this pilot is DESCRIPTIVE, not statistical. It is
a 1-hop set-membership check against the registry -- no BFS, no bridge
resolution, no evidence chain. Its denominator is an address population
(Tether-frozen + sampled normal seeds), so the traceability_continuation
count reflects that population's bridge-usage base rate, not the system's
tracing capability. Do NOT scale the seed count to chase statistical
significance; statistical resolution rates over real bridge transactions
belong to run_across_batch_resolution.py. Keep this script as-is: it is
the generator of the report-2 pilot artifacts (illustrative cases only).

Outputs:
  artifacts/traceability_pilot/direct_hits.csv
  artifacts/traceability_pilot/summary.md
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TRANSFER_DIR = ROOT / "experiments/ml/data/transfers"
LABELS_CSV = ROOT / "experiments/ml/data/labeled_addresses.csv"
USDT_BLACKLIST_CSV = ROOT / "data/blacklists/usdt_blacklist.csv"
OFAC_JSON = ROOT / "src/cripto_analyst/threat_intel/ofac_sanctioned.json"
MIXERS_JSON = ROOT / "src/cripto_analyst/threat_intel/mixers.json"
BRIDGES_JSON = ROOT / "src/cripto_analyst/threat_intel/bridges.json"
OUT_DIR = ROOT / "artifacts/traceability_pilot"


PROTOCOL_ADDRS = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7",  # USDT
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC
    "0x0000000000000000000000000000000000000000",
}


def norm(address: str | None) -> str:
    return (address or "").lower().strip()


def load_json(path: Path) -> Any:
    with path.open() as f:
        return json.load(f)


def load_labels() -> dict[str, str]:
    labels: dict[str, str] = {}
    if not LABELS_CSV.exists():
        return labels
    with LABELS_CSV.open(newline="") as f:
        for row in csv.DictReader(f):
            labels[norm(row.get("address"))] = row.get("label", "unknown")
    return labels


def load_registry() -> dict[str, dict[str, str]]:
    registry: dict[str, dict[str, str]] = {}

    if USDT_BLACKLIST_CSV.exists():
        with USDT_BLACKLIST_CSV.open(newline="") as f:
            for row in csv.DictReader(f):
                address = norm(row.get("address"))
                if address and address not in PROTOCOL_ADDRS:
                    registry[address] = {
                        "category": "risk_anchor",
                        "kind": "USDT blacklist",
                        "traceability": "anchor",
                    }

    if OFAC_JSON.exists():
        for address, meta in load_json(OFAC_JSON).items():
            address = norm(address)
            if address.startswith("0x") and address not in PROTOCOL_ADDRS:
                entity = meta.get("entity", "OFAC sanctioned") if isinstance(meta, dict) else "OFAC sanctioned"
                registry.setdefault(
                    address,
                    {
                        "category": "risk_anchor",
                        "kind": f"OFAC sanctioned: {entity}",
                        "traceability": "anchor",
                    },
                )

    if MIXERS_JSON.exists():
        mixers = load_json(MIXERS_JSON).get("contracts", {})
        for address, name in mixers.items():
            address = norm(address)
            if address in PROTOCOL_ADDRS or "placeholder" in str(name).lower():
                continue
            registry[address] = {
                "category": "traceability_break",
                "kind": f"Mixer/privacy tool: {name}",
                "traceability": "break",
            }

    if BRIDGES_JSON.exists():
        bridges = load_json(BRIDGES_JSON).get("contracts", {})
        for address, meta in bridges.items():
            address = norm(address)
            if not address or address in PROTOCOL_ADDRS:
                continue
            traceable = bool(meta.get("traceable"))
            registry[address] = {
                "category": "traceability_continuation" if traceable else "traceability_break",
                "kind": f"{'Traceable' if traceable else 'Opaque'} bridge: {meta.get('name', 'bridge')}",
                "traceability": "continue" if traceable else "break",
            }

    return registry


def iter_counterparty_edges(seed: str, data: dict[str, Any]):
    for tx in data.get("transfers_sent", []):
        counterparty = norm(tx.get("to"))
        if counterparty in PROTOCOL_ADDRS:
            continue
        yield {
            "seed": seed,
            "direction": "OUT",
            "counterparty": counterparty,
            "amount": float(tx.get("amount") or 0),
            "token": tx.get("token", ""),
            "timestamp": int(tx.get("timestamp") or 0),
            "tx_hash": tx.get("tx_hash", ""),
        }

    for tx in data.get("transfers_received", []):
        counterparty = norm(tx.get("from"))
        if counterparty in PROTOCOL_ADDRS:
            continue
        yield {
            "seed": seed,
            "direction": "IN",
            "counterparty": counterparty,
            "amount": float(tx.get("amount") or 0),
            "token": tx.get("token", ""),
            "timestamp": int(tx.get("timestamp") or 0),
            "tx_hash": tx.get("tx_hash", ""),
        }


def fmt_ts(timestamp: int) -> str:
    if timestamp <= 0:
        return ""
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    labels = load_labels()
    registry = load_registry()

    transfer_files = sorted(TRANSFER_DIR.glob("*.json"))
    rows: list[dict[str, Any]] = []
    seed_edge_counts: Counter[str] = Counter()
    seed_labels: dict[str, str] = {}
    unique_counterparties: set[str] = set()

    for path in transfer_files:
        data = load_json(path)
        seed = norm(data.get("address"))
        seed_label = labels.get(seed, data.get("label", "unknown"))
        seed_labels[seed] = seed_label

        for edge in iter_counterparty_edges(seed, data):
            seed_edge_counts[seed] += 1
            unique_counterparties.add(edge["counterparty"])
            meta = registry.get(edge["counterparty"])
            if not meta:
                continue
            rows.append(
                {
                    "seed": seed,
                    "seed_label": seed_label,
                    "direction": edge["direction"],
                    "counterparty": edge["counterparty"],
                    "counterparty_kind": meta["kind"],
                    "category": meta["category"],
                    "traceability": meta["traceability"],
                    "token": edge["token"],
                    "amount": edge["amount"],
                    "date_utc": fmt_ts(edge["timestamp"]),
                    "tx_hash": edge["tx_hash"],
                }
            )

    direct_hits_csv = OUT_DIR / "direct_hits.csv"
    fieldnames = [
        "seed",
        "seed_label",
        "direction",
        "counterparty",
        "counterparty_kind",
        "category",
        "traceability",
        "token",
        "amount",
        "date_utc",
        "tx_hash",
    ]
    with direct_hits_csv.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    category_counts = Counter(row["category"] for row in rows)
    traceability_counts = Counter(row["traceability"] for row in rows)
    seeds_with_hits = {row["seed"] for row in rows}
    normal_seeds_with_hits = {row["seed"] for row in rows if row["seed_label"] == "normal"}
    label_counts = Counter(seed_labels.values())

    by_seed = Counter(row["seed"] for row in rows)
    top_seed = by_seed.most_common(1)[0][0] if by_seed else ""
    normal_bridge_case = next(
        (
            row
            for row in rows
            if row["seed_label"] == "normal"
            and row["category"] == "traceability_continuation"
        ),
        None,
    )
    risk_anchor_case = next(
        (row for row in rows if row["category"] == "risk_anchor"),
        None,
    )

    summary = OUT_DIR / "summary.md"
    with summary.open("w") as f:
        f.write("# Stablecoin Traceability Pilot Experiment\n\n")
        f.write("## Purpose\n\n")
        f.write(
            "This lightweight pilot tests whether cached stablecoin transfer records can be "
            "converted into explainable traceability evidence. It does not attempt full-chain "
            "surveillance or large-scale AML classification.\n\n"
        )
        f.write("## Input Data\n\n")
        f.write(f"- Cached address files: {len(transfer_files)}\n")
        f.write(f"- Seed labels: {dict(label_counts)}\n")
        f.write(f"- Parsed non-protocol counterparty edges: {sum(seed_edge_counts.values())}\n")
        f.write(f"- Unique non-protocol counterparties: {len(unique_counterparties)}\n")
        f.write(f"- Registry entries loaded: {len(registry)}\n\n")

        f.write("Protocol contracts and zero-address placeholders were excluded before matching, ")
        f.write("including USDT, USDC, and `0x000...000`.\n\n")

        f.write("## Results\n\n")
        f.write(f"- Direct risk/boundary evidence rows: {len(rows)}\n")
        f.write(f"- Seeds with at least one direct evidence hit: {len(seeds_with_hits)} / {len(transfer_files)}\n")
        f.write(f"- Normal-labeled seeds with direct evidence hit: {len(normal_seeds_with_hits)} / {label_counts.get('normal', 0)}\n")
        f.write(f"- Evidence categories: {dict(category_counts)}\n")
        f.write(f"- Traceability outcomes: {dict(traceability_counts)}\n\n")

        f.write("## Illustrative Cases\n\n")
        if normal_bridge_case:
            f.write("### Traceability continuation case\n\n")
            f.write(
                f"A normal-labeled seed `{normal_bridge_case['seed']}` had an "
                f"{normal_bridge_case['direction']} {normal_bridge_case['token']} transfer "
                f"with `{normal_bridge_case['counterparty']}` "
                f"({normal_bridge_case['counterparty_kind']}). "
                "This is not itself a risk anchor; it is evidence that bridge classification "
                "is needed to decide whether tracing can continue across chains.\n\n"
            )
            f.write(
                f"- Amount: {normal_bridge_case['amount']}\n"
                f"- Date UTC: {normal_bridge_case['date_utc']}\n"
                f"- Transaction: `{normal_bridge_case['tx_hash']}`\n\n"
            )

        if risk_anchor_case:
            f.write("### Direct risk-anchor case\n\n")
            f.write(
                f"Seed `{risk_anchor_case['seed']}` ({risk_anchor_case['seed_label']}) "
                f"had a direct {risk_anchor_case['direction']} transfer with "
                f"`{risk_anchor_case['counterparty']}` "
                f"({risk_anchor_case['counterparty_kind']}). This demonstrates a simple "
                "one-hop traceable link to a known anchor.\n\n"
            )
            f.write(
                f"- Amount: {risk_anchor_case['amount']} {risk_anchor_case['token']}\n"
                f"- Date UTC: {risk_anchor_case['date_utc']}\n"
                f"- Transaction: `{risk_anchor_case['tx_hash']}`\n\n"
            )

        if top_seed:
            f.write("### Highest-evidence seed\n\n")
            f.write(
                f"The seed with the most direct evidence rows was `{top_seed}` "
                f"with {by_seed[top_seed]} matched counterparty transfers.\n\n"
            )

        f.write("## Interpretation for Report 2\n\n")
        f.write(
            "The pilot supports a modest but useful claim: stablecoin transfer logs can be "
            "used to construct bounded traceability evidence on a laptop. The experiment also "
            "shows why traceability classification matters: blacklist/OFAC entries act as "
            "anchors, and traceable bridges indicate possible cross-chain continuation. This "
            "particular cached sample did not contain direct mixer or opaque-bridge matches "
            "after protocol-address filtering, but the registry explicitly treats those "
            "mechanisms as tracing boundaries. The current data is only a pilot sample, so it "
            "should not be presented as a full evaluation.\n"
        )

    print(f"Wrote {direct_hits_csv}")
    print(f"Wrote {summary}")
    print(f"direct evidence rows: {len(rows)}")
    print(f"seeds with hits: {len(seeds_with_hits)} / {len(transfer_files)}")
    print(f"categories: {dict(category_counts)}")


if __name__ == "__main__":
    main()
