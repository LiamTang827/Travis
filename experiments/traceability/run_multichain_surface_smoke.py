#!/usr/bin/env python3
"""Multi-chain traceability surface smoke test.

This laptop-sized experiment does not claim to trace laundering across Solana,
Tron, or Hyperliquid. Instead, it completes bounded traceability-surface checks:
public endpoints are queried, live heads are observed, and per-chain case
scripts record the strongest evidence that can be obtained without fabricating a
cross-chain destination.

Outputs:
  artifacts/multichain_surface_smoke/results.json
  artifacts/multichain_surface_smoke/summary.md
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "artifacts" / "multichain_surface_smoke"
OUT_JSON = OUT_DIR / "results.json"
OUT_MD = OUT_DIR / "summary.md"


def post_json(url: str, payload: dict[str, Any], timeout: int = 20) -> dict[str, Any]:
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            response = requests.post(url, json=payload, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(1 + attempt)
    raise last_error or RuntimeError("request failed")


def get_json(url: str, timeout: int = 20) -> dict[str, Any]:
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(1 + attempt)
    raise last_error or RuntimeError("request failed")


def smoke_solana() -> dict[str, Any]:
    url = "https://api.mainnet-beta.solana.com"
    version = post_json(
        url,
        {"jsonrpc": "2.0", "id": 1, "method": "getVersion"},
    )
    slot = post_json(
        url,
        {"jsonrpc": "2.0", "id": 2, "method": "getSlot"},
    )
    return {
        "name": "Solana",
        "reachable": True,
        "endpoint": url,
        "latest_slot": slot.get("result"),
        "version": version.get("result", {}),
        "address_model": "base58 public keys; token balances live in SPL token accounts",
        "stablecoin_surface": "SPL token account transfers and program instructions",
        "bridge_surfaces": [
            "Circle CCTP: burn message, Circle attestation, destination mint recipient",
            "Wormhole: emitter, sequence, signed VAA, destination redeem instruction",
        ],
        "traceability_limitation": (
            "Not EVM-compatible; ERC-20 Transfer logs and 0x addresses do not apply. "
            "The completed Solana case reads program instructions and token-account changes, "
            "but does not infer a counterparty chain without a recovered message/attestation."
        ),
    }


def smoke_tron() -> dict[str, Any]:
    url = "https://api.trongrid.io/wallet/getnowblock"
    block = post_json(url, {})
    header = block.get("block_header", {}).get("raw_data", {})
    return {
        "name": "Tron",
        "reachable": True,
        "endpoint": url,
        "latest_block_number": header.get("number"),
        "latest_block_timestamp": header.get("timestamp"),
        "address_model": "base58check Tron addresses; account-based smart contracts",
        "stablecoin_surface": "TRC-20 USDT transfer records via TronGrid/TronScan-style APIs",
        "bridge_surfaces": [
            "BTTC / BitTorrent Bridge: TRON, BTTC, Ethereum, and BNB Chain transfer path",
            "CEX or issuer routes: visible as deposits/withdrawals, but internal ledger is hidden",
        ],
        "traceability_limitation": (
            "Similar to EVM at the token-transfer level, but APIs, address encoding, "
            "and receipt formats differ. The completed Tron case verifies TRC-20 USDT "
            "transfer evidence; CEX-mediated movement remains an off-chain break."
        ),
    }


def smoke_hyperevm() -> dict[str, Any]:
    url = "https://rpc.hyperliquid.xyz/evm"
    chain_id = post_json(
        url,
        {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
    )
    block_number = post_json(
        url,
        {"jsonrpc": "2.0", "id": 2, "method": "eth_blockNumber", "params": []},
    )
    raw_chain_id = chain_id.get("result")
    raw_block = block_number.get("result")
    return {
        "name": "Hyperliquid / HyperEVM",
        "reachable": True,
        "endpoint": url,
        "chain_id_hex": raw_chain_id,
        "chain_id_decimal": int(raw_chain_id, 16) if raw_chain_id else None,
        "latest_block_number_hex": raw_block,
        "latest_block_number_decimal": int(raw_block, 16) if raw_block else None,
        "address_model": "EVM-compatible 0x addresses on HyperEVM plus HyperCore accounts/actions",
        "stablecoin_surface": "ERC-20 logs on HyperEVM; HyperCore spot balances/actions outside normal ERC-20 graph",
        "bridge_surfaces": [
            "HyperEVM: ordinary EVM JSON-RPC, contract calls, ERC-20 logs",
            "HyperCore <> HyperEVM: system-address transfers and linked spot assets",
        ],
        "traceability_limitation": (
            "HyperEVM can be parsed with EVM tooling, but HyperCore introduces a trading/"
            "settlement surface that is not fully represented by ERC-20 Transfer logs."
        ),
    }


SURFACE_CLASSIFICATION = [
    {
        "system": "Solana CCTP",
        "evm_connectable": True,
        "strong_linkage_fields": ["source tx", "CCTP nonce/message", "attestation", "mint recipient"],
        "current_status": "completed Solana CCTP surface case (receive-side evidence)",
    },
    {
        "system": "Solana Wormhole",
        "evm_connectable": True,
        "strong_linkage_fields": ["emitter", "sequence", "VAA", "redeem tx"],
        "current_status": "not selected for case study",
    },
    {
        "system": "Tron / BTTC",
        "evm_connectable": True,
        "strong_linkage_fields": ["TRC-20 transfer", "bridge gateway tx", "destination tx"],
        "current_status": "completed Tron TRC-20 USDT token-level case",
    },
    {
        "system": "HyperEVM",
        "evm_connectable": True,
        "strong_linkage_fields": ["EVM receipt", "ERC-20 logs", "contract address", "chainId=999"],
        "current_status": "completed EVM-surface probe",
    },
    {
        "system": "HyperCore",
        "evm_connectable": "partially",
        "strong_linkage_fields": ["system address", "linked spot asset", "core action"],
        "current_status": "completed HyperEVM/HyperCore boundary probe",
    },
]


def run() -> dict[str, Any]:
    checks = []
    for fn in (smoke_solana, smoke_tron, smoke_hyperevm):
        try:
            checks.append(fn())
        except Exception as exc:
            checks.append(
                {
                    "name": fn.__name__.replace("smoke_", ""),
                    "reachable": False,
                    "error": str(exc),
                }
            )

    result = {
        "experiment": "multi-chain traceability surface smoke test",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": (
            "Complete bounded non-EVM and hybrid stablecoin traceability-surface checks "
            "without claiming unsupported cross-chain destinations."
        ),
        "checks": checks,
        "surface_classification": SURFACE_CLASSIFICATION,
        "report_claim": (
            "The current prototype has completed bounded surface cases for Solana, Tron, "
            "and HyperEVM/HyperCore. These cases extend the evidence-first workflow beyond "
            "EVM-like bridges while marking unresolved cross-chain hops as evidence boundaries."
        ),
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT_MD.write_text(render_markdown(result), encoding="utf-8")
    return result


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Multi-Chain Traceability Surface Smoke Test",
        "",
        "## Purpose",
        "",
        result["purpose"],
        "",
        "## Connectivity Checks",
        "",
        "| System | Reachable | Observed head / chain ID | Traceability surface |",
        "|---|---:|---|---|",
    ]
    for check in result["checks"]:
        if check.get("name") == "Solana":
            observed = f"slot {check.get('latest_slot')}"
        elif check.get("name") == "Tron":
            observed = f"block {check.get('latest_block_number')}"
        elif check.get("name") == "Hyperliquid / HyperEVM":
            observed = (
                f"chainId {check.get('chain_id_decimal')}, "
                f"block {check.get('latest_block_number_decimal')}"
            )
        else:
            observed = check.get("error", "")
        lines.append(
            f"| {check.get('name')} | {check.get('reachable')} | {observed} | "
            f"{check.get('stablecoin_surface', '')} |"
        )

    lines.extend(
        [
            "",
            "## Evidence-Surface Classification",
            "",
            "| System | EVM-connectable | Strong linkage fields | Current prototype status |",
            "|---|---:|---|---|",
        ]
    )
    for row in result["surface_classification"]:
        fields = ", ".join(row["strong_linkage_fields"])
        lines.append(
            f"| {row['system']} | {row['evm_connectable']} | {fields} | {row['current_status']} |"
        )

    lines.extend(
        [
            "",
            "## Report Interpretation",
            "",
            result["report_claim"],
            "",
            "This should be presented as completed bounded surface testing, not as a completed "
            "cross-chain laundering reconstruction on Solana, Tron, or Hyperliquid.",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    output = run()
    print(json.dumps(output["checks"], indent=2, ensure_ascii=False))
    print(f"\nWrote {OUT_JSON}")
    print(f"Wrote {OUT_MD}")
