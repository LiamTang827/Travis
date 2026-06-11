#!/usr/bin/env python3
"""Run one cross-chain stablecoin bridge trace case for Stargate (LayerZero).

This mirrors run_across_bridge_trace_case.py but for a message-passing bridge.
Stargate routes through LayerZero, so the destination hop is resolved through
the LayerZero Scan API rather than the Across status API. The evidence chain has
the same trustless--trusted--trustless structure:

  1. source step  (trustless): decode the Stargate/LayerZero send on the source
     chain from the Ethereum transaction receipt;
  2. bridge step  (trusted):   query LayerZero Scan for the destination tx that
     this source message was delivered to;
  3. destination step (trustless): fetch the destination-chain receipt and
     confirm the transaction exists on-chain.

Usage (run on your own machine, with ETHERSCAN_API_KEY in .env):

  python experiments/traceability/run_stargate_bridge_trace_case.py <source_tx_hash>

Pick a source tx that is a Stargate USDC/USDT transfer out of Ethereum. If no
hash is supplied, the script prints guidance instead of fabricating a result.

Outputs:
  artifacts/bridge_trace_case/stargate_trace_case.json
  artifacts/bridge_trace_case/stargate_trace_case.md
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "artifacts" / "bridge_trace_case"
OUT_JSON = OUT_DIR / "stargate_trace_case.json"
OUT_MD = OUT_DIR / "stargate_trace_case.md"

ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"
# LayerZero Scan public API (v1). Returns the cross-chain message(s) for a tx,
# including the destination tx hash once the message is DELIVERED.
LAYERZERO_SCAN = "https://scan.layerzero-api.com/v1/messages/tx/{tx_hash}"

ORIGIN_CHAIN_ID = 1
ORIGIN_CHAIN_NAME = "ethereum"

# Known Stargate routers / endpoints on Ethereum (lowercased). Used only to
# confirm the source tx really interacted with a Stargate/LayerZero contract.
STARGATE_SOURCE_CONTRACTS = {
    "0x8731d54e9d02c286767d56ac03e8037c07e01e98",  # Stargate Router (ETH)
    "0x296f55f8fb28e498b858d0bcda06d955b2cb3f97",  # Stargate STG (ETH)
    "0x66a71dcef29a0ffbdbe3c6a460a3b5bc225cd675",  # LayerZero Endpoint v1 (ETH)
    "0x1a44076050125825900e736c501f859c50fe728c",  # LayerZero Endpoint v2
}

# LayerZero EID / chain mapping for human-readable destination naming.
LZ_CHAIN_NAMES = {
    101: "ethereum", 102: "bsc", 106: "avalanche", 109: "polygon",
    110: "arbitrum", 111: "optimism", 184: "base", 30101: "ethereum",
    30102: "bsc", 30106: "avalanche", 30109: "polygon", 30110: "arbitrum",
    30111: "optimism", 30184: "base",
}

EVM_CHAIN_NAMES = {
    1: "ethereum", 10: "optimism", 56: "bsc", 137: "polygon",
    8453: "base", 42161: "arbitrum", 43114: "avalanche",
}

EXPLORERS = {
    1: "https://etherscan.io/tx/",
    10: "https://optimistic.etherscan.io/tx/",
    56: "https://bscscan.com/tx/",
    137: "https://polygonscan.com/tx/",
    8453: "https://basescan.org/tx/",
    42161: "https://arbiscan.io/tx/",
    43114: "https://snowtrace.io/tx/",
}


def require_api_key() -> str:
    load_dotenv(ROOT / ".env")
    key = os.getenv("ETHERSCAN_API_KEY", "")
    if not key:
        raise RuntimeError("ETHERSCAN_API_KEY is missing in .env")
    return key


def etherscan_proxy(chain_id: int, action: str, **params: str) -> Any:
    key = require_api_key()
    payload = {
        "chainid": str(chain_id),
        "module": "proxy",
        "action": action,
        "apikey": key,
        **params,
    }
    response = requests.get(ETHERSCAN_V2, params=payload, timeout=30)
    response.raise_for_status()
    data = response.json()
    if "error" in data:
        raise RuntimeError(data["error"])
    result = data.get("result")
    if result is None:
        raise RuntimeError(f"No result for {action}: {data}")
    return result


def hex_to_int(value: str) -> int:
    return int(value, 16)


def identify_source_contract(receipt: dict[str, Any]) -> Optional[str]:
    """Confirm the tx touched a known Stargate/LayerZero contract."""
    touched = set()
    to_addr = (receipt.get("to") or "").lower()
    if to_addr:
        touched.add(to_addr)
    for log in receipt.get("logs", []):
        touched.add(log.get("address", "").lower())
    hit = touched & STARGATE_SOURCE_CONTRACTS
    return next(iter(hit)) if hit else None


def fetch_layerzero_message(tx_hash: str) -> dict[str, Any]:
    """Trusted bridge step: ask LayerZero Scan for the destination tx."""
    resp = requests.get(LAYERZERO_SCAN.format(tx_hash=tx_hash), timeout=30)
    resp.raise_for_status()
    return resp.json()


def extract_destination(lz_payload: dict[str, Any]) -> dict[str, Any]:
    """Pull destination tx hash + chain from the LayerZero Scan response.

    The v1 response shape is {"data": [{"pathway": {...}, "source": {...},
    "destination": {"tx": {"txHash": ...}, ...}, "status": {...}}]}.
    """
    messages = lz_payload.get("data") or []
    if not messages:
        return {"resolved": False, "reason": "no LayerZero message indexed for this tx"}
    msg = messages[0]
    dest = msg.get("destination", {}) or {}
    dest_tx = (dest.get("tx") or {}).get("txHash")
    status = (msg.get("status") or {}).get("name") or msg.get("status")
    pathway = msg.get("pathway", {}) or {}
    dst_eid = pathway.get("dstEid")
    return {
        "resolved": bool(dest_tx),
        "status": status,
        "dst_eid": dst_eid,
        "dst_chain_guess": LZ_CHAIN_NAMES.get(dst_eid, f"eid_{dst_eid}"),
        "destination_tx": dest_tx,
    }


def evm_chain_id_for(name: str) -> Optional[int]:
    for cid, nm in EVM_CHAIN_NAMES.items():
        if nm == name:
            return cid
    return None


def run(source_tx: str) -> dict[str, Any]:
    receipt = etherscan_proxy(ORIGIN_CHAIN_ID, "eth_getTransactionReceipt", txhash=source_tx)
    source_contract = identify_source_contract(receipt)

    lz_payload = fetch_layerzero_message(source_tx)
    dest = extract_destination(lz_payload)

    dest_receipt = None
    dest_chain_id = evm_chain_id_for(dest.get("dst_chain_guess", ""))
    if dest.get("destination_tx") and dest_chain_id:
        try:
            dest_receipt = etherscan_proxy(
                dest_chain_id, "eth_getTransactionReceipt", txhash=dest["destination_tx"]
            )
        except Exception as exc:  # noqa: BLE001
            dest_receipt = {"error": str(exc)}

    classification = (
        "protocol-assisted traceable bridge"
        if dest.get("resolved")
        else "registry-only bridge (destination not resolved)"
    )

    result = {
        "case_name": "Stargate / LayerZero stablecoin bridge trace",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "classification": classification,
        "source_transaction": source_tx,
        "source_explorer": EXPLORERS[1] + source_tx,
        "source_contract_matched": source_contract,
        "source_is_known_stargate": bool(source_contract),
        "destination_resolution": dest,
        "destination_transaction": dest.get("destination_tx"),
        "destination_explorer": (
            EXPLORERS.get(dest_chain_id, EXPLORERS[1]) + dest["destination_tx"]
            if dest.get("destination_tx")
            else None
        ),
        "destination_receipt_observed": bool(dest_receipt and "error" not in dest_receipt),
        "evidence_strength": {
            "source_step": "trustless (Ethereum receipt + known Stargate/LayerZero contract)",
            "bridge_step": "trusted (LayerZero Scan API maps source message to destination tx)",
            "destination_step": "trustless (destination receipt re-anchors the API claim)",
        },
        "raw_layerzero_message": lz_payload,
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT_MD.write_text(render_markdown(result), encoding="utf-8")
    return result


def render_markdown(result: dict[str, Any]) -> str:
    dest = result["destination_resolution"]
    lines = [
        "# Stargate / LayerZero Bridge Trace Case",
        "",
        "## Claim",
        "",
        "This is a message-passing bridge trace via LayerZero. The source-chain "
        "transaction interacts with a known Stargate/LayerZero contract; LayerZero "
        "Scan then maps the source message to the destination delivery transaction; "
        "the destination receipt is fetched to re-anchor that claim on-chain.",
        "",
        "## Source",
        "",
        f"- Bridge family: Stargate (LayerZero)",
        f"- Classification: {result['classification']}",
        f"- Source tx: `{result['source_transaction']}`",
        f"- Source explorer: {result['source_explorer']}",
        f"- Matched known contract: `{result['source_contract_matched']}`",
        "",
        "## Destination (protocol-assisted, via LayerZero Scan)",
        "",
        f"- Resolved: `{dest.get('resolved')}`",
        f"- LayerZero status: `{dest.get('status')}`",
        f"- Destination chain: {dest.get('dst_chain_guess')}",
        f"- Destination tx: `{result['destination_transaction']}`",
        f"- Destination explorer: {result['destination_explorer']}",
        f"- Destination receipt observed: `{result['destination_receipt_observed']}`",
        "",
        "## Evidence Strength (trustless--trusted--trustless)",
        "",
        f"- Source step: {result['evidence_strength']['source_step']}",
        f"- Bridge step: {result['evidence_strength']['bridge_step']}",
        f"- Destination step: {result['evidence_strength']['destination_step']}",
        "",
        "## Report Interpretation",
        "",
        "If `resolved=true`, this is a second protocol-assisted bridge case using a "
        "different mechanism (message-passing) and a different indexer (LayerZero Scan) "
        "than the Across liquidity-fill case, supporting the generality of the "
        "evidence-first model. If `resolved=false`, this is honestly a registry-only "
        "interaction: the contract is identified but the destination is not yet "
        "linked, which is itself a valid evidence-first outcome.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nNo source tx hash supplied. Example:")
        print("  python experiments/traceability/run_stargate_bridge_trace_case.py 0x<stargate_usdc_tx>")
        print("\nThe script will NOT fabricate a trace without a real source transaction.")
        sys.exit(0)
    trace = run(sys.argv[1])
    print(json.dumps(
        {k: trace[k] for k in ("classification", "source_contract_matched",
                               "destination_transaction", "destination_receipt_observed")},
        indent=2, ensure_ascii=False,
    ))
    print(f"\nWrote {OUT_JSON}")
    print(f"Wrote {OUT_MD}")
