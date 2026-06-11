#!/usr/bin/env python3
"""Batch experiment for Across stablecoin bridge resolution.

This experiment scans a bounded Ethereum block window for Across V3
V3FundsDeposited events, filters stablecoin cases, and checks whether each
candidate can be resolved to a destination fill transaction through Across'
public status API.

Outputs:
  artifacts/bridge_batch_resolution/across_batch_resolution.json
  artifacts/bridge_batch_resolution/across_batch_resolution.md
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "artifacts" / "bridge_batch_resolution"
OUT_JSON = OUT_DIR / "across_batch_resolution.json"
OUT_MD = OUT_DIR / "across_batch_resolution.md"

ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"
ACROSS_STATUS = "https://app.across.to/api/deposit/status"

ORIGIN_CHAIN_ID = 1
SPOKE_POOL_ETHEREUM = "0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5"
V3_FUNDS_DEPOSITED_TOPIC = (
    "0xa123dc29aebf7d0c3322c8eeb5b999e859f39937950ed31056532713d0de396f"
)

# Bounded window around the single-case transaction. This keeps the experiment
# reproducible and laptop-friendly while still giving a real batch sample.
FROM_BLOCK = 20_600_000
TO_BLOCK = 20_602_000
MAX_CASES_TO_VERIFY = 20

CHAIN_NAMES = {
    1: "ethereum",
    10: "optimism",
    137: "polygon",
    324: "zksync",
    8453: "base",
    42161: "arbitrum",
    59144: "linea",
}

STABLE_TOKENS = {
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": ("USDC", 6),
    "0xdac17f958d2ee523a2206206994597c13d831ec7": ("USDT", 6),
    "0xaf88d065e77c8cc2239327c5edb3a432268e5831": ("USDC", 6),
    "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8": ("USDC.e", 6),
    "0x0b2c639c533813f4aa9d7837caf62653d097ff85": ("USDC", 6),
    "0x2791bca1f2de4661ed88a30c99a7a9449aa84174": ("USDC.e", 6),
    "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": ("USDC", 6),
}


def require_api_key() -> str:
    load_dotenv(ROOT / ".env")
    key = os.getenv("ETHERSCAN_API_KEY", "")
    if not key:
        raise RuntimeError("ETHERSCAN_API_KEY is missing in .env")
    return key


def fetch_logs() -> list[dict[str, Any]]:
    params = {
        "chainid": str(ORIGIN_CHAIN_ID),
        "module": "logs",
        "action": "getLogs",
        "address": SPOKE_POOL_ETHEREUM,
        "fromBlock": str(FROM_BLOCK),
        "toBlock": str(TO_BLOCK),
        "topic0": V3_FUNDS_DEPOSITED_TOPIC,
        "apikey": require_api_key(),
    }
    response = requests.get(ETHERSCAN_V2, params=params, timeout=45)
    response.raise_for_status()
    data = response.json()
    result = data.get("result", [])
    if isinstance(result, str):
        raise RuntimeError(result)
    return result


def split_words(data_hex: str) -> list[str]:
    clean = data_hex[2:] if data_hex.startswith("0x") else data_hex
    return [clean[i : i + 64] for i in range(0, len(clean), 64)]


def word_to_address(word_hex: str) -> str:
    return "0x" + word_hex[-40:].lower()


def decode_event(log: dict[str, Any]) -> dict[str, Any] | None:
    topics = [t.lower() for t in log.get("topics", [])]
    words = split_words(log.get("data", "0x"))
    if len(topics) < 4 or len(words) < 9:
        return None

    input_token = word_to_address(words[0])
    output_token = word_to_address(words[1])
    if input_token not in STABLE_TOKENS and output_token not in STABLE_TOKENS:
        return None

    input_symbol, input_decimals = STABLE_TOKENS.get(input_token, ("unknown", 18))
    output_symbol, output_decimals = STABLE_TOKENS.get(output_token, ("unknown", 18))
    input_amount = int(words[2], 16)
    output_amount = int(words[3], 16)
    destination_chain_id = int(topics[1], 16)
    deposit_id = int(topics[2], 16)
    depositor = word_to_address(topics[3])
    recipient = word_to_address(words[7])

    return {
        "tx_hash": log["transactionHash"],
        "block_number": int(log["blockNumber"], 16),
        "timestamp_unix": int(log.get("timeStamp", "0x0"), 16),
        "timestamp_utc": datetime.fromtimestamp(
            int(log.get("timeStamp", "0x0"), 16), tz=timezone.utc
        ).isoformat(),
        "deposit_id": deposit_id,
        "destination_chain_id": destination_chain_id,
        "destination_chain": CHAIN_NAMES.get(destination_chain_id, f"chain_{destination_chain_id}"),
        "depositor": depositor,
        "recipient": recipient,
        "input_token": input_token,
        "input_symbol": input_symbol,
        "input_amount": input_amount / (10**input_decimals),
        "output_token": output_token,
        "output_symbol": output_symbol,
        "output_amount": output_amount / (10**output_decimals),
    }


def fetch_status(case: dict[str, Any]) -> dict[str, Any]:
    response = requests.get(
        ACROSS_STATUS,
        params={"originChainId": str(ORIGIN_CHAIN_ID), "depositId": str(case["deposit_id"])},
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()
    return {
        "status": data.get("status"),
        "fill_tx": data.get("fillTx"),
        "deposit_tx_hash": data.get("depositTxHash") or data.get("depositTxnRef"),
    }


def run() -> dict[str, Any]:
    logs = fetch_logs()
    decoded = [case for log in logs if (case := decode_event(log))]
    to_verify = decoded[:MAX_CASES_TO_VERIFY]
    verified: list[dict[str, Any]] = []

    for case in to_verify:
        status = fetch_status(case)
        verified.append({**case, **status})
        time.sleep(0.25)

    status_counts = Counter(case.get("status") or "unknown" for case in verified)
    chain_counts = Counter(case["destination_chain"] for case in decoded)
    token_counts = Counter(case["input_symbol"] for case in decoded)
    resolved = [case for case in verified if case.get("fill_tx")]

    return {
        "experiment": "Across batch stablecoin bridge resolution",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_chain": "ethereum",
        "bridge": "Across Protocol V3",
        "block_window": {"from": FROM_BLOCK, "to": TO_BLOCK},
        "raw_v3_deposit_events": len(logs),
        "stablecoin_candidate_events": len(decoded),
        "verified_candidate_limit": MAX_CASES_TO_VERIFY,
        "verified_candidates": len(verified),
        "resolved_with_fill_tx": len(resolved),
        "status_counts": dict(status_counts),
        "destination_chain_counts_in_candidates": dict(chain_counts),
        "input_token_counts_in_candidates": dict(token_counts),
        "cases": verified,
        "interpretation": (
            "This batch experiment tests whether the Across resolver works beyond a single hand-picked "
            "transaction. It scans a fixed block window, filters stablecoin deposit events, and verifies "
            "a bounded sample through Across' public status API."
        ),
    }


def write_outputs(result: dict[str, Any]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2), encoding="utf-8")

    lines = [
        "# Across Batch Stablecoin Bridge Resolution",
        "",
        "## Setup",
        "",
        f"- Bridge: {result['bridge']}",
        f"- Source chain: {result['source_chain']}",
        f"- Block window: {result['block_window']['from']} to {result['block_window']['to']}",
        f"- Raw V3FundsDeposited events: {result['raw_v3_deposit_events']}",
        f"- Stablecoin candidate events: {result['stablecoin_candidate_events']}",
        f"- Verified candidate limit: {result['verified_candidate_limit']}",
        "",
        "## Results",
        "",
        f"- Verified candidates: {result['verified_candidates']}",
        f"- Resolved with destination fill tx: {result['resolved_with_fill_tx']}",
        f"- Status counts: `{result['status_counts']}`",
        f"- Candidate destination chains: `{result['destination_chain_counts_in_candidates']}`",
        f"- Candidate input tokens: `{result['input_token_counts_in_candidates']}`",
        "",
        "## Verified Cases",
        "",
    ]
    for case in result["cases"]:
        lines.extend(
            [
                f"- depositId `{case['deposit_id']}`: {case['input_amount']:.6f} {case['input_symbol']} "
                f"to {case['destination_chain']} / status `{case.get('status')}` / "
                f"fill `{case.get('fill_tx')}` / tx `{case['tx_hash']}`",
            ]
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            result["interpretation"],
            "The experiment is still protocol-specific, but it is stronger than a single case study because it applies the same resolver logic to multiple public stablecoin bridge events in a bounded block range.",
        ]
    )
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    output = run()
    write_outputs(output)
    print(json.dumps({k: output[k] for k in output if k != "cases"}, indent=2))
