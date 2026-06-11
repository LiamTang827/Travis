#!/usr/bin/env python3
"""Run one deterministic cross-chain stablecoin bridge trace case.

The case uses an Across Protocol V3 USDC deposit on Ethereum. It verifies:
1. the source-chain V3FundsDeposited event in the transaction receipt,
2. the destination chain and recipient encoded in the event,
3. the protocol-assisted fill status returned by Across' deposit/status API.

Outputs:
  artifacts/bridge_trace_case/across_trace_case.json
  artifacts/bridge_trace_case/across_trace_case.md
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "artifacts" / "bridge_trace_case"
OUT_JSON = OUT_DIR / "across_trace_case.json"
OUT_MD = OUT_DIR / "across_trace_case.md"

ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"
ACROSS_STATUS = "https://app.across.to/api/deposit/status"

ORIGIN_CHAIN_ID = 1
ORIGIN_CHAIN_NAME = "ethereum"
SPOKE_POOL_ETHEREUM = "0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5"

DEPOSIT_TX = "0x024b2b3cfffddb12ef9b93da592f1ec754c457281b11be4e24324cd26359b3f5"
V3_FUNDS_DEPOSITED_TOPIC = (
    "0xa123dc29aebf7d0c3322c8eeb5b999e859f39937950ed31056532713d0de396f"
)

CHAIN_NAMES = {
    1: "ethereum",
    10: "optimism",
    137: "polygon",
    324: "zksync",
    8453: "base",
    42161: "arbitrum",
    59144: "linea",
}

TOKEN_DECIMALS = {
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": ("USDC", 6),
    "0xdac17f958d2ee523a2206206994597c13d831ec7": ("USDT", 6),
    "0xaf88d065e77c8cc2239327c5edb3a432268e5831": ("USDC (Arbitrum)", 6),
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": ("WETH", 18),
    "0xe5d7c2a44ffddf6b295a15c148167daaaf5cf34f": ("WETH (Linea)", 18),
    "0x0000000000000000000000000000000000000000": ("native/zero-address placeholder", 18),
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


def word_to_address(word_hex: str) -> str:
    return "0x" + word_hex[-40:].lower()


def split_words(data_hex: str) -> list[str]:
    clean = data_hex[2:] if data_hex.startswith("0x") else data_hex
    return [clean[i : i + 64] for i in range(0, len(clean), 64)]


def token_display(address: str, amount: int) -> dict[str, Any]:
    symbol, decimals = TOKEN_DECIMALS.get(address.lower(), ("unknown", 18))
    return {
        "address": address,
        "symbol": symbol,
        "raw_amount": str(amount),
        "decimals": decimals,
        "display_amount": amount / (10**decimals),
    }


def decode_v3_funds_deposited(receipt: dict[str, Any]) -> dict[str, Any]:
    for log in receipt.get("logs", []):
        if log.get("address", "").lower() != SPOKE_POOL_ETHEREUM:
            continue
        topics = [t.lower() for t in log.get("topics", [])]
        if not topics or topics[0] != V3_FUNDS_DEPOSITED_TOPIC:
            continue

        words = split_words(log.get("data", "0x"))
        if len(topics) < 4 or len(words) < 10:
            raise RuntimeError("V3FundsDeposited log shape was shorter than expected")

        destination_chain_id = hex_to_int(topics[1])
        deposit_id = hex_to_int(topics[2])
        depositor = word_to_address(topics[3])

        input_token = word_to_address(words[0])
        output_token = word_to_address(words[1])
        input_amount = int(words[2], 16)
        output_amount = int(words[3], 16)
        quote_timestamp = int(words[4], 16)
        fill_deadline = int(words[5], 16)
        exclusivity_deadline = int(words[6], 16)
        recipient = word_to_address(words[7])
        exclusive_relayer = word_to_address(words[8])
        message_offset = int(words[9], 16)
        message_length = int(words[10], 16) if len(words) > 10 else 0

        return {
            "event": "V3FundsDeposited",
            "contract": log["address"],
            "block_number": hex_to_int(log["blockNumber"]),
            "block_timestamp_unix": hex_to_int(log.get("blockTimestamp", "0x0")),
            "block_timestamp_utc": datetime.fromtimestamp(
                hex_to_int(log.get("blockTimestamp", "0x0")), tz=timezone.utc
            ).isoformat(),
            "transaction_hash": log["transactionHash"],
            "origin_chain_id": ORIGIN_CHAIN_ID,
            "origin_chain": ORIGIN_CHAIN_NAME,
            "destination_chain_id": destination_chain_id,
            "destination_chain": CHAIN_NAMES.get(destination_chain_id, f"chain_{destination_chain_id}"),
            "deposit_id": deposit_id,
            "depositor": depositor,
            "recipient": recipient,
            "input": token_display(input_token, input_amount),
            "output": token_display(output_token, output_amount),
            "quote_timestamp_unix": quote_timestamp,
            "fill_deadline_unix": fill_deadline,
            "exclusivity_deadline_unix": exclusivity_deadline,
            "exclusive_relayer": exclusive_relayer,
            "message_offset": message_offset,
            "message_length": message_length,
            "evidence": [
                "source Ethereum transaction receipt",
                "Across V3FundsDeposited event topic",
                "indexed destinationChainId",
                "indexed depositId",
                "indexed depositor",
                "non-indexed recipient in event data",
            ],
        }

    raise RuntimeError("No Across V3FundsDeposited event found in deposit transaction receipt")


def fetch_across_status(deposit_tx: str, origin_chain_id: int, deposit_id: int) -> dict[str, Any]:
    by_hash = requests.get(
        ACROSS_STATUS,
        params={"depositTxnRef": deposit_tx},
        timeout=30,
    )
    by_hash.raise_for_status()

    by_id = requests.get(
        ACROSS_STATUS,
        params={"originChainId": str(origin_chain_id), "depositId": str(deposit_id)},
        timeout=30,
    )
    by_id.raise_for_status()

    return {
        "queried_by_deposit_tx": by_hash.json(),
        "queried_by_origin_chain_and_deposit_id": by_id.json(),
    }


def run() -> dict[str, Any]:
    receipt = etherscan_proxy(
        ORIGIN_CHAIN_ID,
        "eth_getTransactionReceipt",
        txhash=DEPOSIT_TX,
    )
    event = decode_v3_funds_deposited(receipt)
    status = fetch_across_status(DEPOSIT_TX, ORIGIN_CHAIN_ID, event["deposit_id"])

    fill_tx = status["queried_by_deposit_tx"].get("fillTx")
    fill_receipt = None
    if fill_tx:
        fill_receipt = etherscan_proxy(
            event["destination_chain_id"],
            "eth_getTransactionReceipt",
            txhash=fill_tx,
        )

    result = {
        "case_name": "Across Ethereum to Arbitrum USDC bridge trace",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "protocol-assisted traceable bridge",
        "source_transaction": DEPOSIT_TX,
        "source_explorer": f"https://etherscan.io/tx/{DEPOSIT_TX}",
        "destination_transaction": fill_tx,
        "destination_explorer": (
            destination_explorer(event["destination_chain_id"], fill_tx) if fill_tx else None
        ),
        "decoded_source_event": event,
        "across_status": status,
        "destination_receipt_observed": bool(fill_receipt),
        "destination_receipt_summary": {
            "chain_id": event["destination_chain_id"],
            "chain": event["destination_chain"],
            "tx_hash": fill_tx,
            "block_number": hex_to_int(fill_receipt["blockNumber"]) if fill_receipt else None,
            "from": fill_receipt.get("from") if fill_receipt else None,
            "to": fill_receipt.get("to") if fill_receipt else None,
            "log_count": len(fill_receipt.get("logs", [])) if fill_receipt else None,
        },
        "trace_path": [
            {
                "type": "source_tx",
                "chain": event["origin_chain"],
                "tx_hash": DEPOSIT_TX,
                "contract": event["contract"],
            },
            {
                "type": "bridge_event",
                "bridge": "Across Protocol V3",
                "event": event["event"],
                "deposit_id": event["deposit_id"],
                "destination_chain": event["destination_chain"],
                "recipient": event["recipient"],
            },
            {
                "type": "destination_fill",
                "chain": event["destination_chain"],
                "tx_hash": fill_tx,
                "status": status["queried_by_deposit_tx"].get("status"),
            },
        ],
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT_MD.write_text(render_markdown(result), encoding="utf-8")
    return result


def destination_explorer(chain_id: int, tx_hash: str) -> str:
    explorers = {
        42161: "https://arbiscan.io/tx/",
        59144: "https://lineascan.build/tx/",
        10: "https://optimistic.etherscan.io/tx/",
        8453: "https://basescan.org/tx/",
        137: "https://polygonscan.com/tx/",
    }
    return explorers.get(chain_id, "https://etherscan.io/tx/") + tx_hash


def render_markdown(result: dict[str, Any]) -> str:
    event = result["decoded_source_event"]
    status = result["across_status"]["queried_by_deposit_tx"]
    dest = result["destination_receipt_summary"]
    lines = [
        "# Across USDC Bridge Trace Case",
        "",
        "## Claim",
        "",
        "This is one completed deterministic/protocol-assisted stablecoin bridge trace instance. "
        "The source-chain event gives the destination chain, deposit ID, depositor, "
        "recipient, and amount. Across' status API then links the deposit transaction "
        "to the destination fill transaction.",
        "",
        "## Source Event",
        "",
        f"- Bridge: Across Protocol V3",
        f"- Classification: {result['classification']}",
        f"- Origin chain: {event['origin_chain']} ({event['origin_chain_id']})",
        f"- Source tx: `{result['source_transaction']}`",
        f"- Source explorer: {result['source_explorer']}",
        f"- Event: `{event['event']}`",
        f"- Deposit ID: `{event['deposit_id']}`",
        f"- Depositor: `{event['depositor']}`",
        f"- Recipient: `{event['recipient']}`",
        f"- Destination chain: {event['destination_chain']} ({event['destination_chain_id']})",
        f"- Input: {event['input']['display_amount']} {event['input']['symbol']} "
        f"({event['input']['raw_amount']} raw)",
        f"- Output: {event['output']['display_amount']} {event['output']['symbol']} "
        f"({event['output']['raw_amount']} raw)",
        "",
        "## Destination Fill",
        "",
        f"- Status: `{status.get('status')}`",
        f"- Destination tx: `{result['destination_transaction']}`",
        f"- Destination explorer: {result['destination_explorer']}",
        f"- Destination receipt observed: `{result['destination_receipt_observed']}`",
        f"- Destination block: `{dest['block_number']}`",
        f"- Destination tx sender/relayer: `{dest['from']}`",
        "",
        "## Evidence Used",
        "",
    ]
    for item in event["evidence"]:
        lines.append(f"- {item}")
    lines.extend(
        [
            "- Across `/deposit/status` API queried by both deposit transaction hash and originChainId+depositId",
            "- Destination-chain transaction receipt fetched through Etherscan V2 multi-chain API",
            "",
            "## Report Interpretation",
            "",
        "This case should be described as a protocol-assisted traceable stablecoin bridge. "
            "It is stronger than a registry-only bridge interaction because the Across event exposes "
            "the destination chain and recipient, and the Across status API returns the destination fill transaction. "
            "It is not based on time-window or amount-similarity heuristics.",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    trace = run()
    print(json.dumps(trace["trace_path"], indent=2, ensure_ascii=False))
    print(f"\nWrote {OUT_JSON}")
    print(f"Wrote {OUT_MD}")
