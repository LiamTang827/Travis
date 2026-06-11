#!/usr/bin/env python3
"""
Transfer 事件抓取器 — ML 数据准备第二步
=========================================

对 labeled_addresses.csv 中的每个地址，用 getLogs 抓取其所有
USDT/USDC Transfer 事件（包括 sent 和 received 两个方向）。

为什么用 getLogs 而不是 txlist + tokentx：
  1. 避免 txlist 和 tokentx 的交叉重复（问题2）
  2. Transfer 事件是 token 移动的唯一权威记录
  3. 可以分别按 topic[1]=sender 和 topic[2]=receiver 查询，
     天然覆盖双向（解决问题3 — 不再只看 to 字段）

输入：experiments/ml/data/labeled_addresses.csv
输出：experiments/ml/data/transfers/{address}.json（每个地址一个文件）

用法：
  python experiments/ml/fetch_transfers.py
  python experiments/ml/fetch_transfers.py --limit 50
  python experiments/ml/fetch_transfers.py --skip-existing
  python experiments/ml/fetch_transfers.py --label blocklisted
"""

import os
import sys
import csv
import time
import json
import argparse
import requests
from typing import Optional, List, Dict, Set
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
REQUEST_DELAY = 0.25  # Etherscan 免费版限 5 req/s

# ==================== 常量 ====================
ETHERSCAN_API = "https://api.etherscan.io/v2/api"

# 稳定币合约（Ethereum）
STABLECOIN_CONTRACTS = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
}

# ERC-20 Transfer(address,address,uint256) 事件签名
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# 路径
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
LABELS_CSV = os.path.join(DATA_DIR, "labeled_addresses.csv")
TRANSFERS_DIR = os.path.join(DATA_DIR, "transfers")


# ==================== Etherscan getLogs ====================

def etherscan_get(params: dict, retry: int = 3) -> dict:
    params["apikey"] = ETHERSCAN_API_KEY
    params["chainid"] = 1  # Ethereum mainnet
    for attempt in range(retry):
        try:
            r = requests.get(ETHERSCAN_API, params=params, timeout=20)
            data = r.json()
            # 成功
            if data.get("status") == "1" and isinstance(data.get("result"), list):
                return data
            # 无结果（不算错误）
            if data.get("message") == "No records found":
                return {"result": []}
            # 速率限制
            if "rate limit" in str(data.get("result", "")).lower():
                time.sleep(2)
                continue
            # 其他错误
            if attempt < retry - 1:
                time.sleep(0.5)
        except Exception as e:
            if attempt < retry - 1:
                time.sleep(1)
    return {"result": []}


def addr_to_topic(addr: str) -> str:
    """地址转 32 字节 topic 格式：0x + 左补零到 64 位"""
    return "0x" + addr.lower().replace("0x", "").zfill(64)


def fetch_transfer_logs(
    token_contract: str,
    address: str,
    direction: str,  # "sent" or "received"
    from_block: int = 0,
    to_block: int = 99999999,
) -> List[dict]:
    """
    查询指定地址的 Transfer 事件。

    direction="sent":     topic[1] = address（作为发送方）
    direction="received": topic[2] = address（作为接收方）

    返回原始 log 列表，每条包含：
      blockNumber, timeStamp, transactionHash, topics, data
    """
    addr_topic = addr_to_topic(address)

    params = {
        "module": "logs",
        "action": "getLogs",
        "address": token_contract,
        "topic0": TRANSFER_TOPIC,
        "fromBlock": from_block,
        "toBlock": to_block,
    }

    if direction == "sent":
        params["topic1"] = addr_topic
        params["topic0_1_opr"] = "and"
    elif direction == "received":
        params["topic2"] = addr_topic
        params["topic0_2_opr"] = "and"

    data = etherscan_get(params)
    result = data.get("result", [])
    if not isinstance(result, list):
        return []
    return result


def parse_transfer_log(log: dict, token_symbol: str) -> dict:
    """将原始 log 解析为结构化的 Transfer 记录"""
    topics = log.get("topics", [])
    if len(topics) < 3:
        return {}

    # 解析金额（data 字段，hex 编码的 uint256）
    raw_data = log.get("data", "0x0")
    try:
        amount_raw = int(raw_data, 16)
    except (ValueError, TypeError):
        amount_raw = 0

    # USDT 和 USDC 都是 6 位小数
    amount = amount_raw / 1e6

    # 时间戳
    ts_hex = log.get("timeStamp", "0x0")
    try:
        timestamp = int(ts_hex, 16)
    except (ValueError, TypeError):
        timestamp = 0

    block_hex = log.get("blockNumber", "0x0")
    try:
        block = int(block_hex, 16)
    except (ValueError, TypeError):
        block = 0

    return {
        "tx_hash": log.get("transactionHash", ""),
        "block": block,
        "timestamp": timestamp,
        "from": ("0x" + topics[1][-40:]).lower(),
        "to": ("0x" + topics[2][-40:]).lower(),
        "amount": amount,
        "amount_raw": str(amount_raw),
        "token": token_symbol,
    }


# ==================== 单个地址完整抓取 ====================

def fetch_all_transfers_for_address(address: str) -> dict:
    """
    抓取一个地址在所有稳定币上的完整 Transfer 记录。
    返回 {
        "address": "0x...",
        "fetch_time": "2026-...",
        "transfers_sent": [...],
        "transfers_received": [...],
        "stats": {"total_sent": N, "total_received": N, ...}
    }
    """
    addr = address.lower().strip()
    all_sent = []
    all_received = []

    for contract, symbol in STABLECOIN_CONTRACTS.items():
        # 发送方向（topic[1] = address）
        time.sleep(REQUEST_DELAY)
        sent_logs = fetch_transfer_logs(contract, addr, "sent")
        for log in sent_logs:
            parsed = parse_transfer_log(log, symbol)
            if parsed:
                all_sent.append(parsed)

        # 接收方向（topic[2] = address）
        time.sleep(REQUEST_DELAY)
        recv_logs = fetch_transfer_logs(contract, addr, "received")
        for log in recv_logs:
            parsed = parse_transfer_log(log, symbol)
            if parsed:
                all_received.append(parsed)

    # 按时间排序
    all_sent.sort(key=lambda x: x["timestamp"])
    all_received.sort(key=lambda x: x["timestamp"])

    # 基础统计
    total_sent_amount = sum(t["amount"] for t in all_sent)
    total_recv_amount = sum(t["amount"] for t in all_received)

    return {
        "address": addr,
        "fetch_time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "transfers_sent": all_sent,
        "transfers_received": all_received,
        "stats": {
            "sent_count": len(all_sent),
            "received_count": len(all_received),
            "total_count": len(all_sent) + len(all_received),
            "sent_amount_usd": round(total_sent_amount, 2),
            "received_amount_usd": round(total_recv_amount, 2),
        },
    }


# ==================== 批量处理 ====================

def load_labels(label_filter: str = None) -> List[dict]:
    """加载标注地址列表"""
    if not os.path.exists(LABELS_CSV):
        print(f"[ERROR] 未找到 {LABELS_CSV}，请先运行 collect_labels.py")
        sys.exit(1)

    rows = []
    with open(LABELS_CSV, newline="") as f:
        for row in csv.DictReader(f):
            if label_filter and row["label"] != label_filter:
                continue
            # 目前只处理 Ethereum 地址（Tron 需要不同的 API）
            if row["chain"] != "ethereum":
                continue
            rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description="抓取标注地址的 Transfer 事件")
    parser.add_argument("--limit", type=int, default=0,
                        help="只处理前 N 个地址 (0=全部)")
    parser.add_argument("--skip-existing", action="store_true",
                        help="跳过已有 JSON 的地址")
    parser.add_argument("--label", type=str, default=None,
                        help="只处理特定标签 (blocklisted/sanctioned/normal)")
    args = parser.parse_args()

    os.makedirs(TRANSFERS_DIR, exist_ok=True)

    addresses = load_labels(label_filter=args.label)
    if args.limit > 0:
        addresses = addresses[:args.limit]

    print(f"[Transfer] 待处理地址: {len(addresses)}")
    skipped = 0
    processed = 0
    errors = 0

    for i, row in enumerate(addresses):
        addr = row["address"]
        label = row["label"]
        out_file = os.path.join(TRANSFERS_DIR, f"{addr}.json")

        # 跳过已有
        if args.skip_existing and os.path.exists(out_file):
            skipped += 1
            continue

        print(f"\n[{i+1}/{len(addresses)}] {addr[:18]}... ({label})")

        try:
            result = fetch_all_transfers_for_address(addr)
            result["label"] = label
            result["source"] = row.get("source", "")

            with open(out_file, "w") as f:
                json.dump(result, f, indent=2)

            stats = result["stats"]
            print(f"  sent={stats['sent_count']}  recv={stats['received_count']}  "
                  f"total_usd=${stats['sent_amount_usd'] + stats['received_amount_usd']:,.0f}")
            processed += 1

        except Exception as e:
            print(f"  [ERROR] {e}")
            errors += 1

        # 进度提醒
        if (i + 1) % 20 == 0:
            print(f"\n--- 进度: {i+1}/{len(addresses)} "
                  f"(处理={processed} 跳过={skipped} 错误={errors}) ---\n")

    print(f"\n[完成] 处理={processed}  跳过={skipped}  错误={errors}")
    print(f"  数据保存在: {TRANSFERS_DIR}/")


if __name__ == "__main__":
    main()
