#!/usr/bin/env python3
"""
从黑名单地址的交易记录里，自动挖出"用过跨链桥的关联地址"作为测试案例
逻辑：黑名单地址 → 找其交易对手 → 检测对手是否与跨链桥合约交互
"""

import os
import csv
import time
import json
import requests
from pathlib import Path
from typing import Set, Dict, List
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
BLACKLIST_CSV = PROJECT_ROOT / "data" / "blacklists" / "usdt_blacklist.csv"
OUTPUT_FILE = PROJECT_ROOT / "data" / "test_cases" / "test_cases.json"
SAMPLE_SIZE = 30     # 取多少个黑名单地址来挖（ETH链）
DELAY = 0.3

# 主流跨链桥合约（Ethereum）
BRIDGE_CONTRACTS = {
    "0x8731d54e9d02c286767d56ac03e8037c07e01e98": "Stargate Finance",
    "0x3e4a3a4796d16c0cd582c382691998f7c06420b6": "Hop Protocol USDT",
    "0x5427fefa711eff984124bfbb1ab6fbf5e3da1820": "Celer cBridge",
    "0x4d9079bb4165aeb4084c526a32695dcfd2f77381": "Across Protocol",
    "0x2796317b0ff8538f253012862c06787adfb8ceb": "Synapse Bridge",
    "0x3ee18b2214aff97000d974cf647e7c347e8fa585": "Wormhole",
    "0xc564ee9f21ed8a2d8e7e76c085740d5e4c5fafbe": "Multichain",
    "0x80c67432656d59144ceff962e8faf8926599bcf8": "Orbiter Finance",
    "0x66a71dcef29a0ffbdbe3c6a460a3b5bc225cd675": "LayerZero v1",
    "0x1a44076050125825900e736c501f859c50fe728c": "LayerZero v2",
    "0xa0c68c638235ee32657e8f720a23cec1bfc77c77": "Polygon Bridge",
    "0x40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf": "Polygon ERC20",
    "0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a": "Arbitrum Bridge",
    "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1": "Optimism Gateway",
    "0x43de2d77bf8027e25dbd179b491e8d64f38398aa": "deBridge",
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado Cash 0.1ETH",
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado Cash 1ETH",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash 10ETH",
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": "Tornado Cash 100ETH",
}


def load_eth_blacklist(path: str, limit: int) -> List[Dict]:
    rows = []
    with open(path) as f:
        for row in csv.DictReader(f):
            if row["chain"] == "ethereum":
                rows.append(row)
                if len(rows) >= limit:
                    break
    return rows


def etherscan_get(params: dict) -> list:
    params["apikey"] = ETHERSCAN_API_KEY
    try:
        r = requests.get("https://api.etherscan.io/api", params=params, timeout=15)
        data = r.json()
        result = data.get("result", [])
        return result if isinstance(result, list) else []
    except Exception as e:
        print(f"    [WARN] {e}")
        return []


def get_counterparties(address: str) -> Set[str]:
    """获取地址的所有交易对手"""
    addr_lower = address.lower()
    cps = set()

    for action in ["txlist", "tokentx"]:
        time.sleep(DELAY)
        txs = etherscan_get({
            "module": "account", "action": action,
            "address": address, "sort": "desc", "offset": 50, "page": 1,
        })
        for tx in txs:
            f = (tx.get("from") or "").lower()
            t = (tx.get("to") or tx.get("contractAddress") or "").lower()
            other = t if f == addr_lower else f
            if other and other != addr_lower:
                cps.add(other)
    return cps


def check_bridge_usage(address: str) -> List[Dict]:
    """检测一个地址是否用过跨链桥"""
    addr_lower = address.lower()
    hits = []

    for action in ["txlist", "tokentx"]:
        time.sleep(DELAY)
        txs = etherscan_get({
            "module": "account", "action": action,
            "address": address, "sort": "desc", "offset": 100, "page": 1,
        })
        for tx in txs:
            to = (tx.get("to") or "").lower()
            f  = (tx.get("from") or "").lower()
            if to in BRIDGE_CONTRACTS:
                hits.append({
                    "bridge": BRIDGE_CONTRACTS[to],
                    "contract": to,
                    "direction": "OUT" if f == addr_lower else "IN",
                    "token": tx.get("tokenSymbol", "ETH"),
                    "tx": tx.get("hash", ""),
                    "time": tx.get("timeStamp", ""),
                })
    return hits


def main():
    print(f"[*] 加载 Ethereum 黑名单地址（取前 {SAMPLE_SIZE} 个）...")
    bl_sample = load_eth_blacklist(BLACKLIST_CSV, SAMPLE_SIZE)
    bl_all_addrs = set()
    with open(BLACKLIST_CSV) as f:
        for row in csv.DictReader(f):
            bl_all_addrs.add(row["address"].lower())

    print(f"[*] 黑名单总量: {len(bl_all_addrs)}，本次分析样本: {len(bl_sample)} 个\n")

    test_cases = []
    seen_addresses = set()  # 避免重复

    for i, bl_row in enumerate(bl_sample, 1):
        bl_addr = bl_row["address"].lower()
        print(f"[{i:02d}/{SAMPLE_SIZE}] 黑名单地址: {bl_addr[:20]}...  封禁: {bl_row['time'][:10]}")

        # Step 1: 找交易对手
        print(f"         → 查询交易对手...")
        cps = get_counterparties(bl_addr)
        print(f"         → 发现 {len(cps)} 个对手方")

        # Step 2: 对每个对手方检测桥使用
        for cp in list(cps)[:8]:  # 每个黑名单地址最多查8个对手方
            if cp in seen_addresses or cp in bl_all_addrs:
                continue
            seen_addresses.add(cp)

            print(f"         → 检测对手方桥使用: {cp[:20]}...")
            bridge_hits = check_bridge_usage(cp)

            if bridge_hits:
                case = {
                    "test_address": cp,
                    "connected_blacklist": bl_addr,
                    "blacklist_time": bl_row["time"],
                    "bridge_usage": bridge_hits,
                    "bridge_names": list({h["bridge"] for h in bridge_hits}),
                    "expected_risk": "HIGH",
                    "reason": f"与黑名单地址直接交易，且使用了跨链桥: {', '.join({h['bridge'] for h in bridge_hits})}",
                }
                test_cases.append(case)
                print(f"         [!!!] 发现测试案例: 用了 {case['bridge_names']}")

        print()

    # 保存结果
    with open(OUTPUT_FILE, "w") as f:
        json.dump(test_cases, f, ensure_ascii=False, indent=2)

    print(f"\n{'='*60}")
    print(f"挖掘完成，共发现 {len(test_cases)} 个测试案例")
    print(f"已保存到: {OUTPUT_FILE}")
    print(f"{'='*60}\n")

    if test_cases:
        print("前5个测试案例预览：\n")
        for i, case in enumerate(test_cases[:5], 1):
            print(f"  [{i}] {case['test_address']}")
            print(f"       关联黑名单: {case['connected_blacklist'][:20]}...")
            print(f"       使用的桥:   {', '.join(case['bridge_names'])}")
            print(f"       预期风险:   {case['expected_risk']}")
            print()

        print("用法示例 — 用 aml_analyzer.py 验证这些案例：")
        for case in test_cases[:3]:
            print(f"  .venv/bin/python aml_analyzer.py {case['test_address']} --chain ethereum --no-hop2")
    else:
        print("本批次未发现桥使用案例，可尝试增大 SAMPLE_SIZE 重新运行")


if __name__ == "__main__":
    main()
