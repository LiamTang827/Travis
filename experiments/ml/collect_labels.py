#!/usr/bin/env python3
"""
标注地址收集器 — ML 数据准备第一步
===================================

三类标注地址：
  - blocklisted : Tether 冻结地址（usdt_blacklist.csv）
  - sanctioned  : OFAC SDN 制裁名单（自动下载）
  - normal      : 从最近 USDT Transfer 事件中采样的活跃地址（排除已知实体）

输出：experiments/ml/data/labeled_addresses.csv
  列：address, chain, label, source

用法：
  python experiments/ml/collect_labels.py
  python experiments/ml/collect_labels.py --normal-sample 500 --ofac
"""

import os
import sys
import csv
import time
import json
import random
import argparse
import requests
from pathlib import Path
from typing import Dict, Set, List, Tuple
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "src"

# 加载项目根目录的 .env
load_dotenv(PROJECT_ROOT / ".env")

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
REQUEST_DELAY = 0.25

# ==================== 路径 ====================
BLACKLIST_CSV = PROJECT_ROOT / "data" / "blacklists" / "usdt_blacklist.csv"
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "data")
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "labeled_addresses.csv")

# ==================== 已知合约地址（排除用）====================
# 从 aml_analyzer.py 导入，避免重复定义
sys.path.insert(0, str(SRC_DIR))
from cripto_analyst.aml_analyzer import (
    BRIDGE_REGISTRY, ALL_BRIDGE_ADDRS, MIXER_CONTRACTS,
    HIGH_RISK_EXCHANGES, normalize,
)

# USDT/USDC 合约地址（Ethereum）
USDT_CONTRACT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
USDC_CONTRACT = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"

# ERC-20 Transfer 事件签名
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# 需要排除的地址（协议合约、桥、混币器等）
EXCLUDE_ADDRS: Set[str] = (
    ALL_BRIDGE_ADDRS
    | set(MIXER_CONTRACTS)
    | set(HIGH_RISK_EXCHANGES)
    | {
        USDT_CONTRACT,
        USDC_CONTRACT,
        "0x0000000000000000000000000000000000000000",
    }
)


# ==================== Etherscan getLogs ====================

def etherscan_get(params: dict) -> dict:
    """带重试的 Etherscan V2 API 请求"""
    params["apikey"] = ETHERSCAN_API_KEY
    params["chainid"] = 1  # Ethereum mainnet
    for attempt in range(3):
        try:
            r = requests.get("https://api.etherscan.io/v2/api",
                             params=params, timeout=15)
            data = r.json()
            # V2 getLogs 返回 {"status":"1", "result": [...]}
            # V2 proxy 返回 {"jsonrpc":"2.0", "result": "0x..."}
            if (data.get("status") == "1"
                    or isinstance(data.get("result"), list)
                    or data.get("jsonrpc")):
                return data
            # 速率限制时等久一点
            if "rate limit" in str(data.get("result", "")).lower():
                time.sleep(1.5)
                continue
        except Exception as e:
            print(f"  [WARN] 请求失败 (attempt {attempt+1}): {e}")
        time.sleep(0.5)
    return {}


# ==================== 1. 加载黑名单地址 ====================

def load_blacklisted() -> List[dict]:
    """从 usdt_blacklist.csv 加载 Tether 冻结地址"""
    rows = []
    with open(BLACKLIST_CSV, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                "address": normalize(row["address"]),
                "chain": row.get("chain", "ethereum"),
                "label": "blocklisted",
                "source": "tether_freeze",
            })
    print(f"[标注] 黑名单地址: {len(rows)} 条")
    return rows


# ==================== 2. OFAC SDN 制裁名单 ====================

OFAC_SDN_URL = "https://www.treasury.gov/ofac/downloads/sdn.csv"
# OFAC 专门的数字货币地址列表（更精准）
OFAC_CRYPTO_URL = "https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml"

def load_ofac_addresses() -> List[dict]:
    """
    从 OFAC SDN CSV 中提取加密货币地址。
    SDN CSV 格式比较复杂，加密地址出现在 "Remarks" 列中，
    格式如：Digital Currency Address - ETH 0x1234...
    """
    print("[标注] 正在下载 OFAC SDN 数据...")
    rows = []

    try:
        r = requests.get(OFAC_SDN_URL, timeout=30)
        r.raise_for_status()
        lines = r.text.splitlines()
    except Exception as e:
        print(f"  [WARN] OFAC 下载失败: {e}")
        print("  [INFO] 改用本地备份 OFAC 列表（如有）")
        ofac_local = os.path.join(OUTPUT_DIR, "ofac_addresses.json")
        if os.path.exists(ofac_local):
            with open(ofac_local) as f:
                return json.load(f)
        return []

    # 解析 SDN CSV — 加密地址在各行的文本中
    # 格式不固定，用正则提取 0x 开头的 40 位 hex 地址
    import re
    eth_pattern = re.compile(r'0x[0-9a-fA-F]{40}')

    seen = set()
    for line in lines:
        matches = eth_pattern.findall(line)
        for addr in matches:
            addr_norm = normalize(addr)
            if addr_norm not in seen:
                seen.add(addr_norm)
                # 判断链类型（OFAC 列表中 ETH 和 TRON 地址都有）
                chain = "ethereum"  # 0x 地址默认 ethereum
                rows.append({
                    "address": addr_norm,
                    "chain": chain,
                    "label": "sanctioned",
                    "source": "ofac_sdn",
                })

    print(f"[标注] OFAC 制裁地址: {len(rows)} 条")

    # 缓存到本地
    ofac_local = os.path.join(OUTPUT_DIR, "ofac_addresses.json")
    with open(ofac_local, "w") as f:
        json.dump(rows, f, indent=2)

    return rows


# ==================== 3. 采样正常地址 ====================

def sample_normal_addresses(target_count: int = 300,
                            known_addrs: Set[str] = None) -> List[dict]:
    """
    从最近的 USDT Transfer 事件中采样活跃地址作为 "normal" 类。

    策略：
      1. 获取最新区块号
      2. 在最近 10000 个区块内，随机采样几段区块，拉 USDT Transfer logs
      3. 从 from/to 中提取地址，排除已知实体（桥、混币器、黑名单、合约）
      4. 随机选 target_count 个
    """
    if known_addrs is None:
        known_addrs = set()

    print(f"[标注] 采样正常地址 (目标: {target_count})...")

    # 获取最新区块号
    data = etherscan_get({
        "module": "proxy", "action": "eth_blockNumber",
    })
    latest_block = int(data.get("result", "0x0"), 16)
    if latest_block == 0:
        print("  [ERROR] 无法获取最新区块号")
        return []
    print(f"  最新区块: {latest_block}")

    # 在最近 50000 个区块内随机采样多段
    candidate_addrs: Set[str] = set()
    sample_ranges = []

    # 生成 10 个随机起点，每段查 200 个区块
    for _ in range(15):
        start = random.randint(latest_block - 50000, latest_block - 200)
        sample_ranges.append((start, start + 200))

    for from_blk, to_blk in sample_ranges:
        if len(candidate_addrs) >= target_count * 3:
            break

        time.sleep(REQUEST_DELAY)
        data = etherscan_get({
            "module": "logs", "action": "getLogs",
            "address": USDT_CONTRACT,
            "topic0": TRANSFER_TOPIC,
            "fromBlock": from_blk,
            "toBlock": to_blk,
        })

        logs = data.get("result", [])
        if not isinstance(logs, list):
            continue

        for log in logs:
            topics = log.get("topics", [])
            if len(topics) < 3:
                continue
            addr_from = normalize("0x" + topics[1][-40:])
            addr_to = normalize("0x" + topics[2][-40:])

            for addr in [addr_from, addr_to]:
                if (addr not in EXCLUDE_ADDRS
                        and addr not in known_addrs
                        and not addr.startswith("0x000000000000000000")):
                    candidate_addrs.add(addr)

        print(f"  区块 {from_blk}-{to_blk}: "
              f"获取 {len(logs)} 条 Transfer, 累计候选 {len(candidate_addrs)}")

    # 随机采样
    candidates = list(candidate_addrs)
    random.shuffle(candidates)
    selected = candidates[:target_count]

    rows = [{
        "address": addr,
        "chain": "ethereum",
        "label": "normal",
        "source": "usdt_transfer_sample",
    } for addr in selected]

    print(f"[标注] 正常地址采样完成: {len(rows)} 条")
    return rows


# ==================== 4. 合并去重 + 输出 ====================

def merge_and_save(all_rows: List[dict]):
    """合并所有标注，按 address 去重（优先保留 blocklisted > sanctioned > normal）"""
    # 优先级：blocklisted > sanctioned > normal
    priority = {"blocklisted": 0, "sanctioned": 1, "normal": 2}

    best: Dict[str, dict] = {}
    for row in all_rows:
        addr = row["address"]
        if addr not in best or priority[row["label"]] < priority[best[addr]["label"]]:
            best[addr] = row

    final = sorted(best.values(), key=lambda x: (priority[x["label"]], x["address"]))

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["address", "chain", "label", "source"])
        writer.writeheader()
        writer.writerows(final)

    # 统计
    counts = {}
    for row in final:
        counts[row["label"]] = counts.get(row["label"], 0) + 1

    print(f"\n[完成] 输出到 {OUTPUT_CSV}")
    print(f"  总计: {len(final)} 个地址")
    for label, count in sorted(counts.items()):
        print(f"    {label}: {count}")


# ==================== CLI ====================

def main():
    parser = argparse.ArgumentParser(description="收集 ML 训练用标注地址")
    parser.add_argument("--normal-sample", type=int, default=300,
                        help="采样正常地址数量 (默认 300)")
    parser.add_argument("--ofac", action="store_true",
                        help="是否下载 OFAC SDN 制裁名单")
    parser.add_argument("--skip-normal", action="store_true",
                        help="跳过正常地址采样（仅输出黑名单/制裁）")
    args = parser.parse_args()

    all_rows = []

    # 1. 黑名单
    blacklisted = load_blacklisted()
    all_rows.extend(blacklisted)
    known_addrs = {r["address"] for r in blacklisted}

    # 2. OFAC（可选）
    if args.ofac:
        sanctioned = load_ofac_addresses()
        all_rows.extend(sanctioned)
        known_addrs.update(r["address"] for r in sanctioned)

    # 3. 正常地址采样
    if not args.skip_normal:
        normal = sample_normal_addresses(
            target_count=args.normal_sample,
            known_addrs=known_addrs,
        )
        all_rows.extend(normal)

    # 4. 合并输出
    merge_and_save(all_rows)


if __name__ == "__main__":
    main()
