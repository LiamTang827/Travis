#!/usr/bin/env python3
"""
行为特征工程 — ML 数据准备第三步
==================================

从 experiments/ml/data/transfers/{address}.json 中提取 4 类行为特征，
参考 StableAML 论文（arXiv 2602.17842）的特征框架。

4 类特征：
  1. Interaction Features   — 和什么类型的实体交互过（混币器/桥/CEX/标记地址）
  2. Transfer Features      — 金额分布模式（大额转账、重复金额、单一来源/去向）
  3. Derived Network Features — 对手方的二度特征（对手方是否和混币器交互等）
  4. Temporal Features       — 时间模式（爆发活动、高频、快速往返）

输入：experiments/ml/data/transfers/*.json
输出：experiments/ml/data/feature_matrix.csv

用法：
  python experiments/ml/feature_engineer.py
  python experiments/ml/feature_engineer.py --output experiments/ml/data/my_features.csv
"""

import os
import sys
import csv
import json
import math
import argparse
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import Counter, defaultdict

# 导入项目已有的已知实体地址
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
from cripto_analyst.aml_analyzer import (
    BRIDGE_REGISTRY, ALL_BRIDGE_ADDRS, OPAQUE_BRIDGE_ADDRS,
    MIXER_CONTRACTS, HIGH_RISK_EXCHANGES, normalize,
)

# ==================== 路径 ====================
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
TRANSFERS_DIR = os.path.join(DATA_DIR, "transfers")
OUTPUT_CSV = os.path.join(DATA_DIR, "feature_matrix.csv")

# ==================== 已知实体分类 ====================
# 透明桥地址
TRANSPARENT_BRIDGE_ADDRS: Set[str] = {
    a for a, v in BRIDGE_REGISTRY.items() if v["traceable"]
}

# 已知 CEX 热钱包（样本，可后续扩展）
KNOWN_CEX_ADDRS: Set[str] = {
    normalize(a) for a in [
        "0x28c6c06298d514db089934071355e5743bf21d60",  # Binance 14
        "0x21a31ee1afc51d94c2efccaa2092ad1028285549",  # Binance 15
        "0xdfd5293d8e347dfe59e90efd55b2956a1343963d",  # Binance 16
        "0x56eddb7aa87536c09ccc2793473599fd21a8b17f",  # Binance 17
        "0x9696f59e4d72e237be84ffd425dcad154bf96976",  # Binance 18
        "0xf977814e90da44bfa03b6295a0616a897441acec",  # Binance 8
        "0x974caa59e49682cda0ad2bbe82983419a2ecc400",  # Coinbase Commerce
        "0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43",  # Coinbase 10
        "0x503828976d22510aad0201ac7ec88293211d23da",  # Coinbase 2
        "0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740",  # Coinbase 3
        "0x3cd751e6b0078be393132286c442345e68ff0bb0",  # Coinbase 4
        "0xb5d85cbf7cb3ee0d56b3bb207d5fc4b82f43f511",  # Coinbase 5
        "0xeb2629a2734e272bcc07bda959863f316f4bd4cf",  # Coinbase 6
        "0x02466e547bfdab679fc49e96bbfc62b9747d997c",  # Huobi 10
        "0xd24400ae8bfebb18ca49be86258a3c749cf46853",  # Gemini
    ]
}

# DEX Router（排除用，不算有意义的对手方）
KNOWN_DEX_ADDRS: Set[str] = {
    normalize(a) for a in [
        "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",  # Uniswap V2 Router
        "0xe592427a0aece92de3edee1f18e0157c05861564",  # Uniswap V3 Router
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",  # Uniswap Universal Router
        "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b",  # Uniswap Universal Router 2
        "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad",  # Uniswap Universal Router 3
        "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f",  # SushiSwap Router
        "0x1111111254eeb25477b68fb85ed929f73a960582",  # 1inch v5
        "0x1111111254fb6c44bac0bed2854e76f90643097d",  # 1inch v4
        "0xdef1c0ded9bec7f1a1670819833240f027b25eff",  # 0x Exchange Proxy
        "0x881d40237659c251811cec9c364ef91dc08d300c",  # MetaMask Swap Router
    ]
}

# 合并所有 flagged 地址（黑名单在运行时从 labeled_addresses.csv 加载）
FLAGGED_ADDRS: Set[str] = set()

# 零地址和已知协议合约
PROTOCOL_ADDRS: Set[str] = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7",  # USDT
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC
    "0x0000000000000000000000000000000000000000",
}


# ==================== 加载 flagged 地址 ====================

def load_flagged_addresses():
    """从 labeled_addresses.csv 加载所有 blocklisted/sanctioned 地址"""
    global FLAGGED_ADDRS
    labels_csv = os.path.join(DATA_DIR, "labeled_addresses.csv")
    if not os.path.exists(labels_csv):
        return
    with open(labels_csv, newline="") as f:
        for row in csv.DictReader(f):
            if row["label"] in ("blocklisted", "sanctioned"):
                FLAGGED_ADDRS.add(normalize(row["address"]))
    print(f"[特征] 已加载 {len(FLAGGED_ADDRS)} 个 flagged 地址")


# ==================== 特征提取函数 ====================

def extract_features(data: dict) -> dict:
    """
    从一个地址的 Transfer 数据中提取所有行为特征。

    data 格式：fetch_transfers.py 输出的 JSON
    返回：{feature_name: value} 字典
    """
    addr = data["address"]
    sent = data.get("transfers_sent", [])
    received = data.get("transfers_received", [])
    all_transfers = sent + received

    features = {}

    # ========== 1. Interaction Features (和什么类型实体交互) ==========

    # 统计各类实体交互
    sent_to_mixer = 0
    received_from_mixer = 0
    sent_to_opaque_bridge = 0
    received_from_opaque_bridge = 0
    sent_to_transparent_bridge = 0
    received_from_transparent_bridge = 0
    sent_to_cex = 0
    received_from_cex = 0
    sent_to_dex = 0
    received_from_dex = 0
    sent_to_flagged = 0
    received_from_flagged = 0
    sent_to_high_risk_exchange = 0
    received_from_high_risk_exchange = 0

    for tx in sent:
        to = normalize(tx.get("to", ""))
        if to in MIXER_CONTRACTS:
            sent_to_mixer += 1
        if to in OPAQUE_BRIDGE_ADDRS:
            sent_to_opaque_bridge += 1
        if to in TRANSPARENT_BRIDGE_ADDRS:
            sent_to_transparent_bridge += 1
        if to in KNOWN_CEX_ADDRS:
            sent_to_cex += 1
        if to in KNOWN_DEX_ADDRS:
            sent_to_dex += 1
        if to in FLAGGED_ADDRS:
            sent_to_flagged += 1
        if to in HIGH_RISK_EXCHANGES:
            sent_to_high_risk_exchange += 1

    for tx in received:
        frm = normalize(tx.get("from", ""))
        if frm in MIXER_CONTRACTS:
            received_from_mixer += 1
        if frm in OPAQUE_BRIDGE_ADDRS:
            received_from_opaque_bridge += 1
        if frm in TRANSPARENT_BRIDGE_ADDRS:
            received_from_transparent_bridge += 1
        if frm in KNOWN_CEX_ADDRS:
            received_from_cex += 1
        if frm in KNOWN_DEX_ADDRS:
            received_from_dex += 1
        if frm in FLAGGED_ADDRS:
            received_from_flagged += 1
        if frm in HIGH_RISK_EXCHANGES:
            received_from_high_risk_exchange += 1

    features["sent_to_mixer"] = sent_to_mixer
    features["received_from_mixer"] = received_from_mixer
    features["sent_to_opaque_bridge"] = sent_to_opaque_bridge
    features["received_from_opaque_bridge"] = received_from_opaque_bridge
    features["sent_to_transparent_bridge"] = sent_to_transparent_bridge
    features["received_from_transparent_bridge"] = received_from_transparent_bridge
    features["sent_to_cex"] = sent_to_cex
    features["received_from_cex"] = received_from_cex
    features["sent_to_dex"] = sent_to_dex
    features["received_from_dex"] = received_from_dex
    features["sent_to_flagged"] = sent_to_flagged
    features["received_from_flagged"] = received_from_flagged
    features["sent_to_high_risk_exchange"] = sent_to_high_risk_exchange
    features["received_from_high_risk_exchange"] = received_from_high_risk_exchange

    # 布尔特征（是否有过此类交互）
    features["has_mixer_interaction"] = int(sent_to_mixer > 0 or received_from_mixer > 0)
    features["has_bridge_interaction"] = int(
        sent_to_opaque_bridge > 0 or received_from_opaque_bridge > 0
        or sent_to_transparent_bridge > 0 or received_from_transparent_bridge > 0
    )
    features["has_flagged_interaction"] = int(sent_to_flagged > 0 or received_from_flagged > 0)
    features["has_cex_interaction"] = int(sent_to_cex > 0 or received_from_cex > 0)

    # ========== 2. Transfer Features (金额分布模式) ==========

    sent_amounts = [tx["amount"] for tx in sent if tx["amount"] > 0]
    recv_amounts = [tx["amount"] for tx in received if tx["amount"] > 0]
    all_amounts = sent_amounts + recv_amounts

    # 金额阈值特征
    features["transfers_over_1k"] = sum(1 for a in all_amounts if a >= 1000)
    features["transfers_over_5k"] = sum(1 for a in all_amounts if a >= 5000)
    features["transfers_over_10k"] = sum(1 for a in all_amounts if a >= 10000)
    features["transfers_over_50k"] = sum(1 for a in all_amounts if a >= 50000)
    features["transfers_over_100k"] = sum(1 for a in all_amounts if a >= 100000)

    # 金额统计
    features["total_sent_amount"] = sum(sent_amounts) if sent_amounts else 0
    features["total_received_amount"] = sum(recv_amounts) if recv_amounts else 0
    features["sent_count"] = len(sent)
    features["received_count"] = len(received)
    features["total_count"] = len(all_transfers)

    # 流入/流出比 — 正常用户接近1，洗钱中转接近1但金额大
    total_in = features["total_received_amount"]
    total_out = features["total_sent_amount"]
    features["in_out_ratio"] = (total_in / total_out) if total_out > 0 else (999 if total_in > 0 else 0)

    # 余额清空率：发送总额 / 接收总额（接近1 = 几乎把收到的钱全转走了）
    features["drain_ratio"] = (total_out / total_in) if total_in > 0 else (999 if total_out > 0 else 0)

    # 金额统计量
    if all_amounts:
        features["avg_amount"] = sum(all_amounts) / len(all_amounts)
        features["max_amount"] = max(all_amounts)
        features["min_amount"] = min(all_amounts)
        features["median_amount"] = sorted(all_amounts)[len(all_amounts) // 2]
        # 金额标准差
        mean = features["avg_amount"]
        features["std_amount"] = math.sqrt(
            sum((a - mean) ** 2 for a in all_amounts) / len(all_amounts)
        )
    else:
        features["avg_amount"] = 0
        features["max_amount"] = 0
        features["min_amount"] = 0
        features["median_amount"] = 0
        features["std_amount"] = 0

    # 重复相同金额的转账次数（peeling chain 信号）
    if all_amounts:
        amount_counts = Counter(round(a, 2) for a in all_amounts)
        # 有多少个不同金额出现了 >=2 次
        features["repeated_same_amount_groups"] = sum(1 for c in amount_counts.values() if c >= 2)
        # 重复金额占总转账的比例
        repeated_count = sum(c for c in amount_counts.values() if c >= 2)
        features["repeated_amount_ratio"] = repeated_count / len(all_amounts)
    else:
        features["repeated_same_amount_groups"] = 0
        features["repeated_amount_ratio"] = 0

    # 单一来源/单一去向
    unique_senders = set(normalize(tx.get("from", "")) for tx in received) - PROTOCOL_ADDRS
    unique_receivers = set(normalize(tx.get("to", "")) for tx in sent) - PROTOCOL_ADDRS
    features["unique_senders"] = len(unique_senders)
    features["unique_receivers"] = len(unique_receivers)
    features["is_single_source"] = int(len(unique_senders) == 1 and len(received) > 0)
    features["is_single_dest"] = int(len(unique_receivers) == 1 and len(sent) > 0)

    # ========== 3. Derived Network Features (网络拓扑) ==========

    # 入度/出度
    features["in_degree"] = len(unique_senders)
    features["out_degree"] = len(unique_receivers)
    total_degree = features["in_degree"] + features["out_degree"]
    features["in_out_degree_ratio"] = (
        features["in_degree"] / features["out_degree"]
        if features["out_degree"] > 0
        else (999 if features["in_degree"] > 0 else 0)
    )

    # 对手方中属于各类实体的比例
    all_counterparties = unique_senders | unique_receivers
    if all_counterparties:
        features["counterparty_flagged_ratio"] = len(all_counterparties & FLAGGED_ADDRS) / len(all_counterparties)
        features["counterparty_mixer_ratio"] = len(all_counterparties & set(MIXER_CONTRACTS)) / len(all_counterparties)
        features["counterparty_bridge_ratio"] = len(all_counterparties & ALL_BRIDGE_ADDRS) / len(all_counterparties)
        features["counterparty_cex_ratio"] = len(all_counterparties & KNOWN_CEX_ADDRS) / len(all_counterparties)
    else:
        features["counterparty_flagged_ratio"] = 0
        features["counterparty_mixer_ratio"] = 0
        features["counterparty_bridge_ratio"] = 0
        features["counterparty_cex_ratio"] = 0

    features["total_unique_counterparties"] = len(all_counterparties)

    # 代理行为：是否有"收到后24小时内转出相同金额"的模式
    features["has_proxy_behavior"] = int(_detect_proxy_behavior(sent, received))

    # ========== 4. Temporal Features (时间模式) ==========

    timestamps = sorted([tx["timestamp"] for tx in all_transfers if tx["timestamp"] > 0])

    if len(timestamps) >= 2:
        # 账户活跃时间跨度（天）
        features["account_age_days"] = (timestamps[-1] - timestamps[0]) / 86400
        features["prolonged_activity"] = int(features["account_age_days"] > 90)

        # 交易间隔统计
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        features["avg_interval_seconds"] = sum(intervals) / len(intervals)
        features["min_interval_seconds"] = min(intervals)
        mean_interval = features["avg_interval_seconds"]
        features["std_interval_seconds"] = math.sqrt(
            sum((iv - mean_interval) ** 2 for iv in intervals) / len(intervals)
        )

        # 高频活动：是否有间隔 < 60秒的连续交易
        features["has_high_frequency"] = int(any(iv < 60 for iv in intervals))
        # 间隔 < 5分钟的交易对占比
        rapid_count = sum(1 for iv in intervals if iv < 300)
        features["rapid_tx_ratio"] = rapid_count / len(intervals)

        # 每日爆发：某一天的交易数是否 > 日均的 5 倍
        daily_counts = Counter()
        for ts in timestamps:
            day = ts // 86400  # 按天分桶
            daily_counts[day] += 1
        avg_daily = len(timestamps) / max(len(daily_counts), 1)
        features["max_daily_count"] = max(daily_counts.values())
        features["has_daily_burst"] = int(features["max_daily_count"] > max(avg_daily * 5, 10))

        # 快速往返：收到后 1 小时内等额转出
        features["has_rapid_reciprocal"] = int(_detect_rapid_reciprocal(sent, received))

        # 活跃时间集中度：交易是否集中在某个时段（小时）
        hours = [(ts % 86400) // 3600 for ts in timestamps]
        hour_counts = Counter(hours)
        if hour_counts:
            most_active_hour_count = max(hour_counts.values())
            features["hour_concentration"] = most_active_hour_count / len(timestamps)
        else:
            features["hour_concentration"] = 0

    else:
        features["account_age_days"] = 0
        features["prolonged_activity"] = 0
        features["avg_interval_seconds"] = 0
        features["min_interval_seconds"] = 0
        features["std_interval_seconds"] = 0
        features["has_high_frequency"] = 0
        features["rapid_tx_ratio"] = 0
        features["max_daily_count"] = len(timestamps)
        features["has_daily_burst"] = 0
        features["has_rapid_reciprocal"] = 0
        features["hour_concentration"] = 0

    return features


# ==================== 辅助检测函数 ====================

def _detect_proxy_behavior(sent: list, received: list) -> bool:
    """
    代理行为检测：是否在收到资金后 24 小时内转出相同金额（±5%）。
    这是 peeling chain 中继节点的典型特征。
    """
    if not sent or not received:
        return False

    # 对 received 按时间排序，sent 同理
    recv_sorted = sorted(received, key=lambda x: x["timestamp"])
    sent_sorted = sorted(sent, key=lambda x: x["timestamp"])

    matches = 0
    for r in recv_sorted[:50]:  # 只检查前50笔，避免 O(n^2) 太慢
        r_amount = r["amount"]
        r_time = r["timestamp"]
        if r_amount <= 0:
            continue
        for s in sent_sorted:
            s_time = s["timestamp"]
            # 只看接收后 24 小时内
            if s_time < r_time:
                continue
            if s_time > r_time + 86400:
                break
            # 金额匹配（±5%）
            if abs(s["amount"] - r_amount) / r_amount < 0.05:
                matches += 1
                break

    return matches >= 2  # 至少有 2 次代理行为


def _detect_rapid_reciprocal(sent: list, received: list) -> bool:
    """
    快速往返检测：收到资金后 1 小时内向同一地址发送资金。
    """
    if not sent or not received:
        return False

    recv_by_addr = defaultdict(list)
    for r in received:
        recv_by_addr[normalize(r.get("from", ""))].append(r["timestamp"])

    for s in sent:
        to = normalize(s.get("to", ""))
        s_time = s["timestamp"]
        if to in recv_by_addr:
            for r_time in recv_by_addr[to]:
                if 0 < s_time - r_time < 3600:
                    return True
    return False


# ==================== 主流程 ====================

def main():
    parser = argparse.ArgumentParser(description="从 Transfer 事件提取行为特征")
    parser.add_argument("--output", type=str, default=OUTPUT_CSV,
                        help=f"输出 CSV 路径 (默认: {OUTPUT_CSV})")
    args = parser.parse_args()

    load_flagged_addresses()

    # 扫描所有 transfer JSON 文件
    if not os.path.exists(TRANSFERS_DIR):
        print(f"[ERROR] 未找到 {TRANSFERS_DIR}，请先运行 fetch_transfers.py")
        sys.exit(1)

    json_files = [f for f in os.listdir(TRANSFERS_DIR) if f.endswith(".json")]
    print(f"[特征] 发现 {len(json_files)} 个地址的 Transfer 数据")

    all_rows = []
    feature_names = None

    for i, fname in enumerate(sorted(json_files)):
        filepath = os.path.join(TRANSFERS_DIR, fname)
        with open(filepath) as f:
            data = json.load(f)

        features = extract_features(data)

        # 加上元数据列
        row = {
            "address": data["address"],
            "label": data.get("label", "unknown"),
            **features,
        }
        all_rows.append(row)

        if feature_names is None:
            feature_names = list(features.keys())

        if (i + 1) % 100 == 0:
            print(f"  处理进度: {i+1}/{len(json_files)}")

    if not all_rows:
        print("[ERROR] 没有数据可处理")
        sys.exit(1)

    # 输出 CSV
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    fieldnames = ["address", "label"] + feature_names
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    # 统计
    label_counts = Counter(r["label"] for r in all_rows)
    print(f"\n[完成] 输出到 {args.output}")
    print(f"  总计: {len(all_rows)} 个地址, {len(feature_names)} 个特征")
    print(f"  特征列表: {feature_names}")
    print(f"  标签分布:")
    for label, count in sorted(label_counts.items()):
        print(f"    {label}: {count}")


if __name__ == "__main__":
    main()
