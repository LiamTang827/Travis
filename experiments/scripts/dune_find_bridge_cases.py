#!/usr/bin/env python3
"""
用 Dune Analytics 查询：与黑名单地址有 USDT 往来，且使用过跨链桥的地址
这是找真实 AML 测试案例的正确方法（直接查链上事件日志，不依赖 Etherscan txlist）
"""

import os
import csv
import time
import json
import requests
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

DUNE_API_KEY = os.getenv("DUNE_API_KEY", "")
BLACKLIST_CSV = PROJECT_ROOT / "data" / "blacklists" / "usdt_blacklist.csv"
OUTPUT_FILE = PROJECT_ROOT / "artifacts" / "reports" / "bridge_cases_from_dune.json"

# ==================== Dune SQL 查询 ====================
# 逻辑：
#   1. 找所有与黑名单地址有过 USDT 转账的地址（counterparty）
#   2. 再找这些 counterparty 是否也调用过跨链桥合约
#   3. 输出：counterparty 地址 + 关联的黑名单地址 + 使用的桥

DUNE_QUERY_SQL = """
WITH

-- 黑名单地址列表（取 ETH 链前200个，避免查询太重）
blacklist(addr) AS (
  SELECT LOWER(address)
  FROM (VALUES
    {blacklist_values}
  ) AS t(address)
),

-- 主流跨链桥合约
bridges(contract, name) AS (
  SELECT * FROM (VALUES
    ('0x8731d54e9d02c286767d56ac03e8037c07e01e98', 'Stargate Finance'),
    ('0x3e4a3a4796d16c0cd582c382691998f7c06420b6', 'Hop Protocol USDT'),
    ('0x5427fefa711eff984124bfbb1ab6fbf5e3da1820', 'Celer cBridge'),
    ('0x4d9079bb4165aeb4084c526a32695dcfd2f77381', 'Across Protocol v2'),
    ('0x2796317b0ff8538f253012862c06787adfb8ceb',  'Synapse Bridge'),
    ('0x3ee18b2214aff97000d974cf647e7c347e8fa585', 'Wormhole'),
    ('0xc564ee9f21ed8a2d8e7e76c085740d5e4c5fafbe', 'Multichain'),
    ('0x80c67432656d59144ceff962e8faf8926599bcf8', 'Orbiter Finance'),
    ('0x66a71dcef29a0ffbdbe3c6a460a3b5bc225cd675', 'LayerZero v1'),
    ('0x1a44076050125825900e736c501f859c50fe728c', 'LayerZero v2'),
    ('0xa0c68c638235ee32657e8f720a23cec1bfc77c77', 'Polygon Bridge'),
    ('0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a', 'Arbitrum Bridge'),
    ('0x99c9fc46f92e8a1c0dec1b1747d010903e884be1', 'Optimism Gateway'),
    ('0x43de2d77bf8027e25dbd179b491e8d64f38398aa', 'deBridge'),
    ('0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936', 'Tornado Cash 0.1ETH'),
    ('0x910cbd523d972eb0a6f4cae4618ad62622b39dbf', 'Tornado Cash 1ETH'),
    ('0xa160cdab225685da1d56aa342ad8841c3b53f291', 'Tornado Cash 10ETH'),
    ('0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3', 'Tornado Cash 100ETH')
  ) AS t(contract, name)
),

-- USDT 合约地址
-- USDT ERC20: 0xdac17f958d2ee523a2206206994597c13d831ec7

-- Step1: 找与黑名单地址有过 USDT 转账的对手方
usdt_with_blacklist AS (
  SELECT
    CASE
      WHEN LOWER(t."from") IN (SELECT addr FROM blacklist) THEN LOWER(t."to")
      ELSE LOWER(t."from")
    END AS counterparty,
    CASE
      WHEN LOWER(t."from") IN (SELECT addr FROM blacklist) THEN LOWER(t."from")
      ELSE LOWER(t."to")
    END AS blacklist_addr,
    t.evt_tx_hash,
    t.evt_block_time,
    t.value / 1e6 AS usdt_amount
  FROM usdt_ethereum.USDT_evt_Transfer t
  WHERE
    LOWER(t."from") IN (SELECT addr FROM blacklist)
    OR LOWER(t."to") IN (SELECT addr FROM blacklist)
  ORDER BY t.evt_block_time DESC
  LIMIT 5000
),

-- Step2: 找这些对手方是否也使用了跨链桥
bridge_usage AS (
  SELECT
    LOWER(tx."from") AS bridge_user,
    b.name AS bridge_name,
    b.contract AS bridge_contract,
    tx.hash AS bridge_tx,
    tx.block_time AS bridge_time
  FROM ethereum.transactions tx
  JOIN bridges b ON LOWER(tx."to") = b.contract
  WHERE LOWER(tx."from") IN (SELECT DISTINCT counterparty FROM usdt_with_blacklist)
)

-- 最终结果：counterparty + 关联黑名单 + 使用桥
SELECT DISTINCT
  ub.counterparty,
  ub.blacklist_addr,
  ub.usdt_amount,
  ub.evt_block_time AS usdt_tx_time,
  bu.bridge_name,
  bu.bridge_tx,
  bu.bridge_time
FROM usdt_with_blacklist ub
JOIN bridge_usage bu ON ub.counterparty = bu.bridge_user
ORDER BY ub.evt_block_time DESC
LIMIT 200
"""


def load_eth_blacklist(path: str, limit: int = 200) -> list:
    rows = []
    with open(path) as f:
        for row in csv.DictReader(f):
            if row["chain"] == "ethereum":
                rows.append(row["address"].lower())
                if len(rows) >= limit:
                    break
    return rows


def run_dune_query(sql: str, api_key: str) -> list:
    headers = {"X-Dune-API-Key": api_key, "Content-Type": "application/json"}

    print("[*] 提交 Dune 查询...")
    r = requests.post(
        "https://api.dune.com/api/v1/query/execute",
        headers=headers,
        json={"query_sql": sql, "performance": "medium"},
        timeout=30,
    )
    if r.status_code != 200:
        print(f"[ERROR] 提交失败: {r.status_code} {r.text[:300]}")
        return []

    execution_id = r.json().get("execution_id")
    print(f"[*] 执行 ID: {execution_id}")

    # 等待完成
    for i in range(60):
        time.sleep(5)
        status_r = requests.get(
            f"https://api.dune.com/api/v1/execution/{execution_id}/status",
            headers=headers,
            timeout=15,
        ).json()
        state = status_r.get("state", "")
        print(f"    [{i*5}s] 状态: {state}")
        if state == "QUERY_STATE_COMPLETED":
            break
        if state in ("QUERY_STATE_FAILED", "QUERY_STATE_CANCELLED"):
            print(f"[ERROR] 查询失败: {status_r}")
            return []

    # 拉取结果
    result_r = requests.get(
        f"https://api.dune.com/api/v1/execution/{execution_id}/results",
        headers=headers,
        params={"limit": 200},
        timeout=30,
    ).json()
    return result_r.get("result", {}).get("rows", [])


def main():
    print("[*] 加载 ETH 黑名单（前200个）...")
    bl_addrs = load_eth_blacklist(BLACKLIST_CSV, 200)
    print(f"[*] 加载 {len(bl_addrs)} 个地址")

    # 生成 SQL VALUES 列表
    values_str = ",\n    ".join(f"('{addr}')" for addr in bl_addrs)
    sql = DUNE_QUERY_SQL.replace("{blacklist_values}", values_str)

    # 运行查询
    rows = run_dune_query(sql, DUNE_API_KEY)

    if not rows:
        print("[WARN] 未获取到结果")
        return

    print(f"\n[*] 发现 {len(rows)} 条跨链桥关联记录\n")

    # 保存
    with open(OUTPUT_FILE, "w") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
    print(f"[*] 结果已保存: {OUTPUT_FILE}")

    # 打印汇总
    print(f"\n{'='*60}")
    print("测试案例列表（可直接用 aml_analyzer.py 分析）：")
    print(f"{'='*60}")
    seen = set()
    for row in rows:
        addr = row.get("counterparty", "")
        if addr in seen:
            continue
        seen.add(addr)
        print(f"\n  地址:     {addr}")
        print(f"  关联黑名单: {row.get('blacklist_addr','')[:30]}...")
        print(f"  USDT金额: {row.get('usdt_amount', '?')} USDT")
        print(f"  使用桥:   {row.get('bridge_name', '')}")
        print(f"  桥交易:   {row.get('bridge_tx', '')[:30]}...")
        print(f"\n  验证命令:")
        print(f"  .venv/bin/python aml_analyzer.py {addr} --chain ethereum --no-hop2")

    print(f"\n共 {len(seen)} 个唯一可疑地址")


if __name__ == "__main__":
    main()
