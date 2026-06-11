# ============================================================
# collector.py
# 从 Etherscan V2 拉取地址的所有链上数据
# ============================================================

import requests
import time
from config import ETHERSCAN_KEY, ETHERSCAN_BASE, ETHERSCAN_CHAIN

SESS = requests.Session()
SESS.headers.update({"User-Agent": "compliance-engine/1.0"})


# ============================================================
# 核心请求函数
# ============================================================

def _get(params, retry=5):
    """
    Etherscan V2 请求
    关键：只要 result 是 list 就返回，不管 message 是否 NOTOK
    """
    params["chainid"] = ETHERSCAN_CHAIN
    params["apikey"]  = ETHERSCAN_KEY

    for i in range(retry):
        try:
            r = SESS.get(ETHERSCAN_BASE, params=params, timeout=30)
            if r.status_code == 200:
                j      = r.json()
                result = j.get("result", [])

                # result 是 list → 有数据，直接返回
                if isinstance(result, list):
                    return j

                # result 是字符串 → 真正的错误
                if isinstance(result, str):
                    msg = result.lower()
                    if "rate limit" in msg:
                        print(f"    [限速] 等待3秒...")
                        time.sleep(3)
                        continue
                    if "no transactions" in msg or "no records" in msg:
                        return {"result": []}
                    print(f"    [API] {result[:100]}")
                    return {"result": []}

        except Exception as e:
            print(f"    [retry {i+1}/{retry}] {e}")

        time.sleep(0.5 * (1.5 ** i))

    return {"result": []}


def safe_int(x):
    """安全转换为整数，支持 hex 字符串"""
    if x is None: return 0
    if isinstance(x, int): return x
    s = str(x).strip().lower()
    if s in ("", "0x"): return 0
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
    except:
        return 0


# ============================================================
# 四种数据拉取
# ============================================================

def fetch_txlist(address):
    """
    普通 ETH 交易（txlist）
    用途：Gas 来源分析、ETH 流向、首笔入金来源
    """
    res = _get({
        "module":  "account",
        "action":  "txlist",
        "address": address.lower(),
        "sort":    "asc",
    }).get("result", [])
    return res if isinstance(res, list) else []


def fetch_internaltx(address):
    """
    内部交易（txlistinternal）
    用途：合约调用产生的 ETH 转账，DeFi 协议交互
    """
    res = _get({
        "module":  "account",
        "action":  "txlistinternal",
        "address": address.lower(),
        "sort":    "asc",
    }).get("result", [])
    return res if isinstance(res, list) else []


def fetch_tokentx(address):
    """
    ERC20 转账（tokentx）
    用途：全币种转账追踪（USDT/USDC/WETH等）
    """
    res = _get({
        "module":  "account",
        "action":  "tokentx",
        "address": address.lower(),
        "sort":    "asc",
    }).get("result", [])
    return res if isinstance(res, list) else []


def fetch_logs(address):
    """
    原始事件日志（getLogs）
    用途：DEX swap、LP 存取、底层事件
    topic0 = ERC20 Transfer event
    """
    TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    addr_padded    = "0x" + address.lower().replace("0x", "").zfill(64)

    logs = []
    for pos in ["topic1", "topic2"]:
        batch = _get({
            "module":    "logs",
            "action":    "getLogs",
            "fromBlock": "0",
            "toBlock":   "latest",
            "topic0":    TOPIC_TRANSFER,
            pos:         addr_padded,
        }).get("result", [])
        if isinstance(batch, list):
            logs.extend(batch)
        time.sleep(0.25)

    return logs


# ============================================================
# 组合拉取（四合一）
# ============================================================

def fetch_all(address, verbose=True):
    """
    拉取一个地址的所有链上数据
    返回：(eth_txs, int_txs, token_txs, logs)
    """
    addr = address.lower()

    if verbose:
        print(f"    拉取 ETH 交易...")
    eth = fetch_txlist(addr)
    if verbose:
        print(f"      → {len(eth)} 笔")
    time.sleep(0.25)

    if verbose:
        print(f"    拉取内部交易...")
    int_ = fetch_internaltx(addr)
    if verbose:
        print(f"      → {len(int_)} 笔")
    time.sleep(0.25)

    if verbose:
        print(f"    拉取 ERC20 转账（全币种）...")
    tok = fetch_tokentx(addr)
    if verbose:
        print(f"      → {len(tok)} 笔")
    time.sleep(0.25)

    if verbose:
        print(f"    拉取原始事件...")
    logs = fetch_logs(addr)
    if verbose:
        print(f"      → {len(logs)} 条")

    return eth, int_, tok, logs


# ============================================================
# 多跳采集（BFS 往上追来源）
# ============================================================

def collect_hops(address, hops=2, verbose=True):
    """
    BFS 往上追 hops 跳
    每层最多追 5 个来源地址，控制 API 调用量

    返回：
      all_eth     所有 ETH 交易
      all_int     所有内部交易
      all_token   所有 ERC20 转账
      all_logs    所有原始事件
      visited     访问过的地址集合
    """
    all_eth, all_int, all_token, all_logs = [], [], [], []
    visited = set()
    queue   = [(address.lower(), 0)]

    while queue:
        addr, depth = queue.pop(0)
        if addr in visited or depth > hops:
            continue
        visited.add(addr)

        if verbose:
            indent = "  " * depth
            print(f"\n  {indent}[深度{depth}] {addr[:22]}...")

        eth, int_, tok, logs = fetch_all(addr, verbose=verbose)

        all_eth   += eth
        all_int   += int_
        all_token += tok
        all_logs  += logs

        # 往上追：找这个地址收到钱的来源
        sources = list(set(
            tx.get("from", "").lower()
            for tx in eth + tok
            if tx.get("to", "").lower() == addr
               and tx.get("from", "").lower() not in visited
               and tx.get("from", "")
        ))

        # 每层最多追5个来源，避免爆炸
        for src in sources[:5]:
            queue.append((src, depth + 1))

        time.sleep(0.2)

    if verbose:
        total = len(all_eth) + len(all_int) + len(all_token)
        print(f"\n  采集完成: {len(visited)} 个地址 / {total} 笔交易")

    return all_eth, all_int, all_token, all_logs, visited


# ============================================================
# 工具：提取地址的第一笔入金来源
# ============================================================

def get_first_funder(address, eth_txs):
    """
    找到给这个地址发送第一笔 ETH 的来源地址
    用于 C8 Gas Funding 检测
    """
    addr = address.lower()
    incoming = [
        tx for tx in eth_txs
        if tx.get("to", "").lower() == addr
        and safe_int(tx.get("value", 0)) > 0
    ]
    if not incoming:
        return None
    first = sorted(incoming, key=lambda x: safe_int(x.get("blockNumber", 0)))[0]
    return first.get("from", "").lower()


# ============================================================
# 工具：按 token 类型统计转账
# ============================================================

def summarize_tokens(token_txs):
    """
    统计涉及的币种和数量
    返回：{symbol: count}
    """
    from collections import Counter
    symbols = [tx.get("tokenSymbol", "?") for tx in token_txs]
    return dict(Counter(symbols).most_common(20))
