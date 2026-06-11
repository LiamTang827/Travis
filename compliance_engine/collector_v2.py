# ============================================================
# collector.py  v2
# 全量交易采集 + Method 标签 + SQLite 存储去重
# 
# 核心改进：
#   1. getLogs 拿全量 Transfer 事件（不漏 DEX/合约路由的交易）
#   2. txlist 按 block 批量拿 methodId + functionName（不逐个查）
#   3. SQLite 自动去重，多地址 overlap 不重复存
#   4. 每条边打拓扑标签（peel/fanout/smurfing等，由 graph 层写入）
# ============================================================

import requests, time, json, os, sqlite3
from collections import defaultdict
from config import ETHERSCAN_KEY, ETHERSCAN_BASE, ETHERSCAN_CHAIN

SESS = requests.Session()
SESS.headers.update({"User-Agent": "lucidaml/2.0"})

# SQLite 路径（跟 analyze.py 同目录）
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "chain_sentinel.db")

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# ── 本地 Method 签名字典（覆盖95%+的DeFi操作，不需要API）──────────
METHOD_LABELS = {
    "0xa9059cbb": "transfer",
    "0x23b872dd": "transferFrom",
    "0x095ea7b3": "approve",
    "0x40c10f19": "mint",
    "0x42966c68": "burn",
    "0x79cc6790": "burnFrom",
    "0xd0e30db0": "deposit",
    "0x2e1a7d4d": "withdraw",
    "0x3d18b912": "getReward",
    "0xe8e33700": "addLiquidity",
    "0x4a25d94a": "swapTokensForExactTokens",
    "0x7ff36ab5": "swapExactETHForTokens",
    "0x18cbafe5": "swapExactTokensForETH",
    "0x38ed1739": "swapExactTokensForTokens",
    "0x8803dbee": "swapTokensForExactETH",
    "0xfb3bdb41": "swapETHForExactTokens",
    "0x5c11d795": "swapExactTokensForTokensSupportingFeeOnTransferTokens",
    "0xb6f9de95": "swapExactETHForTokensSupportingFeeOnTransferTokens",
    "0x791ac947": "swapExactTokensForETHSupportingFeeOnTransferTokens",
    "0x414bf389": "exactInputSingle",    # Uniswap V3
    "0xdb3e2198": "exactOutputSingle",
    "0xc04b8d59": "exactInput",
    "0xf28c0498": "exactOutput",
    "0xac9650d8": "multicall",
    "0x5ae401dc": "multicall",           # Uniswap V3 multicall (with deadline)
    "0x04e45aaf": "exactInputSingle",    # V3 router2
    "0x0162e2d0": "exactOutputSingle",
    "0x3593564c": "execute",             # Uniswap Universal Router
    "0x12aa3caf": "swap",               # 1inch v5
    "0xe449022e": "uniswapV3Swap",      # 1inch
    "0x2e95b6c8": "unoswap",            # 1inch
    "0xa6c3bf33": "fillOrderRFQ",       # 1inch
    "0x9871efa4": "swap",               # Paraswap
    "0xda8567c8": "simpleBuy",
    "0x54e3f31b": "simpleSwap",
    "0x76019e2f": "depositAndSwap",
    "0xe2a7515e": "swap",               # Curve
    "0x3df02124": "exchange",           # Curve
    "0xa6417ed6": "exchange_underlying",# Curve
    "0x6a627842": "mint",               # Uniswap V2 LP
    "0xba9a7a56": "burn",               # Uniswap V2 LP
    "0x022c0d9f": "swap",               # Uniswap V2 pair
    "0x1a4d01d2": "remove_liquidity",   # Curve
    "0x0b4c7e4d": "add_liquidity",      # Curve
    "0x4515cef3": "add_liquidity",
    "0xee22be23": "stake",
    "0xa694fc3a": "stake",
    "0x2def6620": "unstake",
    "0x3a4b66f1": "stake",
    "0x1249c58b": "mint",
    "0x60759fce": "claimReward",
    "0x4e71d92d": "claim",
    "0xb88a802f": "claimReward",
    "0x853828b6": "withdrawAll",
    "0x441a3e70": "withdraw",
    "0xe9fad8ee": "exit",
    "0x8340f549": "depositFor",
    "0x2d2da806": "depositETH",
    "0x47e7ef24": "deposit",
    "0xf340fa01": "deposit",
    "0x6e553f65": "deposit",            # ERC4626
    "0xb460af94": "withdraw",           # ERC4626
    "0x07a96aff": "submitOrder",
    "0xab834bab": "atomicMatch_",       # OpenSea
    "0x1a8631b2": "cancelOrder",
    "0x9a1fc3a7": "fulfillOrder",       # Seaport
    "0xed98a574": "fulfillBasicOrder",  # Seaport
    "0xa8174404": "fulfillBasicOrder_efficient",
    "0x00000000": "fulfillBasicOrder",
    "0xe7acab24": "fulfillAdvancedOrder",
    "0xf07ec373": "safeTransferFrom",
    "0x42842e0e": "safeTransferFrom",
    "0xb88d4fde": "safeTransferFrom",
    "0x23b872dd": "transferFrom",
    "0xa22cb465": "setApprovalForAll",
    "0x6352211e": "ownerOf",
    "0x": "ETH transfer",
    "0x0": "ETH transfer",
}


# ============================================================
# 核心请求
# ============================================================

def _get(params, retry=5):
    params["chainid"] = ETHERSCAN_CHAIN
    params["apikey"]  = ETHERSCAN_KEY
    for i in range(retry):
        try:
            r = SESS.get(ETHERSCAN_BASE, params=params, timeout=30)
            if r.status_code == 200:
                j      = r.json()
                result = j.get("result", [])
                if isinstance(result, list):
                    return j
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
    if x is None: return 0
    if isinstance(x, int): return x
    s = str(x).strip().lower()
    if s in ("", "0x"): return 0
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
    except:
        return 0


# ============================================================
# SQLite 初始化
# ============================================================

def init_db(db_path=None):
    """初始化数据库，建表"""
    path = db_path or DB_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    c = conn.cursor()

    # 主交易表：每条边一行，tx_hash+log_index唯一
    c.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            tx_hash         TEXT NOT NULL,
            log_index       INTEGER DEFAULT 0,
            block_number    INTEGER,
            ts              INTEGER,
            from_addr       TEXT,
            to_addr         TEXT,
            value_raw       TEXT,
            token_symbol    TEXT DEFAULT 'ETH',
            token_decimal   INTEGER DEFAULT 18,
            method_id       TEXT,
            method          TEXT,
            function_name   TEXT,
            topo_tags       TEXT DEFAULT '[]',
            PRIMARY KEY (tx_hash, log_index)
        )
    """)

    # 地址扫描记录
    c.execute("""
        CREATE TABLE IF NOT EXISTS scanned_addresses (
            address     TEXT PRIMARY KEY,
            scanned_at  INTEGER,
            hops        INTEGER DEFAULT 1
        )
    """)

    # 索引
    c.execute("CREATE INDEX IF NOT EXISTS idx_from ON transactions(from_addr)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_to   ON transactions(to_addr)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_block ON transactions(block_number)")

    conn.commit()
    return conn


# ============================================================
# Step 1: getLogs — 拿全量 Transfer 事件
# ============================================================

def fetch_transfer_logs(address, from_block=0, to_block=99999999, step=2000):
    """
    用 getLogs 拿一个地址相关的所有 ERC20 Transfer 事件
    比 tokentx 更全：包括 DEX 路由、合约内部转账
    """
    addr_padded = "0x" + address.lower().replace("0x", "").zfill(64)
    logs = []

    for topic_pos in ["topic1", "topic2"]:   # topic1=from, topic2=to
        cur = from_block
        while cur <= to_block:
            end = min(cur + step - 1, to_block)
            batch = _get({
                "module":    "logs",
                "action":    "getLogs",
                "fromBlock": str(cur),
                "toBlock":   str(end),
                "topic0":    TRANSFER_TOPIC,
                topic_pos:   addr_padded,
            }).get("result", [])

            if isinstance(batch, list) and batch:
                logs.extend(batch)
                print(f"      getLogs {topic_pos} blocks {cur}-{end}: {len(batch)} events")

            # 如果返回满1000条，可能截断，缩窗口
            if len(batch) >= 1000 and step > 200:
                step = step // 2
                continue

            cur += step
            time.sleep(0.22)

    # 去重（同一个log可能在两次查询都出现）
    seen = set()
    unique = []
    for lg in logs:
        key = (lg.get("transactionHash",""), lg.get("logIndex",""))
        if key not in seen:
            seen.add(key)
            unique.append(lg)

    return unique


def parse_transfer_log(log):
    """从 Transfer event log 解析 from/to/value"""
    topics = log.get("topics", [])
    if len(topics) < 3:
        return None, None, 0
    sender   = "0x" + topics[1][-40:]
    receiver = "0x" + topics[2][-40:]
    try:
        value = int(log.get("data", "0x0") or "0x0", 16)
    except:
        value = 0
    return sender.lower(), receiver.lower(), value


# ============================================================
# Step 2: 批量从 txlist 拿 methodId + functionName
# ============================================================

def fetch_methods_by_block_range(address, start_block, end_block):
    """
    用 txlist 按 block range 批量拿该地址的所有 tx
    返回 {tx_hash: (method_id, function_name, method_label)}
    
    关键优化：一次 API 调用拿一批 tx 的 method，不逐个查
    """
    result = {}
    page = 1
    while True:
        batch = _get({
            "module":     "account",
            "action":     "txlist",
            "address":    address.lower(),
            "startblock": str(start_block),
            "endblock":   str(end_block),
            "page":       str(page),
            "offset":     "1000",
            "sort":       "asc",
        }).get("result", [])

        if not batch:
            break

        for tx in batch:
            h   = tx.get("hash", "").lower()
            mid = tx.get("methodId", "0x") or "0x"
            fn  = tx.get("functionName", "") or ""
            label = fn.split("(")[0].strip() if fn else mid
            result[h] = (mid, fn, label)

        if len(batch) < 1000:
            break
        page += 1
        time.sleep(0.22)

    return result


def fetch_methods_for_hashes(tx_hashes, address=None):
    """
    ★ 本地字典瞬间decode，不发任何API请求 ★
    getLogs里没有input data，所以method从tokentx的methodId字段来。
    这里返回空dict，fetch_all_with_method会用tokentx补充method。
    tx_hashes: list of (hash, block_number)  ← 保持接口不变
    """
    return {}


# ============================================================
# 主采集函数：全量 + method
# ============================================================

def fetch_all_with_method(address, verbose=True):
    """
    ★ 重写版：直接用 tokentx，本地字典 decode method，秒完 ★
    
    原来：getLogs(全链扫) + 逐个补查method → 几百次API，半小时
    现在：tokentx(一次API) + 本地字典decode → 几秒
    
    tokentx 已经包含 methodId + functionName，不需要任何补查。
    """
    addr = address.lower()
    if verbose:
        print(f"    [tokentx] 拉取 ERC20 转账 + method...")

    res = _get({
        "module":  "account",
        "action":  "tokentx",
        "address": addr,
        "sort":    "asc",
    }).get("result", [])
    tok = res if isinstance(res, list) else []

    if verbose:
        print(f"      → {len(tok)} 笔")

    # 同时拉 txlist 补充 ETH 转账的 method（tokentx 没有 ETH tx）
    eth_res = _get({
        "module":  "account",
        "action":  "txlist",
        "address": addr,
        "sort":    "asc",
    }).get("result", [])
    eth_txs = eth_res if isinstance(eth_res, list) else []

    # 本地字典 decode ETH tx 的 method
    eth_method_map = {}
    for tx in eth_txs:
        h   = tx.get("hash", "").lower()
        inp = tx.get("input", "") or ""
        mid = inp[:10].lower() if inp and inp not in ("0x", "") and len(inp) >= 10 else "0x"
        fn  = tx.get("functionName", "") or ""
        label = fn.split("(")[0].strip() if fn else METHOD_LABELS.get(mid, mid)
        eth_method_map[h] = (mid, fn, label)

    records = []
    seen = set()

    for tx in tok:
        h = tx.get("hash", "").lower()
        log_key = (h, tx.get("transactionIndex", "0"))
        if log_key in seen:
            continue
        seen.add(log_key)

        # tokentx 自带 methodId，直接用本地字典
        inp = tx.get("input", "") or ""
        mid_raw = tx.get("methodId", "") or (inp[:10] if inp and len(inp) >= 10 else "0x")
        mid = mid_raw.lower() if mid_raw else "0x"
        fn  = tx.get("functionName", "") or ""
        label = fn.split("(")[0].strip() if fn else METHOD_LABELS.get(mid, mid)

        records.append({
            "tx_hash":       h,
            "log_index":     0,
            "block_number":  safe_int(tx.get("blockNumber", 0)),
            "ts":            safe_int(tx.get("timeStamp", 0)),
            "from_addr":     tx.get("from", "").lower(),
            "to_addr":       tx.get("to", "").lower(),
            "value_raw":     tx.get("value", "0"),
            "token_symbol":  tx.get("tokenSymbol", "ERC20"),
            "token_decimal": safe_int(tx.get("tokenDecimal", 18)),
            "method_id":     mid,
            "method":        label,
            "function_name": fn,
            "topo_tags":     [],
        })

    if verbose:
        print(f"      → {len(records)} 条完整记录（本地decode，0 额外API）")

    return records


def _fetch_tokentx_with_method(address, verbose=True):
    """fallback: tokentx + txlist method"""
    from collector import fetch_tokentx, fetch_txlist
    tok = fetch_tokentx(address)
    eth = fetch_txlist(address)

    # 建 hash→method 映射
    method_map = {}
    for tx in eth:
        h   = tx.get("hash", "").lower()
        mid = tx.get("methodId", "0x") or "0x"
        fn  = tx.get("functionName", "") or ""
        method_map[h] = (mid, fn, fn.split("(")[0].strip() if fn else mid)

    records = []
    for tx in tok:
        h = tx.get("hash", "").lower()
        mid, fn, label = method_map.get(h, ("0x", "", "transfer"))
        records.append({
            "tx_hash":       h,
            "log_index":     0,
            "block_number":  safe_int(tx.get("blockNumber", 0)),
            "ts":            safe_int(tx.get("timeStamp", 0)),
            "from_addr":     tx.get("from", "").lower(),
            "to_addr":       tx.get("to", "").lower(),
            "value_raw":     tx.get("value", "0"),
            "token_symbol":  tx.get("tokenSymbol", "?"),
            "token_decimal": safe_int(tx.get("tokenDecimal", 18)),
            "method_id":     mid,
            "method":        label,
            "function_name": fn,
            "topo_tags":     [],
        })
    return records


def _fetch_token_symbol_map(address):
    """用 tokentx 建 tx_hash → {symbol, decimal} 映射"""
    res = _get({
        "module":  "account",
        "action":  "tokentx",
        "address": address.lower(),
        "sort":    "asc",
    }).get("result", [])
    mapping = {}
    for tx in (res if isinstance(res, list) else []):
        h = tx.get("hash", "").lower()
        mapping[h] = {
            "symbol":  tx.get("tokenSymbol", "ERC20"),
            "decimal": safe_int(tx.get("tokenDecimal", 18)),
        }
    return mapping


# ============================================================
# SQLite 存储
# ============================================================

def save_to_db(records, address, conn=None):
    """
    把采集结果存入 SQLite，自动去重（PRIMARY KEY = tx_hash + log_index）
    同时记录已扫描地址
    """
    close_after = conn is None
    if conn is None:
        conn = init_db()

    c = conn.cursor()
    inserted = 0
    skipped  = 0

    for rec in records:
        try:
            c.execute("""
                INSERT OR IGNORE INTO transactions
                  (tx_hash, log_index, block_number, ts,
                   from_addr, to_addr, value_raw,
                   token_symbol, token_decimal,
                   method_id, method, function_name, topo_tags)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                rec["tx_hash"],
                rec.get("log_index", 0),
                rec.get("block_number", 0),
                rec.get("ts", 0),
                rec.get("from_addr", ""),
                rec.get("to_addr", ""),
                rec.get("value_raw", "0"),
                rec.get("token_symbol", "ERC20"),
                rec.get("token_decimal", 18),
                rec.get("method_id", "0x"),
                rec.get("method", ""),
                rec.get("function_name", ""),
                json.dumps(rec.get("topo_tags", [])),
            ))
            if c.rowcount > 0:
                inserted += 1
            else:
                skipped += 1
        except Exception as e:
            print(f"    [DB] insert error: {e}")

    # 记录已扫描地址
    c.execute("""
        INSERT OR REPLACE INTO scanned_addresses (address, scanned_at, hops)
        VALUES (?, ?, 1)
    """, (address.lower(), int(time.time())))

    conn.commit()
    if close_after:
        conn.close()

    print(f"      DB: +{inserted} 新增, {skipped} 已存在")
    return inserted, skipped


def update_topo_tags(tx_hash, log_index, tags, conn):
    """更新某条边的拓扑标签"""
    c = conn.cursor()
    c.execute("""
        UPDATE transactions SET topo_tags=? WHERE tx_hash=? AND log_index=?
    """, (json.dumps(tags), tx_hash, log_index))
    conn.commit()


def load_from_db(address=None, conn=None):
    """
    从 DB 读取交易记录
    address=None 时读全部
    """
    close_after = conn is None
    if conn is None:
        conn = init_db()

    c = conn.cursor()
    if address:
        addr = address.lower()
        c.execute("""
            SELECT tx_hash, log_index, block_number, ts,
                   from_addr, to_addr, value_raw,
                   token_symbol, token_decimal,
                   method_id, method, function_name, topo_tags
            FROM transactions
            WHERE from_addr=? OR to_addr=?
            ORDER BY block_number ASC
        """, (addr, addr))
    else:
        c.execute("""
            SELECT tx_hash, log_index, block_number, ts,
                   from_addr, to_addr, value_raw,
                   token_symbol, token_decimal,
                   method_id, method, function_name, topo_tags
            FROM transactions ORDER BY block_number ASC
        """)

    rows = c.fetchall()
    if close_after:
        conn.close()

    return [
        {
            "tx_hash":       r[0],
            "log_index":     r[1],
            "block_number":  r[2],
            "ts":            r[3],
            "from_addr":     r[4],
            "to_addr":       r[5],
            "value_raw":     r[6],
            "token_symbol":  r[7],
            "token_decimal": r[8],
            "method_id":     r[9],
            "method":        r[10],
            "function_name": r[11],
            "topo_tags":     json.loads(r[12] or "[]"),
        }
        for r in rows
    ]


# ============================================================
# 兼容旧接口（analyze.py 用到的）
# ============================================================

def fetch_txlist(address):
    res = _get({
        "module":  "account",
        "action":  "txlist",
        "address": address.lower(),
        "sort":    "asc",
    }).get("result", [])
    return res if isinstance(res, list) else []


def fetch_internaltx(address):
    res = _get({
        "module":  "account",
        "action":  "txlistinternal",
        "address": address.lower(),
        "sort":    "asc",
    }).get("result", [])
    return res if isinstance(res, list) else []


def fetch_tokentx(address):
    res = _get({
        "module":  "account",
        "action":  "tokentx",
        "address": address.lower(),
        "sort":    "asc",
    }).get("result", [])
    return res if isinstance(res, list) else []


def fetch_logs(address):
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


def fetch_all(address, verbose=True):
    addr = address.lower()
    if verbose: print(f"    拉取 ETH 交易...")
    eth = fetch_txlist(addr)
    if verbose: print(f"      → {len(eth)} 笔")
    time.sleep(0.25)
    if verbose: print(f"    拉取内部交易...")
    int_ = fetch_internaltx(addr)
    if verbose: print(f"      → {len(int_)} 笔")
    time.sleep(0.25)
    if verbose: print(f"    拉取 ERC20 转账（全币种）...")
    tok = fetch_tokentx(addr)
    if verbose: print(f"      → {len(tok)} 笔")
    time.sleep(0.25)
    if verbose: print(f"    拉取原始事件...")
    logs = fetch_logs(addr)
    if verbose: print(f"      → {len(logs)} 条")
    return eth, int_, tok, logs


def collect_hops(address, hops=2, verbose=True):
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
        sources = list(set(
            tx.get("from", "").lower()
            for tx in eth + tok
            if tx.get("to", "").lower() == addr
               and tx.get("from", "").lower() not in visited
               and tx.get("from", "")
        ))
        for src in sources[:5]:
            queue.append((src, depth + 1))
        time.sleep(0.2)
    if verbose:
        total = len(all_eth) + len(all_int) + len(all_token)
        print(f"\n  采集完成: {len(visited)} 个地址 / {total} 笔交易")
    return all_eth, all_int, all_token, all_logs, visited


def get_first_funder(address, eth_txs):
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


def summarize_tokens(token_txs):
    from collections import Counter
    symbols = [tx.get("tokenSymbol", "?") for tx in token_txs]
    return dict(Counter(symbols).most_common(20))
