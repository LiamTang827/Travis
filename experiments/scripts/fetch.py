#!/usr/bin/env python3
# ============================================================
# fetch.py — 按 Token 合约全量采集 Transfer 事件
#
# 基于 collector_v2.py 的 method 逻辑：
#   - getLogs(address=Token合约) 扫全量 Transfer
#   - tokentx 补 methodId + functionName（和 collector_v2 完全一致）
#   - 本地字典 decode method（不逐个查 API）
#   - 断点续跑、CSV 分片输出（每片文件名带时间戳不覆盖）
#
# 用法:
#   python experiments/scripts/fetch.py --token USDT            # 采集 USDT
#   python experiments/scripts/fetch.py --token USDT USDC DAI   # 多个
#   python experiments/scripts/fetch.py --resume                # 断点续跑
#   python experiments/scripts/fetch.py --status                # 查看进度
#   python experiments/scripts/fetch.py --export USDT           # 从DB导出 CSV
# ============================================================

import requests, time, json, os, sqlite3, sys, argparse, csv, glob
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# ╔══════════════════════════════════════════════════════════╗
# ║                     配置                                ║
# ╠══════════════════════════════════════════════════════════╣
PROJECT_ROOT    = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

ETHERSCAN_KEY   = os.getenv("ETHERSCAN_API_KEY", "")
ETHERSCAN_BASE  = "https://api.etherscan.io/v2/api"
ETHERSCAN_CHAIN = "1"
DB_PATH         = str(PROJECT_ROOT / "artifacts" / "tokens.db")
FROM_DATE       = "2017-11-28"
TO_DATE         = "2025-05-06"
# ╚══════════════════════════════════════════════════════════╝

if not ETHERSCAN_KEY:
    try:
        from config import ETHERSCAN_KEY as _K, ETHERSCAN_BASE as _B, ETHERSCAN_CHAIN as _C
        ETHERSCAN_KEY, ETHERSCAN_BASE, ETHERSCAN_CHAIN = _K, _B, _C
    except ImportError:
        pass

if not ETHERSCAN_KEY:
    raise SystemExit("ERROR: ETHERSCAN_API_KEY not set in .env")

SESS = requests.Session()
SESS.headers.update({"User-Agent": "lucidaml-fetch/2.0"})
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

TOKEN_CONTRACTS = {
    "USDT": {"address": "0xdac17f958d2ee523a2206206994597c13d831ec7", "decimal": 6},
    "USDC": {"address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "decimal": 6},
    "DAI":  {"address": "0x6b175474e89094c44da98b954eedeac495271d0f", "decimal": 18},
    "WBTC": {"address": "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", "decimal": 8},
    "WETH": {"address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", "decimal": 18},
    "BUSD": {"address": "0x4fabb145d64652a948d72533023f6e7a623c7c53", "decimal": 18},
}

# ── 本地 Method 字典（直接复制自 collector_v2.py）────────────
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
    "0x414bf389": "exactInputSingle",
    "0xdb3e2198": "exactOutputSingle",
    "0xc04b8d59": "exactInput",
    "0xf28c0498": "exactOutput",
    "0xac9650d8": "multicall",
    "0x5ae401dc": "multicall",
    "0x04e45aaf": "exactInputSingle",
    "0x0162e2d0": "exactOutputSingle",
    "0x3593564c": "execute",
    "0x12aa3caf": "swap",
    "0xe449022e": "uniswapV3Swap",
    "0x2e95b6c8": "unoswap",
    "0xa6c3bf33": "fillOrderRFQ",
    "0x9871efa4": "swap",
    "0xda8567c8": "simpleBuy",
    "0x54e3f31b": "simpleSwap",
    "0x76019e2f": "depositAndSwap",
    "0xe2a7515e": "swap",
    "0x3df02124": "exchange",
    "0xa6417ed6": "exchange_underlying",
    "0x6a627842": "mint",
    "0xba9a7a56": "burn",
    "0x022c0d9f": "swap",
    "0x1a4d01d2": "remove_liquidity",
    "0x0b4c7e4d": "add_liquidity",
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
    "0x6e553f65": "deposit",
    "0xb460af94": "withdraw",
    "0xab834bab": "atomicMatch_",
    "0x9a1fc3a7": "fulfillOrder",
    "0xed98a574": "fulfillBasicOrder",
    "0xa8174404": "fulfillBasicOrder_efficient",
    "0xe7acab24": "fulfillAdvancedOrder",
    "0xf07ec373": "safeTransferFrom",
    "0x42842e0e": "safeTransferFrom",
    "0xb88d4fde": "safeTransferFrom",
    "0xa22cb465": "setApprovalForAll",
    "0x":        "ETH transfer",
    "0x0":       "ETH transfer",
}


# ============================================================
# API
# ============================================================

def safe_int(x):
    if x is None: return 0
    if isinstance(x, int): return x
    s = str(x).strip().lower()
    if s in ("", "0x"): return 0
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
    except:
        return 0


def _get(params, retry=6):
    params["chainid"] = ETHERSCAN_CHAIN
    params["apikey"]  = ETHERSCAN_KEY
    for i in range(retry):
        try:
            r = SESS.get(ETHERSCAN_BASE, params=params, timeout=30)
            if r.status_code == 200:
                j      = r.json()
                result = j.get("result", [])
                if isinstance(result, (list, dict)):
                    return j
                if isinstance(result, str):
                    # 纯数字字符串（如 getblocknobytime 返回块号）直接透传
                    if result.strip().isdigit():
                        return j
                    msg = result.lower()
                    if "rate limit" in msg or "max rate" in msg:
                        wait = 3 * (i + 1)
                        print(f"    [限速] 等待 {wait}s...")
                        time.sleep(wait)
                        continue
                    if any(x in msg for x in ("no transactions", "no records", "no result")):
                        return {"result": []}
                    print(f"    [API] {result[:100]}")
                    return {"result": []}
            elif r.status_code == 429:
                time.sleep(5 * (i + 1))
        except Exception as e:
            print(f"    [retry {i+1}] {e}")
        time.sleep(0.5 * (1.5 ** i))
    return {"result": []}


# ============================================================
# SQLite
# ============================================================

def init_db(path=None):
    path = path or DB_PATH
    conn = sqlite3.connect(path)
    c    = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            tx_hash         TEXT NOT NULL,
            log_index       INTEGER DEFAULT 0,
            block_number    INTEGER,
            ts              INTEGER,
            from_addr       TEXT,
            to_addr         TEXT,
            value_raw       TEXT,
            token_symbol    TEXT DEFAULT 'ERC20',
            token_decimal   INTEGER DEFAULT 18,
            method_id       TEXT,
            method          TEXT,
            function_name   TEXT,
            topo_tags       TEXT DEFAULT '[]',
            PRIMARY KEY (tx_hash, log_index)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS contract_progress (
            contract_addr   TEXT PRIMARY KEY,
            token_symbol    TEXT,
            status          TEXT DEFAULT 'pending',
            last_block      INTEGER DEFAULT 0,
            total_logs      INTEGER DEFAULT 0,
            total_inserted  INTEGER DEFAULT 0,
            started_at      INTEGER,
            updated_at      INTEGER,
            error_msg       TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS method_cache (
            tx_hash       TEXT PRIMARY KEY,
            method_id     TEXT,
            method        TEXT,
            function_name TEXT
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_from   ON transactions(from_addr)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_to     ON transactions(to_addr)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_block  ON transactions(block_number)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_symbol ON transactions(token_symbol)")
    conn.commit()
    return conn


def set_progress(conn, addr, symbol, status, last_block=0, total_logs=0, total_ins=0, error=None):
    now = int(time.time())
    c   = conn.cursor()
    c.execute("""
        INSERT OR REPLACE INTO contract_progress
          (contract_addr, token_symbol, status, last_block, total_logs, total_inserted,
           started_at, updated_at, error_msg)
        VALUES (
          ?, ?, ?, ?, ?, ?,
          COALESCE((SELECT started_at FROM contract_progress WHERE contract_addr=?), ?),
          ?, ?
        )
    """, (addr.lower(), symbol, status, last_block, total_logs, total_ins,
          addr.lower(), now, now, error))
    conn.commit()


def save_records(conn, records):
    c = conn.cursor()
    ins = sk = 0
    for rec in records:
        c.execute("""
            INSERT OR IGNORE INTO transactions
              (tx_hash, log_index, block_number, ts,
               from_addr, to_addr, value_raw,
               token_symbol, token_decimal,
               method_id, method, function_name, topo_tags)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            rec["tx_hash"], rec["log_index"],
            rec["block_number"], rec["ts"],
            rec["from_addr"], rec["to_addr"],
            str(rec["value_raw"]),
            rec["token_symbol"], rec["token_decimal"],
            rec["method_id"], rec["method"], rec["function_name"],
            json.dumps(rec.get("topo_tags", [])),
        ))
        if c.rowcount > 0: ins += 1
        else: sk += 1
    conn.commit()
    return ins, sk


def lookup_method_cache(conn, hashes):
    if not hashes: return {}
    c, result = conn.cursor(), {}
    for i in range(0, len(hashes), 900):
        batch = hashes[i:i+900]
        ph    = ",".join("?" * len(batch))
        c.execute(f"SELECT tx_hash, method_id, method, function_name FROM method_cache WHERE tx_hash IN ({ph})", batch)
        for row in c.fetchall():
            result[row[0]] = (row[1], row[2], row[3])
    return result


def cache_methods(conn, method_map):
    c = conn.cursor()
    c.executemany(
        "INSERT OR IGNORE INTO method_cache (tx_hash, method_id, method, function_name) VALUES (?,?,?,?)",
        [(h, v[0], v[1], v[2]) for h, v in method_map.items()]
    )
    conn.commit()


# ============================================================
# getLogs：按合约扫全量 Transfer
# 修复原版死循环：满1000缩窗后cur不动重试，不是continue卡死
# ============================================================

def fetch_contract_logs(contract_addr, from_block=0, to_block=22500000, step=2000):
    MIN_STEP = 25
    MAX_STEP = 10000
    cur = from_block
    empty_streak = 0
    print(f"    从 block {from_block:,} 扫到 {to_block:,}  (初始step={step})")

    while cur <= to_block:
        end = min(cur + step - 1, to_block)
        batch = _get({
            "module":    "logs",
            "action":    "getLogs",
            "fromBlock": str(cur),
            "toBlock":   str(end),
            "address":   contract_addr.lower(),
            "topic0":    TRANSFER_TOPIC,
        }).get("result", [])

        if not isinstance(batch, list):
            batch = []

        if len(batch) >= 1000:
            new_step = max(MIN_STEP, step // 2)
            if new_step == step:
                # 已到最小步长，接受截断继续推进
                print(f"      ⚠️  step已最小({MIN_STEP})仍满1000，接受截断")
                yield cur, end, batch
                cur += step
            else:
                step = new_step
                print(f"      ⚠️  满1000，缩窗至 {step} blocks，重试 block {cur:,}")
            time.sleep(0.22)
            continue

        if batch:
            yield cur, end, batch
            empty_streak = 0
            if len(batch) < 500 and step < MAX_STEP:
                step = min(MAX_STEP, int(step * 1.5))
        else:
            empty_streak += 1
            if empty_streak >= 3 and step < MAX_STEP:
                step = min(MAX_STEP, step * 2)
                empty_streak = 0

        if cur % 100000 < step:
            pct = int((cur - from_block) / max(to_block - from_block, 1) * 100)
            print(f"      进度 {pct}% | block {cur:,}/{to_block:,} | step={step}")

        cur += step
        time.sleep(0.22)


# ============================================================
# method 解析：eth_getTransactionByHash → input → methodId
# 再用 txlist 按 block 查 functionName（v7 原版逻辑）
# ============================================================

def get_tx_method(tx_hash, conn):
    """
    单笔 tx：eth_getTransactionByHash 拿 input → methodId
    本地字典 decode label，不查 txlist（快）
    functionName 留空，后面可以单独补
    """
    key = tx_hash.lower()

    # 先查缓存
    cached = lookup_method_cache(conn, [key])
    if key in cached:
        return cached[key]  # (mid, label, fn)

    j      = _get({"module": "proxy", "action": "eth_getTransactionByHash", "txhash": tx_hash})
    result = j.get("result") or {}
    inp    = result.get("input", "") or ""
    mid    = inp[:10].lower() if inp and inp not in ("0x", "") and len(inp) >= 10 else "0x"
    label  = METHOD_LABELS.get(mid, mid)
    fn     = ""

    cache_methods(conn, {key: (mid, label, fn)})
    return mid, label, fn


def fetch_methods_batch(tx_hashes, conn):
    """
    批量处理一批 tx hash 的 method，带进度打印
    """
    result  = {}
    missing = [h for h in tx_hashes if h not in lookup_method_cache(conn, tx_hashes)]
    for i, h in enumerate(missing):
        mid, label, fn = get_tx_method(h, conn)
        result[h] = (mid, label, fn)
        time.sleep(0.22)
    # 合并缓存里已有的
    cached = lookup_method_cache(conn, tx_hashes)
    cached.update(result)
    return cached


# ============================================================
# CSV 分片（每片文件名带时间戳，不会覆盖）
# ============================================================

CSV_CHUNK   = 900_000
CSV_HEADERS = ["Transaction Hash", "Block", "Date Time (UTC)",
               "From", "To", "Amount", "Token",
               "Method ID", "Method", "Function Name"]


def _new_csv(symbol):
    """新建 CSV，文件名带日期段+序号"""
    date_tag = f"{FROM_DATE[:4]}-{TO_DATE[:4]}"
    existing = sorted(glob.glob(f"{symbol}_{date_tag}_part*.csv"))
    part_num = len(existing) + 1
    ts_str   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path     = f"{symbol}_{date_tag}_part{part_num:03d}_{ts_str}.csv"
    f        = open(path, "w", newline="", encoding="utf-8")
    w        = csv.writer(f)
    w.writerow(CSV_HEADERS)
    print(f"  📄 新建 {path}")
    return f, w, path, part_num


def _reopen_csv(path):
    """续写已有 CSV"""
    rows = sum(1 for _ in open(path, encoding="utf-8")) - 1
    f    = open(path, "a", newline="", encoding="utf-8")
    w    = csv.writer(f)
    print(f"  📄 续写 {path}（已有 {rows:,} 行）")
    return f, w, rows


# ============================================================
# 主采集
# ============================================================

def collect_contract(contract_addr, symbol, decimal, conn, force=False,
                     from_block_override=0, to_block=22500000):
    addr = contract_addr.lower()

    # 断点：从 DB 找最大 block
    c = conn.cursor()
    c.execute("SELECT MAX(block_number), COUNT(*) FROM transactions WHERE token_symbol=?", (symbol,))
    row          = c.fetchone()
    db_max_block = row[0] or 0
    db_count     = row[1] or 0

    # 续跑：DB最大block必须>=from_block_override才算在日期范围内
    # 否则说明是旧数据，要从日期起点重新开始
    if db_max_block >= from_block_override and not force:
        from_block = db_max_block + 1  # +1 避免重复扫已有block
        total_logs = db_count
        total_ins  = db_count
        print(f"  ↩️  {symbol} 续跑，DB已有 {db_count:,} 条，从 block {from_block:,} 继续")
    else:
        from_block = from_block_override
        total_logs = 0
        total_ins  = 0
        print(f"  🔍 {symbol} ({addr}) 从 block {from_block:,} 开始采集...")

    set_progress(conn, addr, symbol, "running", from_block, total_logs, total_ins)
    last_saved_block = from_block

    # ── CSV：续跑接着写，新跑新建 ──────────────────────────
    date_tag = f"{FROM_DATE[:4]}-{TO_DATE[:4]}"
    existing_csvs = sorted(glob.glob(f"{symbol}_{date_tag}_part*.csv"))
    if existing_csvs and not force:
        last_path = existing_csvs[-1]
        last_rows = sum(1 for _ in open(last_path, encoding="utf-8")) - 1
        if last_rows < CSV_CHUNK:
            csv_f, csv_w, csv_rows = _reopen_csv(last_path)
            csv_part = len(existing_csvs)
        else:
            csv_f, csv_w, _, csv_part = _new_csv(symbol)
            csv_rows = 0
    else:
        csv_f, csv_w, _, csv_part = _new_csv(symbol)
        csv_rows = 0

    try:
        for start_blk, end_blk, logs in fetch_contract_logs(addr, from_block, to_block=to_block):

            # ── 解析 log ──────────────────────────────────
            raw_records, tx_hashes = [], []
            for lg in logs:
                topics = lg.get("topics", [])
                if len(topics) < 3:
                    continue
                try:
                    frm = "0x" + topics[1][-40:]
                    to  = "0x" + topics[2][-40:]
                except Exception:
                    continue
                data = lg.get("data", "0x") or "0x"
                try:
                    val_raw = int(data, 16)
                except Exception:
                    val_raw = 0

                h   = lg.get("transactionHash", "").lower()
                idx = safe_int(lg.get("logIndex", 0))
                blk = safe_int(lg.get("blockNumber", 0))
                ts  = safe_int(lg.get("timeStamp",  0))

                tx_hashes.append(h)
                raw_records.append({
                    "tx_hash":       h,
                    "log_index":     idx,
                    "block_number":  blk,
                    "ts":            ts,
                    "from_addr":     frm.lower(),
                    "to_addr":       to.lower(),
                    "value_raw":     str(val_raw),
                    "token_symbol":  symbol,
                    "token_decimal": decimal,
                    "method_id":     "0x",
                    "method":        "",
                    "function_name": "",
                    "topo_tags":     [],
                })

            if not raw_records:
                continue

            # ── method 补充（v7逻辑：eth_getTransactionByHash + txlist）
            unique_hashes = list(set(tx_hashes))
            method_map    = fetch_methods_batch(unique_hashes, conn)

            for rec in raw_records:
                m = method_map.get(rec["tx_hash"])
                if m:
                    rec["method_id"], rec["method"], rec["function_name"] = m[0], m[1], m[2]
                else:
                    rec["method_id"] = "0xa9059cbb"
                    rec["method"]    = "transfer"

            # ── 写 DB ──────────────────────────────────────
            ins, sk = save_records(conn, raw_records)
            total_logs += len(raw_records)
            total_ins  += ins
            last_saved_block = end_blk

            # ── 写 CSV（自动分片）──────────────────────────
            for rec in raw_records:
                if csv_rows >= CSV_CHUNK:
                    csv_f.flush(); csv_f.close()
                    csv_f, csv_w, _, csv_part = _new_csv(symbol)
                    csv_rows = 0

                ts_val = rec["ts"]
                dt     = datetime.utcfromtimestamp(ts_val).strftime("%Y-%m-%d %H:%M:%S") if ts_val else ""
                try:
                    amount = int(rec["value_raw"]) / (10 ** (decimal or 18))
                except Exception:
                    amount = rec["value_raw"]

                csv_w.writerow([
                    rec["tx_hash"], rec["block_number"], dt,
                    rec["from_addr"], rec["to_addr"], amount, symbol,
                    rec["method_id"], rec["method"], rec["function_name"],
                ])
                csv_rows += 1

            csv_f.flush()
            set_progress(conn, addr, symbol, "running", last_saved_block, total_logs, total_ins)
            print(f"      block {start_blk:,}-{end_blk:,} | +{ins} DB | CSV第{csv_part}片{csv_rows:,}行 | 累计{total_logs:,}条")

        csv_f.flush(); csv_f.close()
        set_progress(conn, addr, symbol, "done", last_saved_block, total_logs, total_ins)
        print(f"  ✅ {symbol} 完成  共 {total_logs:,} 条")

    except KeyboardInterrupt:
        csv_f.flush(); csv_f.close()
        set_progress(conn, addr, symbol, "pending", last_saved_block, total_logs, total_ins)
        print(f"\n  ⏸  中断，已保存到 block {last_saved_block:,}")
        raise

    except Exception as e:
        csv_f.flush(); csv_f.close()
        import traceback
        set_progress(conn, addr, symbol, "error", last_saved_block, total_logs, total_ins, str(e))
        print(f"  ❌ {symbol} 错误: {e}")
        traceback.print_exc()


# ============================================================
# CLI
# ============================================================

def cmd_status(conn):
    c = conn.cursor()
    c.execute("""
        SELECT token_symbol, contract_addr, status, last_block,
               total_logs, total_inserted, updated_at
        FROM contract_progress ORDER BY updated_at DESC
    """)
    rows = c.fetchall()
    if not rows:
        print("  还没有采集记录"); return
    ICON = {"done": "✅", "running": "🔄", "pending": "⏸ ", "error": "❌"}
    print(f"\n  {'Token':<8} {'合约':<44} {'状态':<8} {'断点块':>10} {'总条数':>10}  时间")
    print(f"  {'─'*90}")
    for sym, addr, status, blk, logs, ins, upd in rows:
        ts = datetime.fromtimestamp(upd).strftime("%m/%d %H:%M") if upd else "—"
        print(f"  {sym:<8} {addr:<44} {ICON.get(status,'?')} {status:<6} {blk or 0:>10,} {logs or 0:>10,}  {ts}")
    c.execute("SELECT COUNT(*), COUNT(DISTINCT token_symbol) FROM transactions")
    total, syms = c.fetchone()
    print(f"\n  DB 总记录: {total:,} 条  |  币种: {syms} 个")


def cmd_export(conn, sym):
    c = conn.cursor()
    c.execute("""
        SELECT tx_hash, block_number, ts, from_addr, to_addr,
               value_raw, token_symbol, token_decimal, method_id, method, function_name
        FROM transactions WHERE token_symbol=? ORDER BY block_number ASC
    """, (sym.upper(),))
    rows = c.fetchall()
    if not rows:
        print(f"  没有 {sym} 的数据"); return
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    path   = f"export_{sym}_{ts_str}.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)
        for h, blk, ts_val, frm, to, val_raw, sym2, dec, mid, meth, fn in rows:
            dt = datetime.utcfromtimestamp(ts_val).strftime("%Y-%m-%d %H:%M:%S") if ts_val else ""
            try:
                amount = int(val_raw) / (10 ** (dec or 18))
            except Exception:
                amount = val_raw
            writer.writerow([h, blk, dt, frm, to, amount, sym2, mid, meth, fn])
    print(f"  ✅ 导出 {len(rows):,} 条 → {path}")


def main():
    parser = argparse.ArgumentParser(description="按 Token 合约全量采集 Transfer（断点续跑）")
    parser.add_argument("--token",    nargs="*", metavar="SYM",  help="Token 名称，如 USDT USDC")
    parser.add_argument("--contract", nargs="*", metavar="ADDR", help="直接填合约地址")
    parser.add_argument("--resume",   action="store_true",       help="续跑 pending/error")
    parser.add_argument("--status",   action="store_true",       help="查看采集进度")
    parser.add_argument("--export",   metavar="SYM",             help="从DB导出 CSV")
    parser.add_argument("--force",    action="store_true",       help="强制重采（忽略断点）")
    parser.add_argument("--db",       default=None,              help="指定 DB 路径")
    args = parser.parse_args()

    conn = init_db(args.db or DB_PATH)
    print(f"\n{'═'*55}")
    print(f"  LucidAML fetch.py  (合约全量采集)")
    print(f"  DB: {args.db or DB_PATH}")
    print(f"{'═'*55}")

    if args.status:  cmd_status(conn); return
    if args.export:  cmd_export(conn, args.export); return

    to_collect = []
    if args.resume:
        c = conn.cursor()
        c.execute("SELECT contract_addr, token_symbol FROM contract_progress WHERE status IN ('pending','error')")
        for addr, sym in c.fetchall():
            info = TOKEN_CONTRACTS.get(sym, {})
            to_collect.append((addr, sym, info.get("decimal", 18)))
    elif args.contract:
        for addr in args.contract:
            sym = next((s for s, v in TOKEN_CONTRACTS.items() if v["address"].lower() == addr.lower()), addr[:8])
            to_collect.append((addr.lower(), sym, TOKEN_CONTRACTS.get(sym, {}).get("decimal", 18)))
    elif args.token:
        for sym in args.token:
            sym = sym.upper()
            if sym not in TOKEN_CONTRACTS:
                print(f"  ❌ 未知 Token: {sym}，支持: {', '.join(TOKEN_CONTRACTS)}")
                continue
            info = TOKEN_CONTRACTS[sym]
            to_collect.append((info["address"], sym, info["decimal"]))
    else:
        for sym, info in TOKEN_CONTRACTS.items():
            to_collect.append((info["address"], sym, info["decimal"]))

    if not to_collect:
        parser.print_help(); return

    def date_to_block(date_str, is_end=False):
        from datetime import datetime, timezone, timedelta
        dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if is_end:
            dt = dt + timedelta(days=1) - timedelta(seconds=1)
        ts  = int(dt.timestamp())
        res = _get({"module": "block", "action": "getblocknobytime",
                    "timestamp": str(ts), "closest": "before" if is_end else "after"})
        result = res.get("result", "")
        if isinstance(result, str) and result.isdigit():
            return int(result)
        return 0 if not is_end else 22500000

    print(f"  日期: {FROM_DATE} → {TO_DATE}")
    fb = date_to_block(FROM_DATE, is_end=False)
    tb = date_to_block(TO_DATE,   is_end=True)
    print(f"  块号: {fb:,} → {tb:,}")
    print(f"  待采集: {len(to_collect)} 个合约")

    try:
        for addr, sym, dec in to_collect:
            print(f"\n  {'─'*52}")
            collect_contract(addr, sym, dec, conn, force=args.force,
                             from_block_override=fb, to_block=tb)
    except KeyboardInterrupt:
        print("\n\n  ⏸  中断，下次 --resume 继续")

    print(f"\n{'═'*55}")
    conn.close()


if __name__ == "__main__":
    main()
