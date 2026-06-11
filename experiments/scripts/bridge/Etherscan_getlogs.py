import os
import requests
import time
from datetime import datetime, timezone
import pandas as pd
from collections import Counter
from dotenv import load_dotenv

load_dotenv()

# ========= CONFIG (edit here) =========
API_KEY    = os.getenv("ETHERSCAN_API_KEY", "")
POOL_ADDR  = "0x7858e59e0c01ea06df3af3d20ac7b0003275d4bf"  # Example: V3 USDC-USDT 0.05% pool
START_DATE = datetime(2023, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
END_DATE   = datetime(2023, 4, 1, 0, 0, 0, tzinfo=timezone.utc)

# Only used to label output filenames (does NOT affect L calculation)
T0_SYM, T1_SYM = "USDC", "USDT"

# ========= Constants & session =========
ETHERSCAN_API = "https://api.etherscan.io/api"
SESS = requests.Session()
SESS.headers.update({"User-Agent": "uniswap-v3-liquidity/1.1"})

# V3 event topic0
TOPIC_V3_SWAP = "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"
TOPIC_V3_MINT = "0x7a53080ba414158be7ec69b987b5fb7d07dee101fe85488f0853ae16239d0bde"
TOPIC_V3_BURN = "0x0c396cd989a39f4459b5fa1aed6a9a8dcdbc45908acfd67e028cd568da98982c"

# ========= Helpers =========
def _get(params, retry=8, base_sleep=0.25):
    for i in range(retry):
        try:
            r = SESS.get(ETHERSCAN_API, params=params, timeout=60)
            if r.status_code == 200:
                j = r.json()
                msg = j.get("message", "").lower()
                result = j.get("result", "")
                # rate limit 判断
                if "rate limit" in msg or (isinstance(result, str) and "rate" in result.lower()):
                    raise RuntimeError("rate limited")
                return j
        except Exception:
            pass
        time.sleep(base_sleep * (1.5 ** i))
    raise RuntimeError(f"HTTP failed after retries: {params}")

def ts_to_block(ts_dt: datetime, closest: str) -> int:
    ts = int(ts_dt.timestamp())
    j = _get({
        "module": "block", "action": "getblocknobytime",
        "timestamp": ts, "closest": closest, "apikey": API_KEY
    })
    return int(j.get("result"))

def chunks_64(d_no0x):
    return [d_no0x[i:i+64] for i in range(0, len(d_no0x), 64)]

def to_int_signed_256(hx: str) -> int:
    x = int(hx, 16)
    return x - (1 << 256) if x >= (1 << 255) else x

def safe_int_hex(x):
    if x is None:
        return 0
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        s = x.strip().lower()
        if s == "" or s == "0x":
            return 0
        if s.startswith("0x"):
            try:
                return int(s, 16)
            except Exception:
                return 0
        try:
            return int(s)
        except Exception:
            return 0
    try:
        return int(x)
    except Exception:
        return 0

def fetch_all_logs(address, start_block, end_block, step=5000):
    out = []
    cur = start_block
    while cur <= end_block:
        to_blk = min(cur + step, end_block)
        res = _get({
            "module": "logs", "action": "getLogs",
            "fromBlock": str(cur), "toBlock": str(to_blk),
            "address": address,
            "apikey": API_KEY
        }).get("result", [])

        # 触及1000条上限，缩小step重试
        if isinstance(res, list) and len(res) >= 1000:
            new_step = max(step // 2, 100)
            print(f"  ⚠️ 触及1000条上限 [{cur}-{to_blk}]，缩小step {step}→{new_step}")
            step = new_step
            continue

        if res:
            print(f"  logs {cur}-{to_blk}: {len(res)} 条")
            out.extend(res)

        cur = to_blk + 1
        time.sleep(0.22)
    return out

# ========= Recognizers (用 topic0 判断，不靠 data 结构) =========
def is_v3_mint(log) -> bool:
    return bool(log.get("topics")) and log["topics"][0].lower() == TOPIC_V3_MINT

def is_v3_burn(log) -> bool:
    return bool(log.get("topics")) and log["topics"][0].lower() == TOPIC_V3_BURN

def is_v3_swap(log) -> bool:
    return bool(log.get("topics")) and log["topics"][0].lower() == TOPIC_V3_SWAP

# ========= Decoders =========
def decode_v3_mint(log):
    d = log["data"][2:]; c = chunks_64(d)
    owner   = "0x" + log["topics"][1][-40:]
    tickLow = to_int_signed_256(log["topics"][2])
    tickHigh= to_int_signed_256(log["topics"][3])
    sender  = "0x" + c[0][-40:]
    amountL = int(c[1], 16)
    amount0 = int(c[2], 16)
    amount1 = int(c[3], 16)
    return {
        "event": "Mint", "sender": sender, "owner": owner,
        "tickLower": tickLow, "tickUpper": tickHigh,
        "amountL": amountL, "amount0": amount0, "amount1": amount1
    }

def decode_v3_burn(log):
    d = log["data"][2:]; c = chunks_64(d)
    owner   = "0x" + log["topics"][1][-40:]
    tickLow = to_int_signed_256(log["topics"][2])
    tickHigh= to_int_signed_256(log["topics"][3])
    amountL = int(c[0], 16)
    amount0 = int(c[1], 16)
    amount1 = int(c[2], 16)
    return {
        "event": "Burn", "owner": owner,
        "tickLower": tickLow, "tickUpper": tickHigh,
        "amountL": amountL, "amount0": amount0, "amount1": amount1
    }

def decode_v3_swap(log):
    d = log["data"][2:]; c = chunks_64(d)
    sender    = "0x" + log["topics"][1][-40:]
    recipient = "0x" + log["topics"][2][-40:]
    amount0   = to_int_signed_256(c[0])
    amount1   = to_int_signed_256(c[1])
    sqrtP     = int(c[2], 16)
    L         = int(c[3], 16)
    tick      = to_int_signed_256(c[4])
    return {
        "event": "Swap", "sender": sender, "recipient": recipient,
        "amount0": amount0, "amount1": amount1,
        "sqrtPriceX96": sqrtP, "liquidity": L, "tick": tick
    }

# ========= Liquidity reconstruction =========
def build_tick_deltas(mint_logs, burn_logs):
    delta = {}
    def add(t, v): delta[t] = delta.get(t, 0) + v

    for lg in mint_logs:
        rec = decode_v3_mint(lg)
        L = rec["amountL"]
        add(rec["tickLower"], +L)
        add(rec["tickUpper"], -L)

    for lg in burn_logs:
        rec = decode_v3_burn(lg)
        L = rec["amountL"]
        add(rec["tickLower"], -L)
        add(rec["tickUpper"], +L)

    if not delta:
        return [], [], {}

    ticks_sorted = sorted(delta.keys())
    cum = []
    run = 0
    for t in ticks_sorted:
        run += delta[t]
        cum.append(run)
    return ticks_sorted, cum, delta

# ========= Main =========
def main():
    # fix: START 用 after，END 用 before
    fb = ts_to_block(START_DATE, "after")
    tb = ts_to_block(END_DATE,   "before")
    print(f"== V3 window: {START_DATE} → {END_DATE} | blocks {fb}→{tb}")

    logs_all = fetch_all_logs(POOL_ADDR, fb, tb)
    if not logs_all:
        print("❌ 没有任何日志：检查池地址/时间窗")
        return

    topic0_counts = Counter([
        lg["topics"][0].lower() for lg in logs_all if lg.get("topics")
    ])
    print("topic0 seen:", dict(topic0_counts))

    mints = [lg for lg in logs_all if is_v3_mint(lg)]
    burns = [lg for lg in logs_all if is_v3_burn(lg)]
    swaps = [lg for lg in logs_all if is_v3_swap(lg)]
    print(f"Found Mint={len(mints)}, Burn={len(burns)}, Swap={len(swaps)}")

    def build_rows(logs, decoder):
        rows = []
        for lg in logs:
            ts  = safe_int_hex(lg.get("timeStamp"))
            rec = decoder(lg)
            rows.append({
                "blockNumber": safe_int_hex(lg.get("blockNumber")),
                "logIndex":    safe_int_hex(lg.get("logIndex")),
                "txHash":      lg.get("transactionHash", ""),
                "ts_utc":      datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                **rec
            })
        return rows

    rows = []
    rows.extend(build_rows(mints, decode_v3_mint))
    rows.extend(build_rows(burns, decode_v3_burn))
    rows.extend(build_rows(swaps, decode_v3_swap))

    if not rows:
        print("ℹ️ 时间窗内没有 Mint/Burn/Swap。")
        return

    COLS = [
        "blockNumber", "logIndex", "txHash", "ts_utc", "event",
        "sender", "recipient", "owner",
        "tick", "tickLower", "tickUpper",
        "amount0", "amount1", "amountL",
        "sqrtPriceX96", "liquidity"
    ]
    df = pd.DataFrame(rows)
    for c in COLS:
        if c not in df.columns:
            df[c] = pd.NA

    df["blockNumber"] = df["blockNumber"].apply(safe_int_hex)
    df["logIndex"]    = df["logIndex"].apply(safe_int_hex)

    df = df[COLS].sort_values(["blockNumber", "logIndex"]).reset_index(drop=True)

    outdir = os.path.join(os.path.expanduser("~"), "Desktop", "swap-pair")
    os.makedirs(outdir, exist_ok=True)
    suf = f"{START_DATE:%Y%m%d}_{END_DATE:%Y%m%d}"
    fn_events = os.path.join(outdir, f"V3_{T0_SYM}-{T1_SYM}_Events_{suf}.csv")
    df.to_csv(fn_events, index=False)
    print(f"✅ Events saved: {len(df)} → {fn_events}")

if __name__ == "__main__":
    main()
