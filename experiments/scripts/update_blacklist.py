#!/usr/bin/env python3
"""
update_blacklist.py — 增量更新 USDT 黑名单 (ETH) + OFAC SDN

直接跑: python3 experiments/scripts/update_blacklist.py
"""

import os, csv, json, time, re
import urllib.request
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

BLACKLIST_CSV = PROJECT_ROOT / "data" / "blacklists" / "usdt_blacklist.csv"
OFAC_JSON     = PROJECT_ROOT / "src" / "cripto_analyst" / "threat_intel" / "ofac_sanctioned.json"

USDT_ETH = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
ETH_API  = "https://api.etherscan.io/v2/api"
OFAC_URL = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN_ADVANCED.XML"

TOPIC_ADD    = "0x42e160154868087d6bfdc0ca23d96a1c1cfa32f1b72ba9ba27b69b98a0d819dc"
TOPIC_REMOVE = "0xd7e9ec6e6ecd65492dce6bf513cd6867560d49544421d0783ddf06e76c24470c"

CHUNK = 5000   # blocks per getLogs request (safe for free tier)

API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
if not API_KEY:
    raise SystemExit("ERROR: ETHERSCAN_API_KEY not set")


# ── HTTP ──────────────────────────────────────────────────────────────────────

def _get(url: str, timeout: int = 20) -> dict:
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "travis/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except Exception as e:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)

def _get_raw(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "travis/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# ── Etherscan helpers ─────────────────────────────────────────────────────────

def current_block() -> int:
    d = _get(f"{ETH_API}?chainid=1&module=proxy&action=eth_blockNumber&apikey={API_KEY}")
    return int(d["result"], 16)

def ts_to_block(ts: int) -> int:
    d = _get(f"{ETH_API}?chainid=1&module=block&action=getblocknobytime"
             f"&timestamp={ts}&closest=after&apikey={API_KEY}")
    return int(d["result"])

def addr_from_data(data: str) -> str:
    raw = data.replace("0x", "").replace("0X", "")
    return ("0x" + raw[-40:]) if len(raw) >= 40 else ""

def fetch_events(from_block: int, to_block: int, topic: str) -> list:
    results = []
    cur = from_block
    while cur <= to_block:
        end = min(cur + CHUNK - 1, to_block)
        pct = (cur - from_block) / max(1, to_block - from_block) * 100
        print(f"  blocks {cur:,}–{end:,}  ({pct:.0f}%)", end="\r", flush=True)
        url = (f"{ETH_API}?chainid=1&module=logs&action=getLogs"
               f"&address={USDT_ETH}&topic0={topic}"
               f"&fromBlock={cur}&toBlock={end}&page=1&offset=1000&apikey={API_KEY}")
        try:
            d = _get(url)
            for ev in (d.get("result") or []):
                addr = addr_from_data(ev.get("data", ""))
                if not addr or addr == "0x" + "0" * 40:
                    continue
                ts = int(ev.get("timeStamp", "0x0"), 16)
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                results.append({
                    "address": addr.lower(),
                    "time": dt.strftime("%Y-%m-%d %H:%M:%S.000 UTC"),
                })
        except Exception as e:
            print(f"\n  WARN chunk {cur}-{end}: {e}")
        cur = end + 1
        time.sleep(0.22)
    print()
    return results


# ── CSV I/O ───────────────────────────────────────────────────────────────────

def load_csv() -> dict:
    """Returns {addr_lower: time_str} for ETH entries only."""
    bl = {}
    if BLACKLIST_CSV.exists():
        for row in csv.DictReader(open(BLACKLIST_CSV, newline="")):
            if row.get("chain", "").lower() == "ethereum":
                bl[row["address"].lower()] = row["time"]
    return bl

def save_csv(bl: dict) -> None:
    rows = sorted(
        [{"address": a, "time": t, "chain": "ethereum"} for a, t in bl.items()],
        key=lambda r: r["time"], reverse=True
    )
    with open(BLACKLIST_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["address", "time", "chain"])
        w.writeheader()
        w.writerows(rows)


# ── OFAC ─────────────────────────────────────────────────────────────────────

_CRYPTO = {"XBT","ETH","XMR","LTC","ZEC","DASH","BTG","ETC","BCH","BSV",
           "USDT","TRX","USDC","BNB","XRP","DOGE","SOL","MATIC","ARB",
           "OP","TON","AVAX","LINK"}

def update_ofac() -> tuple:
    print("  Downloading OFAC SDN_ADVANCED.XML …", flush=True)
    xml = _get_raw(OFAC_URL).decode("utf-8", errors="replace")
    print(f"  Downloaded {len(xml):,} chars", flush=True)

    # FeatureTypeID → currency (e.g. ID 344 → "XBT", 345 → "ETH", 887 → "USDT")
    ft_currency = {}
    for m in re.finditer(
        r'<FeatureType ID="(\d+)"[^>]*>Digital Currency Address - ([^<]+)</FeatureType>', xml):
        currency = m.group(2).strip().upper()
        if currency in _CRYPTO:
            ft_currency[m.group(1)] = currency

    # IdentityID → party fixedRef
    identity_to_party = {}
    for m in re.finditer(
        r'<DistinctParty[^>]*\bfixedRef="([^"]+)"[^>]*>(.*?)</DistinctParty>',
        xml, re.DOTALL):
        for id_m in re.finditer(r'<Identity\s+ID="(\d+)"', m.group(2)):
            identity_to_party[id_m.group(1)] = m.group(1)

    # party fixedRef → primary name
    party_names = {}
    for m in re.finditer(
        r'<DistinctParty[^>]*\bfixedRef="([^"]+)"[^>]*>.*?<Alias[^>]*\bPrimary="true"[^>]*>.*?'
        r'<LastName[^>]*>([^<]+)</LastName>', xml, re.DOTALL):
        party_names[m.group(1)] = m.group(2).strip()

    result = {}
    for feat in re.finditer(r'<Feature\b([^>]*)>(.*?)</Feature>', xml, re.DOTALL):
        attrs, body = feat.group(1), feat.group(2)
        ft_id_m = re.search(r'FeatureTypeID="(\d+)"', attrs)
        if not ft_id_m:
            continue
        currency = ft_currency.get(ft_id_m.group(1))
        if not currency:
            continue
        addr_m = re.search(r'<VersionDetail[^>]*>([A-Za-z0-9]+)</VersionDetail>', body)
        if not addr_m:
            continue
        addr = addr_m.group(1).strip()
        if len(addr) < 20:
            continue
        entity = "Unknown"
        im = re.search(r'<IdentityReference\s+IdentityID="(\d+)"', body)
        if im:
            entity = party_names.get(identity_to_party.get(im.group(1), ""), "Unknown")
        result[addr.lower()] = {"currency": currency, "entity": entity, "source": "OFAC_SDN"}

    existing = {}
    if OFAC_JSON.exists():
        existing = {k.lower(): v for k, v in json.load(open(OFAC_JSON)).items()}

    added   = len(set(result) - set(existing))
    removed = len(set(existing) - set(result))
    OFAC_JSON.parent.mkdir(exist_ok=True)
    json.dump(result, open(OFAC_JSON, "w"), indent=2, ensure_ascii=False)
    return added, removed


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    bl = load_csv()
    print(f"Loaded {len(bl):,} existing ETH addresses")

    top_block = current_block()
    print(f"Current block: {top_block:,}")

    # Determine start block
    if bl:
        latest_ts = max(bl.values())
        ts_sec = int(datetime.strptime(
            latest_ts.replace(".000 UTC", ""), "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=timezone.utc).timestamp())
        from_block = ts_to_block(ts_sec)
        print(f"Resuming from block {from_block:,}  (after {latest_ts})")
    else:
        from_block = 4634749  # USDT deployment block
        print(f"Fresh scan from block {from_block:,}")

    added = removed = 0

    if from_block < top_block:
        print("Fetching AddedBlackList …")
        for ev in fetch_events(from_block, top_block, TOPIC_ADD):
            if ev["address"] not in bl:
                bl[ev["address"]] = ev["time"]
                added += 1

        print("Fetching RemovedBlackList …")
        for ev in fetch_events(from_block, top_block, TOPIC_REMOVE):
            if ev["address"] in bl:
                del bl[ev["address"]]
                removed += 1
    else:
        print("Already up-to-date.")

    print(f"ETH USDT: +{added} added, -{removed} removed → {len(bl):,} total")

    # Save ETH blacklist
    save_csv(bl)
    print(f"Saved {BLACKLIST_CSV.name}")

    # OFAC
    print("\nUpdating OFAC …")
    try:
        oa, or_ = update_ofac()
        print(f"OFAC: +{oa} added, -{or_} removed")
    except Exception as e:
        print(f"OFAC update failed: {e}")

    print(f"\nDone — {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"Total ETH blacklist: {len(bl):,} addresses")


if __name__ == "__main__":
    main()
