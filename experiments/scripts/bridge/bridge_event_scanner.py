#!/usr/bin/env python3
"""
跨链桥事件扫描器 — 基于 getLogs + indexed topic filter
=========================================================

解决核心痛点：
  txlist 只能查 EOA 主动发起的交易，遇到合约地址就断了。
  getLogs 直接查桥合约事件，用 indexed topic filter 定位特定发送方。

原理：
  桥合约 emit 事件时，depositor/sender 通常是 indexed 参数，
  被编码进 topic[1~3]。Etherscan getLogs 支持按 topic 精确过滤，
  因此无需 txlist，直接从事件日志里找到该地址所有的跨链事件。

额外优势：
  - 可以发现通过 DeFi 聚合器 / 路由合约间接发起的跨链
  - 对合约地址（中间跳）同样有效

支持桥：
  Celer cBridge v2 / Across v3+v2 / Stargate (Pool Swap) / Wormhole

用法：
  python bridge_event_scanner.py <address>
  python bridge_event_scanner.py <address> --from-block 18000000 --to-block 19000000
  python bridge_event_scanner.py <address> --output result.json
"""

import os
import time
import json
import requests
from typing import Optional, Dict, List, Callable
from dotenv import load_dotenv

load_dotenv()

# ==================== CONFIG ====================
ETHERSCAN_API = "https://api.etherscan.io/v2/api"
API_KEY = os.getenv("ETHERSCAN_API_KEY", "")

REQUEST_INTERVAL = 0.22   # 请求间隔（秒）
DEFAULT_STEP     = 2000   # getLogs 每次查询的 block 跨度


# ==================== 地址格式转换 ====================

def addr_to_topic(addr: str) -> str:
    """
    地址转 topic 格式（32 字节，左补零）
    "0xABC..." → "0x000...000ABC..."
    """
    return "0x" + addr.lower().replace("0x", "").zfill(64)


def topic_to_addr(topic: str) -> str:
    """从 topic 中提取 20 字节地址（取末40位）"""
    return "0x" + topic.lower()[-40:]


# ==================== Etherscan getLogs 封装 ====================

def _get(params: dict, retry: int = 5) -> dict:
    """带重试的 Etherscan API GET"""
    params = {"chainid": "1", **params}
    for i in range(retry):
        try:
            r = requests.get(ETHERSCAN_API, params=params, timeout=30)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        time.sleep(0.5 * (1.5 ** i))
    return {}


def fetch_logs(
    contract: str,
    topic0: str,
    from_block: int,
    to_block: int,
    topic1: Optional[str] = None,
    topic2: Optional[str] = None,
    topic3: Optional[str] = None,
    step: int = DEFAULT_STEP,
) -> List[dict]:
    """
    分块查询 getLogs，自动处理 1000 条上限（缩小 step 重试）。

    topic1/2/3 都用 AND 关系。空 topic 视为通配符（不过滤）。

    为什么分块：
      Etherscan getLogs 单次请求最多返回 1000 条，超出则需缩小 block 范围重查。
      这里用自适应 step 处理高频桥合约（如大型 Stargate Pool）。
    """
    results = []
    cur = from_block
    while cur <= to_block:
        end = min(cur + step - 1, to_block)

        params: dict = {
            "module":    "logs",
            "action":    "getLogs",
            "address":   contract,
            "fromBlock": str(cur),
            "toBlock":   str(end),
            "topic0":    topic0,
            "apikey":    API_KEY,
        }
        # 只有用到了 topic N，才需要声明相邻的 operator
        # Etherscan: 空 topic = 通配符，operators 控制 AND/OR
        if topic1:
            params["topic0_1_opr"] = "and"
            params["topic1"] = topic1
        if topic2:
            params.setdefault("topic0_1_opr", "and")
            params["topic1_2_opr"] = "and"
            params["topic2"] = topic2
        if topic3:
            params.setdefault("topic0_1_opr", "and")
            params.setdefault("topic1_2_opr", "and")
            params["topic2_3_opr"] = "and"
            params["topic3"] = topic3

        data = _get(params)
        res = data.get("result", [])

        if isinstance(res, str):
            # API 返回错误字符串（如 rate limit / no records）
            if "no records" not in res.lower():
                print(f"    API 错误: {res}")
            cur = end + 1
            time.sleep(REQUEST_INTERVAL)
            continue

        if len(res) >= 1000:
            # 触及上限，缩小 step 重试（不推进 cur）
            step = max(step // 2, 100)
            print(f"    ⚠ 触及1000条上限，缩小 step → {step}")
            continue

        if res:
            print(f"    getLogs blocks {cur:,}–{end:,}: {len(res)} 条")
            results.extend(res)

        cur = end + 1
        time.sleep(REQUEST_INTERVAL)

    return results


# ==================== 各桥事件解码器 ====================

def _chunks(data: bytes, size: int = 32) -> List[bytes]:
    return [data[i:i+size] for i in range(0, len(data), size)]


def decode_across_v3(log: dict) -> Optional[Dict]:
    """
    Across v3 SpokePool — V3FundsDeposited 事件

    事件签名（keccak256 topic0）：
      V3FundsDeposited(address inputToken, address outputToken,
                       uint256 inputAmount, uint256 outputAmount,
                       uint256 indexed destinationChainId,
                       uint32 indexed depositId,
                       uint32 quoteTimestamp, uint32 fillDeadline,
                       uint32 exclusivityDeadline,
                       address indexed depositor,
                       address recipient,
                       address exclusiveRelayer,
                       bytes message)

    topics:  [sig, destinationChainId, depositId, depositor]
    data:    inputToken(32) + outputToken(32) + inputAmount(32) + outputAmount(32)
           + quoteTimestamp(32) + fillDeadline(32) + exclusivityDeadline(32)
           + recipient(32) + exclusiveRelayer(32) + message_offset(32) + ...
    """
    try:
        topics = log.get("topics", [])
        raw    = log.get("data", "0x")[2:]
        c      = _chunks(bytes.fromhex(raw)) if raw else []

        dst_chain_id = int(topics[1], 16)           if len(topics) > 1 else 0
        depositor    = topic_to_addr(topics[3])     if len(topics) > 3 else "unknown"
        recipient    = topic_to_addr("0x" + c[7].hex()) if len(c) > 7 else "需手动查"

        input_token  = topic_to_addr("0x" + c[0].hex()) if len(c) > 0 else "?"
        output_token = topic_to_addr("0x" + c[1].hex()) if len(c) > 1 else "?"
        input_amount = int.from_bytes(c[2], "big")       if len(c) > 2 else 0

        return {
            "bridge":        "Across Protocol v3",
            "tx_hash":       log.get("transactionHash", ""),
            "block":         int(log.get("blockNumber", "0x0"), 16),
            "depositor":     depositor,
            "dst_chain_id":  dst_chain_id,
            "dst_address":   recipient,
            "input_token":   input_token,
            "output_token":  output_token,
            "input_amount":  input_amount,
            # 简单猜测精度（USDC/USDT=6位，WETH=18位）
            "amount_display": (
                f"{input_amount / 1e6:.2f} USDC/USDT"
                if 1e4 < input_amount < 1e15 else str(input_amount)
            ),
        }
    except Exception as e:
        print(f"    [Across] 解码失败: {e}")
        return None


def decode_celer(log: dict) -> Optional[Dict]:
    """
    Celer cBridge v2 — Send 事件

    事件签名：
      Send(bytes32 indexed transferId,
           address indexed sender,
           address indexed receiver,
           address token, uint256 amount,
           uint64 dstChainId, uint64 nonce, uint32 maxSlippage)

    topics:  [sig, transferId, sender, receiver]
    data:    token(32) + amount(32) + dstChainId(32) + nonce(32) + maxSlippage(32)

    注意：cross_chain_tracer.py 里的 CelerTracer 把 topics[2] 误读为 token，
          实际上 topics[2]=sender（indexed），token 在 data 里。
    """
    try:
        topics = log.get("topics", [])
        raw    = log.get("data", "0x")[2:]
        c      = _chunks(bytes.fromhex(raw)) if raw else []

        sender       = topic_to_addr(topics[2]) if len(topics) > 2 else "unknown"
        receiver     = topic_to_addr(topics[3]) if len(topics) > 3 else "unknown"
        token        = topic_to_addr("0x" + c[0].hex()) if len(c) > 0 else "?"
        amount       = int.from_bytes(c[1], "big")       if len(c) > 1 else 0
        # dstChainId 是 uint64，ABI 编码填充成 32 bytes
        dst_chain_id = int.from_bytes(c[2], "big")       if len(c) > 2 else 0

        return {
            "bridge":        "Celer cBridge v2",
            "tx_hash":       log.get("transactionHash", ""),
            "block":         int(log.get("blockNumber", "0x0"), 16),
            "sender":        sender,
            "dst_chain_id":  dst_chain_id,
            "dst_address":   receiver,
            "token":         token,
            "amount":        amount,
            "amount_display": f"{amount / 1e18:.6f} ETH" if amount > 1e12 else f"{amount / 1e6:.2f} USDT",
        }
    except Exception as e:
        print(f"    [Celer] 解码失败: {e}")
        return None


def decode_stargate_pool(log: dict) -> Optional[Dict]:
    """
    Stargate Pool — Swap 事件

    事件签名：
      Swap(uint16 indexed chainId, uint256 indexed dstPoolId,
           address indexed from,
           uint256 amountSD, uint256 eqReward, uint256 eqFee,
           uint256 protocolFee, uint256 lpFee)

    topics:  [sig, chainId, dstPoolId, from(sender)]
    data:    amountSD(32) + eqReward(32) + eqFee(32) + protocolFee(32) + lpFee(32)

    局限：Pool 事件不包含目标地址（to），to 地址编码在 Router calldata 里。
          发现事件后，建议再用 cross_chain_tracer.StargateTracer 解析 tx calldata 取 to。
    """
    try:
        topics = log.get("topics", [])
        raw    = log.get("data", "0x")[2:]
        c      = _chunks(bytes.fromhex(raw)) if raw else []

        dst_chain_id = int(topics[1], 16)           if len(topics) > 1 else 0
        sender       = topic_to_addr(topics[3])     if len(topics) > 3 else "unknown"
        amount_sd    = int.from_bytes(c[0], "big")  if len(c) > 0 else 0

        return {
            "bridge":        "Stargate Finance (Pool)",
            "tx_hash":       log.get("transactionHash", ""),
            "block":         int(log.get("blockNumber", "0x0"), 16),
            "sender":        sender,
            "dst_chain_id":  dst_chain_id,
            "dst_address":   "见 tx calldata（Pool 事件不含目标地址）",
            "amount_sd":     amount_sd,
            "amount_display": str(amount_sd),
            "note":          "目标地址需用 cross_chain_tracer.StargateTracer 解析 tx calldata",
        }
    except Exception as e:
        print(f"    [Stargate] 解码失败: {e}")
        return None


def decode_wormhole(log: dict) -> Optional[Dict]:
    """
    Wormhole Core Bridge — LogMessagePublished 事件

    事件签名：
      LogMessagePublished(address indexed sender,
                          uint64 sequence, uint32 nonce,
                          bytes payload, uint8 consistencyLevel)

    topics:  [sig, sender]
    data:    sequence(32) + nonce(32) + payload_offset(32) + consistencyLevel(32) + payload...

    目标链 / 接收地址编码在 payload 里，需进一步解析 VAA payload。
    建议拿到 sequence 后调用 Wormhole Guardian API 查完整 VAA。
    """
    try:
        topics   = log.get("topics", [])
        raw      = log.get("data", "0x")[2:]
        c        = _chunks(bytes.fromhex(raw)) if raw else []

        sender   = topic_to_addr(topics[1]) if len(topics) > 1 else "unknown"
        sequence = int.from_bytes(c[0], "big") if len(c) > 0 else 0
        nonce    = int.from_bytes(c[1], "big") if len(c) > 1 else 0

        # payload 在 data 后半段，跳过 offset 字段
        payload_hex = ""
        if len(c) > 4:
            payload_hex = b"".join(c[4:]).hex()

        return {
            "bridge":      "Wormhole Core Bridge",
            "tx_hash":     log.get("transactionHash", ""),
            "block":       int(log.get("blockNumber", "0x0"), 16),
            "sender":      sender,
            "sequence":    sequence,
            "nonce":       nonce,
            "payload_hex": payload_hex[:64] + "..." if len(payload_hex) > 64 else payload_hex,
            "dst_chain_id":  "见 payload（需解析 VAA）",
            "dst_address":   "见 payload（需解析 VAA）",
            "note":        f"Wormhole sequence={sequence}，可用 https://api.wormholescan.io/api/v1/transactions/{log.get('transactionHash','')} 查询完整目标信息",
        }
    except Exception as e:
        print(f"    [Wormhole] 解码失败: {e}")
        return None


# ==================== 链 ID → 链名映射 ====================
CHAIN_ID_NAME: Dict[int, str] = {
    # 标准 EVM chain ID
    1:       "ethereum",
    10:      "optimism",
    56:      "bsc",
    100:     "gnosis",
    137:     "polygon",
    8453:    "base",
    42161:   "arbitrum",
    43114:   "avalanche",
    59144:   "linea",
    534352:  "scroll",
    # LayerZero / Stargate 使用自己的 chain ID 体系
    101:     "bsc",
    106:     "avalanche",
    109:     "polygon",
    110:     "arbitrum",
    111:     "optimism",
    184:     "base",
    214:     "tron",
    230:     "tron",
}


def chain_id_to_name(chain_id) -> str:
    try:
        return CHAIN_ID_NAME.get(int(chain_id), f"chain_{chain_id}")
    except Exception:
        return str(chain_id)


# ==================== 桥扫描配置表 ====================
# 每条记录：
#   name           : 桥名称（显示用）
#   contract       : 桥合约地址（ETH 主网）
#   topic0         : 事件 keccak256 哈希
#   sender_topic   : sender/depositor 在哪个 topic index（1/2/3）
#   decoder        : 解码函数
#
# sender_topic 决定了用哪个 topicN 过滤：
#   topic[1] → Wormhole sender
#   topic[2] → Celer sender
#   topic[3] → Across depositor / Stargate from
BRIDGE_SCAN_CONFIGS: List[Dict] = [
    # ---------- Celer cBridge ----------
    {
        "name":         "Celer cBridge v2",
        "contract":     "0x5427fefa711eff984124bfbb1ab6fbf5e3da1820",
        # keccak256("Send(bytes32,address,address,address,uint256,uint64,uint64,uint32)")
        "topic0":       "0x89d8051e597ab4178a863a5190407b98abfeff406aa8db90c59af76612e58f01",
        "sender_topic": 2,   # topic[2] = sender (indexed)
        "decoder":      decode_celer,
    },
    # ---------- Across Protocol ----------
    {
        "name":         "Across Protocol v3 SpokePool",
        "contract":     "0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5",
        # keccak256("V3FundsDeposited(address,address,uint256,uint256,uint256,uint32,uint32,uint32,uint32,address,address,address,bytes)")
        "topic0":       "0xa123dc29aebf7d0c3322c8eeb5b999e859f39937950ed31056532713d0de396f",
        "sender_topic": 3,   # topic[3] = depositor (indexed)
        "decoder":      decode_across_v3,
    },
    {
        "name":         "Across Protocol v2",
        "contract":     "0x4d9079bb4165aeb4084c526a32695dcfd2f77381",
        "topic0":       "0xa123dc29aebf7d0c3322c8eeb5b999e859f39937950ed31056532713d0de396f",
        "sender_topic": 3,
        "decoder":      decode_across_v3,
    },
    # ---------- Stargate Finance (Pool 合约，按资产分) ----------
    # Pool 事件含发送方和目标链，但不含目标地址（需解析 calldata）
    {
        "name":         "Stargate USDT Pool",
        "contract":     "0x38ea452219524bb87e18de1c24d3bb59954a1042",
        # keccak256("Swap(uint16,uint256,address,uint256,uint256,uint256,uint256,uint256)")
        "topic0":       "0x34660fc8af304464529f48a778e03d03e4d34bcd5f9b6f0cfbf3cd238c642f7f",
        "sender_topic": 3,   # topic[3] = from (indexed)
        "decoder":      decode_stargate_pool,
    },
    {
        "name":         "Stargate USDC Pool",
        "contract":     "0xdf0770df86a8034b3efef0a1bb3c889b8332ff56",
        "topic0":       "0x34660fc8af304464529f48a778e03d03e4d34bcd5f9b6f0cfbf3cd238c642f7f",
        "sender_topic": 3,
        "decoder":      decode_stargate_pool,
    },
    {
        "name":         "Stargate ETH Pool",
        "contract":     "0x101816545f6bd2b1076434b54383a1e633390a2e",
        "topic0":       "0x34660fc8af304464529f48a778e03d03e4d34bcd5f9b6f0cfbf3cd238c642f7f",
        "sender_topic": 3,
        "decoder":      decode_stargate_pool,
    },
    # ---------- Wormhole ----------
    {
        "name":         "Wormhole Core Bridge",
        "contract":     "0x98f3c9e6e3face36baad05fe09d375ef1464288b",
        # keccak256("LogMessagePublished(address,uint64,uint32,bytes,uint8)")
        "topic0":       "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2",
        "sender_topic": 1,   # topic[1] = sender (indexed)
        "decoder":      decode_wormhole,
    },
]


# ==================== 辅助：获取地址的活跃 block 范围 ====================

def get_block_range(address: str) -> tuple:
    """
    用 txlist 快速获取地址的第一笔和最后一笔交易 block，
    以此确定 getLogs 的扫描范围，避免扫全链。
    """
    def _latest_block() -> int:
        r = _get({"module": "proxy", "action": "eth_blockNumber", "apikey": API_KEY})
        try:
            return int(r.get("result", "0x0"), 16)
        except Exception:
            return 20_000_000

    try:
        r1 = _get({
            "module": "account", "action": "txlist",
            "address": address, "sort": "asc",
            "offset": 1, "page": 1, "apikey": API_KEY,
        })
        first_txs = r1.get("result", [])
        first_block = int(first_txs[0].get("blockNumber", 0)) if first_txs and isinstance(first_txs, list) else 0

        r2 = _get({
            "module": "account", "action": "txlist",
            "address": address, "sort": "desc",
            "offset": 1, "page": 1, "apikey": API_KEY,
        })
        last_txs = r2.get("result", [])
        last_block = int(last_txs[0].get("blockNumber", 0)) if last_txs and isinstance(last_txs, list) else 0
        if last_block == 0:
            last_block = _latest_block()

        return first_block, last_block
    except Exception:
        return 0, _latest_block()


# ==================== 主扫描函数 ====================

def scan_bridge_events(
    address: str,
    from_block: Optional[int] = None,
    to_block: Optional[int] = None,
) -> List[Dict]:
    """
    给定 EOA 或合约地址，扫描它在所有已注册桥上的出账跨链事件。

    比 txlist 方式的优势：
      1. 对合约地址有效（txlist 对合约基本无用）
      2. 能捕获通过聚合器/路由间接触发的跨链
      3. 不受 txlist 10000 条分页限制

    参数：
      address     : 要追踪的地址
      from_block  : 起始 block（None = 自动从第一笔 tx 推断）
      to_block    : 结束 block（None = 自动到最新 block）

    返回：
      List[Dict]，每条记录含 bridge / tx_hash / block /
                               sender / dst_chain_id / dst_chain / dst_address / amount 等
    """
    address = address.lower()

    if from_block is None or to_block is None:
        print(f"[*] 检测 {address} 的活跃 block 范围...")
        fb, tb = get_block_range(address)
        from_block = from_block if from_block is not None else fb
        to_block   = to_block   if to_block   is not None else tb
        print(f"    活跃范围: block {from_block:,} → {to_block:,}")

    print(f"\n[*] 开始扫描，共 {len(BRIDGE_SCAN_CONFIGS)} 个桥合约\n")

    all_events: List[Dict] = []
    addr_topic = addr_to_topic(address)

    for cfg in BRIDGE_SCAN_CONFIGS:
        name         = cfg["name"]
        contract     = cfg["contract"]
        topic0       = cfg["topic0"]
        sender_idx   = cfg["sender_topic"]
        decoder: Callable = cfg["decoder"]

        print(f"  [{name}]")

        # 根据 sender 所在 topic index 确定过滤参数
        t1 = t2 = t3 = None
        if sender_idx == 1:
            t1 = addr_topic
        elif sender_idx == 2:
            t2 = addr_topic
        elif sender_idx == 3:
            t3 = addr_topic

        logs = fetch_logs(
            contract=contract, topic0=topic0,
            from_block=from_block, to_block=to_block,
            topic1=t1, topic2=t2, topic3=t3,
        )

        for log in logs:
            decoded = decoder(log)
            if decoded:
                decoded["dst_chain"] = chain_id_to_name(decoded.get("dst_chain_id", 0))
                all_events.append(decoded)

        time.sleep(0.3)

    return all_events


# ==================== 输出格式化 ====================

def print_events(events: List[Dict]):
    if not events:
        print("\n  未发现跨链桥事件")
        return

    events_sorted = sorted(events, key=lambda x: x.get("block", 0))
    print(f"\n{'='*70}")
    print(f"共发现 {len(events_sorted)} 笔跨链事件")
    print(f"{'='*70}")

    for ev in events_sorted:
        print(f"\n  桥:       {ev.get('bridge', '?')}")
        print(f"  Block:    {ev.get('block', '?'):,}")
        dst_chain = ev.get("dst_chain", "?")
        dst_id    = ev.get("dst_chain_id", "?")
        print(f"  目标链:   {dst_chain}  (chain_id={dst_id})")
        print(f"  目标地址: {ev.get('dst_address', '?')}")
        if ev.get("amount_display"):
            print(f"  金额:     {ev['amount_display']}")
        if ev.get("depositor"):
            print(f"  存款方:   {ev['depositor']}")
        if ev.get("sender") and ev.get("sender") != ev.get("depositor"):
            print(f"  发送方:   {ev['sender']}")
        print(f"  TX Hash:  {ev.get('tx_hash', '?')}")
        if ev.get("note"):
            print(f"  提示:     {ev['note']}")
        print(f"  {'─'*60}")


# ==================== CLI ====================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="跨链桥事件扫描器（getLogs + indexed topic filter）"
    )
    parser.add_argument("address",      help="要扫描的 EOA 或合约地址")
    parser.add_argument("--from-block", type=int, default=None, help="起始 block（默认自动检测）")
    parser.add_argument("--to-block",   type=int, default=None, help="结束 block（默认最新）")
    parser.add_argument("--output",     default=None,           help="结果保存文件（JSON）")
    args = parser.parse_args()

    events = scan_bridge_events(
        args.address,
        from_block=args.from_block,
        to_block=args.to_block,
    )

    print_events(events)

    if events:
        out_file = args.output or f"bridge_events_{args.address[:10]}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(events, f, ensure_ascii=False, indent=2)
        print(f"\n结果已保存: {out_file}")
