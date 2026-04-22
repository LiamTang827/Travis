#!/usr/bin/env python3
"""
跨链桥追踪模块 - 连接两条链上的同一实体
核心问题：ETH 链上 Address A 调用桥 → Tron 链上 Address B 收款
         如何证明 A == B 的控制者？

方法：解析桥合约的事件日志，目标地址编码在 calldata 或 event 里
支持桥：Stargate / Orbiter Finance / Across / Hop / Celer / Wormhole
"""

import os
import time
import json
import hashlib
import requests
from typing import Optional, Dict, List
from dotenv import load_dotenv

load_dotenv()

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
BLOCKSCOUT_ETH   = "https://eth.blockscout.com/api"
TRON_API         = "https://apilist.tronscanapi.com/api"

# ==================== 链 ID 映射（LayerZero / Stargate）====================
LAYERZERO_CHAIN_ID = {
    1:    "ethereum",
    101:  "bsc",
    106:  "avalanche",
    109:  "polygon",
    110:  "arbitrum",
    111:  "optimism",
    112:  "fantom",
    125:  "celo",
    138:  "zkevm",
    145:  "gnosis",
    184:  "base",
    196:  "xlayer",
    230:  "tron",     # Stargate Tron
    214:  "tron",
}

# ==================== 事件签名 (keccak256 topic0)====================
# 可用 web3.keccak(text="EventName(types...)") 验证
BRIDGE_EVENT_TOPICS = {
    # Stargate
    "0x9fbf..." : "Stargate Swap",
    # Across v3
    "0x571749efd0..." : "Across V3FundsDeposited",
    # Hop
    "0xe9b39d8..." : "Hop TransferSent",
    # Celer
    "0x0493..." : "Celer Send",
    # Orbiter (无标准事件，识别方式不同)
}


# ==================== Base58 工具（Tron 地址转换）====================
_B58_ALPHA = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP   = {chr(_B58_ALPHA[i]): i for i in range(58)}

def hex_to_tron(hex_addr: str) -> str:
    clean = hex_addr.lower().replace("0x", "").replace("41", "", 1) if hex_addr.lower().replace("0x","").startswith("41") else hex_addr.lower().replace("0x","")
    raw = bytes.fromhex("41" + clean[-40:])
    cs  = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    num = int.from_bytes(raw + cs, "big")
    result = []
    while num > 0:
        num, r = divmod(num, 58)
        result.append(_B58_ALPHA[r:r+1])
    return b"".join(reversed(result)).decode()


def tron_to_hex(b58: str) -> Optional[str]:
    try:
        num = 0
        for c in b58:
            num = num * 58 + _B58_MAP[c]
        raw = num.to_bytes(25, "big")
        return "0x" + raw[1:21].hex()
    except Exception:
        return None


# ==================== 链上数据获取 ====================
def get_tx_input(tx_hash: str) -> Optional[str]:
    """获取交易 input data（calldata）"""
    r = requests.get(BLOCKSCOUT_ETH, params={
        "module": "proxy", "action": "eth_getTransactionByHash",
        "txhash": tx_hash,
    }, timeout=15)
    result = r.json().get("result") or {}
    return result.get("input")


def get_tx_logs(tx_hash: str) -> List[dict]:
    """获取交易的事件日志"""
    r = requests.get(BLOCKSCOUT_ETH, params={
        "module": "logs", "action": "getLogs",
        "txhash": tx_hash,
    }, timeout=15)
    result = r.json().get("result", [])
    return result if isinstance(result, list) else []


def get_logs_by_contract(contract: str, from_block: int, to_block: int, topic0: str) -> List[dict]:
    """按合约地址和事件 topic 查询日志"""
    r = requests.get(BLOCKSCOUT_ETH, params={
        "module": "logs", "action": "getLogs",
        "address": contract,
        "fromBlock": from_block,
        "toBlock": to_block,
        "topic0": topic0,
    }, timeout=15)
    result = r.json().get("result", [])
    return result if isinstance(result, list) else []


# ==================== 各桥解析逻辑 ====================

class BridgeTracer:
    """基类"""
    name = "Unknown"
    contract = ""

    def trace(self, tx_hash: str, sender: str) -> Optional[Dict]:
        """返回 {dst_chain, dst_address, amount, bridge}"""
        raise NotImplementedError


class StargateTracer(BridgeTracer):
    """
    Stargate Finance 追踪
    函数签名: swap(dstChainId, srcPoolId, dstPoolId, refundAddress, amountLD, minAmountLD, lzTxParams, to, payload)
    参数 to (bytes) = 目标链上的接收地址
    函数 selector: 0xbf4e5ad0 (Router.swap)
    """
    name = "Stargate Finance"
    SELECTOR = "0xbf4e5ad0"  # swap(uint16,uint256,uint256,address,uint256,uint256,(uint256,uint256,uint256),bytes,bytes)

    # Stargate 事件：Swap(uint16 chainId, uint256 dstPoolId, address from, ...)
    SWAP_TOPIC = "0x34660fc8af304464529f48a778e03d03e4d34bcd5f9b6f0cfbf3cd238c642f7"

    def trace(self, tx_hash: str, sender: str) -> Optional[Dict]:
        print(f"    [Stargate] 解析交易 {tx_hash[:20]}...")
        inp = get_tx_input(tx_hash)
        if not inp or not inp.startswith(self.SELECTOR):
            return None

        # calldata 布局（去掉4字节selector）:
        # offset 0:   dstChainId (uint16, padded 32 bytes)
        # offset 32:  srcPoolId
        # offset 64:  dstPoolId
        # offset 96:  refundAddress
        # offset 128: amountLD
        # offset 160: minAmountLD
        # offset 192: lzTxParams tuple offset
        # offset 224: to (bytes) offset
        # offset 256: payload (bytes) offset
        try:
            data = bytes.fromhex(inp[2:])  # 去掉 0x
            # selector = 4 bytes
            params = data[4:]

            dst_chain_id = int.from_bytes(params[0:32], "big")
            amount_ld    = int.from_bytes(params[128:160], "big")

            # 解析 `to` bytes 参数
            to_offset = int.from_bytes(params[224:256], "big")
            to_len    = int.from_bytes(params[to_offset:to_offset+32], "big")
            to_bytes  = params[to_offset+32:to_offset+32+to_len]

            dst_chain = LAYERZERO_CHAIN_ID.get(dst_chain_id, f"chain_{dst_chain_id}")
            dst_addr  = "0x" + to_bytes.hex() if len(to_bytes) == 20 else to_bytes.hex()

            # 如果目标是 Tron，转换地址格式
            if dst_chain == "tron" and len(to_bytes) >= 20:
                dst_addr_tron = hex_to_tron("0x" + to_bytes[-20:].hex())
                dst_addr = dst_addr_tron

            return {
                "bridge": self.name,
                "tx_hash": tx_hash,
                "sender": sender,
                "dst_chain": dst_chain,
                "dst_chain_id": dst_chain_id,
                "dst_address": dst_addr,
                "amount": amount_ld,
                "amount_display": f"{amount_ld / 1e6:.2f} USDT" if amount_ld > 0 else "N/A",
            }
        except Exception as e:
            print(f"    [Stargate] 解析失败: {e}")
            return None


class OrbiterTracer(BridgeTracer):
    """
    Orbiter Finance 追踪
    Maker / liquidity routing 模式下，链上通常无法强验证收款方。
    这里保留桥识别，但不再把启发式推断当作确定目标地址。
    """
    name = "Orbiter Finance"
    CONTRACT = "0x80c67432656d59144ceff962e8faf8926599bcf8"

    ORBITER_CHAIN_CODES = {
        "9001": "ethereum",
        "9002": "tron",
        "9006": "polygon",
        "9007": "optimism",
        "9010": "arbitrum",
        "9016": "base",
        "9018": "zksync",
        "9019": "starknet",
    }

    def trace(self, tx_hash: str, sender: str) -> Optional[Dict]:
        print(f"    [Orbiter] 解析交易 {tx_hash[:20]}...")
        return {
            "bridge": self.name,
            "tx_hash": tx_hash,
            "sender": sender,
            "dst_chain": "unknown",
            "dst_address": "不透明桥：目标地址无法从链上强验证",
            "opaque": True,
            "note": "Orbiter 采用 maker / liquidity routing 模式，启发式推断不作为强证据。",
        }


class AcrossTracer(BridgeTracer):
    """
    Across Protocol v3 追踪
    事件: V3FundsDeposited(inputToken, outputToken, inputAmount, outputAmount,
                            destinationChainId, depositId, quoteTimestamp,
                            fillDeadline, exclusivityDeadline, depositor,
                            recipient, exclusiveRelayer, message)
    """
    name = "Across Protocol v3"
    CONTRACT = "0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5"
    # keccak256("V3FundsDeposited(address,address,uint256,uint256,uint256,uint32,uint32,uint32,uint32,address,address,address,bytes)")
    EVENT_TOPIC = "0xa123dc29aebf7d0c3322c408d519459798f512851f64c7b1f76af6de6ae55ba"

    def trace(self, tx_hash: str, sender: str) -> Optional[Dict]:
        print(f"    [Across] 解析交易 {tx_hash[:20]}...")
        logs = get_tx_logs(tx_hash)
        for log in logs:
            if log.get("topics", [None])[0] == self.EVENT_TOPIC:
                try:
                    # topics[1] = inputToken, topics[2] = outputToken
                    # data: inputAmount(32), outputAmount(32), destinationChainId(32),
                    #       depositId(32), quoteTimestamp(32), fillDeadline(32),
                    #       exclusivityDeadline(32), depositor(32), recipient(32), ...
                    data = bytes.fromhex(log.get("data", "0x")[2:])
                    dst_chain_id = int.from_bytes(data[64:96], "big")
                    depositor    = "0x" + data[224:256].hex()[-40:]
                    recipient    = "0x" + data[256:288].hex()[-40:]
                    amount       = int.from_bytes(data[0:32], "big")
                    dst_chain    = LAYERZERO_CHAIN_ID.get(dst_chain_id, f"evm_{dst_chain_id}")
                    return {
                        "bridge": self.name,
                        "tx_hash": tx_hash,
                        "sender": sender,
                        "depositor": depositor,
                        "dst_chain": dst_chain,
                        "dst_address": recipient,
                        "amount": amount,
                        "amount_display": f"{amount / 1e6:.2f} USDT",
                    }
                except Exception as e:
                    print(f"    [Across] 日志解析失败: {e}")
        return None


class CelerTracer(BridgeTracer):
    """
    Celer cBridge 追踪
    事件: Send(bytes32 transferId, address sender, address receiver,
               address token, uint256 amount, uint64 dstChainId,
               uint64 nonce, uint32 maxSlippage)
    """
    name = "Celer cBridge"
    CONTRACT = "0x5427fefa711eff984124bfbb1ab6fbf5e3da1820"
    # keccak256("Send(bytes32,address,address,address,uint256,uint64,uint64,uint32)")
    EVENT_TOPIC = "0x89d8051e597ab4178a863a5190407b98abfeff406aa8db90c59af76612e58f01"

    def trace(self, tx_hash: str, sender: str) -> Optional[Dict]:
        print(f"    [Celer] 解析交易 {tx_hash[:20]}...")
        logs = get_tx_logs(tx_hash)
        for log in logs:
            if log.get("topics", [None])[0] == self.EVENT_TOPIC:
                try:
                    topics = log.get("topics", [])
                    data   = bytes.fromhex(log.get("data", "0x")[2:])
                    # topics[1]=transferId, topics[2]=sender, topics[3]=receiver
                    receiver     = "0x" + topics[3][-40:] if len(topics) > 3 else "unknown"
                    token        = "0x" + topics[2][-40:] if len(topics) > 2 else "unknown"
                    amount       = int.from_bytes(data[0:32], "big")
                    dst_chain_id = int.from_bytes(data[32:40], "big")
                    dst_chain    = LAYERZERO_CHAIN_ID.get(dst_chain_id, f"chain_{dst_chain_id}")
                    return {
                        "bridge": self.name,
                        "tx_hash": tx_hash,
                        "sender": sender,
                        "dst_chain": dst_chain,
                        "dst_address": receiver,
                        "amount": amount,
                        "amount_display": f"{amount / 1e18:.4f} ETH",
                    }
                except Exception as e:
                    print(f"    [Celer] 日志解析失败: {e}")
        return None


# ==================== 主追踪器 ====================
BRIDGE_TRACERS = {
    "0x8731d54e9d02c286767d56ac03e8037c07e01e98": StargateTracer(),
    "0x150f94b44927f078737562f0fcf3c95c01cc2376": StargateTracer(),
    "0x80c67432656d59144ceff962e8faf8926599bcf8": OrbiterTracer(),
    "0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5": AcrossTracer(),
    "0x4d9079bb4165aeb4084c526a32695dcfd2f77381": AcrossTracer(),
    "0x5427fefa711eff984124bfbb1ab6fbf5e3da1820": CelerTracer(),
}

BRIDGE_NAMES = {
    "0x8731d54e9d02c286767d56ac03e8037c07e01e98": "Stargate Finance",
    "0x150f94b44927f078737562f0fcf3c95c01cc2376": "Stargate Finance",
    "0x80c67432656d59144ceff962e8faf8926599bcf8": "Orbiter Finance",
    "0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5": "Across Protocol v3",
    "0x4d9079bb4165aeb4084c526a32695dcfd2f77381": "Across Protocol v2",
    "0x5427fefa711eff984124bfbb1ab6fbf5e3da1820": "Celer cBridge",
    "0x3ee18b2214aff97000d974cf647e7c347e8fa585": "Wormhole",
    "0x43de2d77bf8027e25dbd179b491e8d64f38398aa": "deBridge",
    "0x66a71dcef29a0ffbdbe3c6a460a3b5bc225cd675": "LayerZero v1",
    "0x1a44076050125825900e736c501f859c50fe728c": "LayerZero v2",
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado Cash 0.1ETH",
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado Cash 1ETH",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash 10ETH",
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": "Tornado Cash 100ETH",
}


def trace_bridge_tx(tx_hash: str, sender: str, bridge_contract: str) -> Optional[Dict]:
    """
    给定一笔桥合约交易，解析出目标链和目标地址
    这是"连接两条链"的核心函数
    """
    bridge_contract = bridge_contract.lower()
    tracer = BRIDGE_TRACERS.get(bridge_contract)
    if tracer:
        return tracer.trace(tx_hash, sender)
    # 对没有专门解析器的桥，返回基本信息
    return {
        "bridge": BRIDGE_NAMES.get(bridge_contract, bridge_contract),
        "tx_hash": tx_hash,
        "sender": sender,
        "dst_chain": "unknown",
        "dst_address": "需要手动解析 calldata",
        "note": "该桥暂无自动解析器，请用 Etherscan 手动查看 Input Data",
    }


def find_bridge_txs_for_address(address: str) -> List[Dict]:
    """
    查找某地址的所有跨链桥交易，并解析目标地址
    返回：[{bridge, tx_hash, dst_chain, dst_address, amount}, ...]
    """
    print(f"\n[*] 扫描 {address} 的跨链桥交易...")
    results = []
    addr_lower = address.lower()

    # 查 ETH 普通交易
    r = requests.get(BLOCKSCOUT_ETH, params={
        "module": "account", "action": "txlist",
        "address": address, "sort": "desc", "offset": 200, "page": 1,
    }, timeout=15)
    txs = r.json().get("result", [])
    if not isinstance(txs, list):
        txs = []

    for tx in txs:
        to = (tx.get("to") or "").lower()
        if to in BRIDGE_NAMES:
            bridge_name = BRIDGE_NAMES[to]
            tx_hash = tx.get("hash", "")
            print(f"  → 发现桥交易: {bridge_name}  tx={tx_hash[:20]}...")

            # 尝试解析目标地址
            time.sleep(0.3)
            detail = trace_bridge_tx(tx_hash, addr_lower, to)
            if detail:
                detail["block"] = tx.get("blockNumber", "")
                detail["timestamp"] = tx.get("timeStamp", "")
                results.append(detail)
            else:
                results.append({
                    "bridge": bridge_name,
                    "contract": to,
                    "tx_hash": tx_hash,
                    "sender": addr_lower,
                    "dst_chain": "需解析",
                    "dst_address": "需解析",
                })

    return results


def print_bridge_trace(results: List[Dict]):
    if not results:
        print("  未发现跨链桥交易")
        return

    print(f"\n发现 {len(results)} 笔跨链桥交易：")
    print("=" * 70)
    for r in results:
        print(f"\n  桥:       {r.get('bridge', '?')}")
        print(f"  发送方:   {r.get('sender', '?')}")
        print(f"  目标链:   {r.get('dst_chain', '?')}")
        print(f"  目标地址: {r.get('dst_address', '?')}")
        if r.get("amount_display"):
            print(f"  金额:     {r['amount_display']}")
        print(f"  交易哈希: {r.get('tx_hash', '?')}")
        if r.get("note"):
            print(f"  备注:     {r['note']}")
        print(f"  {'─'*60}")
        # 显示 Tron 追踪建议
        dst = r.get("dst_address", "")
        dst_chain = r.get("dst_chain", "")
        if dst_chain == "tron" and dst.startswith("T"):
            print(f"\n  [追踪建议] 在 TronScan 查询目标地址：")
            print(f"  https://tronscan.org/#/address/{dst}")
        elif dst_chain == "tron" and dst.startswith("0x"):
            tron_b58 = hex_to_tron(dst)
            print(f"\n  [追踪建议] Tron 地址: {tron_b58}")
            print(f"  https://tronscan.org/#/address/{tron_b58}")


# ==================== CLI ====================
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("用法:")
        print("  python cross_chain_tracer.py <地址>          # 扫描该地址的所有跨链桥交易")
        print("  python cross_chain_tracer.py tx <tx_hash> <桥合约>  # 解析单笔桥交易的目标地址")
        print()
        print("示例:")
        print("  python cross_chain_tracer.py 0xabc123...")
        print("  python cross_chain_tracer.py tx 0xtxhash... 0x8731d5...")
        sys.exit(0)

    if sys.argv[1] == "tx":
        tx_hash = sys.argv[2]
        bridge_contract = sys.argv[3]
        result = trace_bridge_tx(tx_hash, "unknown", bridge_contract)
        if result:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print("解析失败")
    else:
        address = sys.argv[1]
        results = find_bridge_txs_for_address(address)
        print_bridge_trace(results)
        if results:
            with open("bridge_trace_result.json", "w") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"\n结果已保存: bridge_trace_result.json")
