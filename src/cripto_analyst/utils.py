#!/usr/bin/env python3
"""地址与黑名单工具：Base58 转换、地址归一化、黑名单加载、链类型判断。"""

import csv
import sys
import hashlib
from typing import Optional, Dict

from .chains import EVM_CHAIN_REGISTRY

# ==================== Base58 工具 ====================
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    count = 0
    for byte in data:
        if byte == 0:
            count += 1
        else:
            break
    num = int.from_bytes(data, "big")
    result = []
    while num > 0:
        num, rem = divmod(num, 58)
        result.append(_B58_ALPHABET[rem : rem + 1])
    result.extend([_B58_ALPHABET[0:1]] * count)
    return b"".join(reversed(result)).decode()


def hex_to_tron_base58(hex_addr: str) -> str:
    """将 0x 开头的 hex 地址转换为 Tron Base58Check 地址（T 开头）"""
    clean = hex_addr.lower().replace("0x", "")
    raw = bytes.fromhex("41" + clean)
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    return _b58encode(raw + checksum)


def normalize(addr: str) -> str:
    return addr.lower().strip()


# ==================== 黑名单加载 ====================
def load_blacklist(csv_path: str) -> Dict[str, Dict]:
    """加载黑名单，返回 {normalize(address): {chain, time}} 字典"""
    bl: Dict[str, Dict] = {}
    try:
        with open(csv_path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                addr = normalize(row["address"])
                bl[addr] = {"chain": row.get("chain", ""), "time": row.get("time", "")}
    except FileNotFoundError:
        print(f"[ERROR] 找不到黑名单文件: {csv_path}", file=sys.stderr)
        sys.exit(1)
    return bl


# ==================== 链类型判断 ====================
def detect_chain(address: str, blacklist: Dict[str, Dict]) -> str:
    # Tron 地址以 T 开头，Base58 编码，34位
    if not address.startswith("0x"):
        return "tron"
    addr_norm = normalize(address)
    # 黑名单里有明确链记录时使用（避免多链同地址歧义）
    if addr_norm in blacklist:
        chain = blacklist[addr_norm].get("chain", "")
        if chain and chain in EVM_CHAIN_REGISTRY:
            return chain
    return "ethereum"



# ==================== Tron Base58 转 Hex ====================
_B58_MAP = {chr(_B58_ALPHABET[i]): i for i in range(58)}

def _tron_b58_to_hex(b58_addr: str) -> Optional[str]:
    try:
        num = 0
        for c in b58_addr:
            num = num * 58 + _B58_MAP[c]
        raw = num.to_bytes(25, "big")
        payload = raw[:21]
        checksum = raw[21:]
        expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        if checksum != expected:
            return None
        return "0x" + payload[1:].hex()
    except Exception:
        return None

