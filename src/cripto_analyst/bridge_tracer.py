#!/usr/bin/env python3
"""跨链桥对端解析（生效实现）：协议索引器 API（LayerZero Scan 等）+ 目标链 receipt 回锚。"""

import sys
import time
from typing import Optional, Dict

import requests

from .config import ETHERSCAN_API_KEY, REQUEST_DELAY
from .chains import LZ_CHAIN_MAP, CHAIN_SCANNERS
from .utils import normalize

# ==================== 跨链桥对端地址追踪器 ====================
class BridgeTracer:
    def resolve(self, tx_hash: str, method: str, src_address: str,
                dst_chains_hint: list) -> Optional[Dict]:
        if method == "layerzero_api":
            return self._resolve_layerzero(tx_hash, src_address)
        # 其余 method（hop_api/cbridge_api/across_api 等）均未实现，返回 None
        # bridges.json 中对应条目应标记 traceable=false，不会走到这里
        return None

    def _resolve_layerzero(self, tx_hash: str, src_address: str) -> Optional[Dict]:
        try:
            r = requests.get(f"https://api.layerzeroscan.com/tx/{tx_hash}", timeout=10)
            if r.status_code != 200:
                return None
            data = r.json()
            messages = data.get("messages") or data.get("data") or []
            if not messages:
                return None
            msg = messages[0]
            dst_chain_id = (
                msg.get("dstChainId")
                or msg.get("pathway", {}).get("dstEid")
                or (msg.get("destination") or {}).get("chainId")
            )
            dst_tx = (
                msg.get("dstTxHash")
                or (msg.get("destination") or {}).get("tx", {}).get("txHash")
                or ""
            )
            dst_chain = LZ_CHAIN_MAP.get(int(dst_chain_id)) if dst_chain_id else None
            if not dst_chain:
                return None
            dst_address = self._find_token_receiver(dst_tx, dst_chain) or src_address
            return {"dst_chain": dst_chain, "dst_address": dst_address, "dst_tx": dst_tx}
        except Exception as e:
            print(f"  [WARN] LZ Scan 查询失败: {e}", file=sys.stderr)
            return None

    def _find_token_receiver(self, tx_hash: str, chain: str) -> Optional[str]:
        if not tx_hash:
            return None
        cfg = CHAIN_SCANNERS.get(chain, {})
        api = cfg.get("api")
        key = cfg.get("key", "")
        if not api:
            return None
        try:
            params = {"module": "account", "action": "tokentx",
                      "txhash": tx_hash, "page": 1, "offset": 5}
            if key:
                params["apikey"] = key
            r = requests.get(api, params=params, timeout=10)
            txs = r.json().get("result", [])
            if isinstance(txs, list) and txs:
                return normalize(txs[0].get("to", ""))
        except Exception:
            pass
        return None

