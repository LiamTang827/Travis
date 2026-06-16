#!/usr/bin/env python3
"""核心分析引擎 AMLAnalyzer：单地址比例 taint 打分 + 2-hop 真实污染比例 + 跨链桥追踪编排。

评分公式（污染比例模型）：
  risk_score = max(received_taint, sent_taint) × 100
  taint = Σ(风险往来金额 × 类别权重 × hop_decay) / 该方向总流量
"""

import sys
import time
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Optional, Set, Dict, List, Tuple

import requests

from .config import (
    CATEGORY_WEIGHTS, HOP_DECAY, STABLECOIN_SYMBOLS,
    ETHERSCAN_API_KEY, REQUEST_DELAY, PAGE_SIZE, MAX_TX_FETCH, MAX_PAGES,
    decode_method, risk_level, HOP2_ENABLED,
)
from .chains import (
    ChainConfig, EVM_CHAIN_REGISTRY, EVMClient, TronScanClient,
    CHAIN_SCANNERS, LZ_CHAIN_MAP, KNOWN_DEX_ADDRS,
    TRON_BRIDGE_CONTRACTS_HEX, BRIDGE_TRACE_ENABLED,
)
from .models import RiskIndicator, RiskReport
from .utils import normalize, hex_to_tron_base58, _tron_b58_to_hex
from .bridge_tracer import BridgeTracer
from .threat_intel import (
    MIXER_CONTRACTS, BRIDGE_REGISTRY, ALL_BRIDGE_ADDRS, OPAQUE_BRIDGE_ADDRS,
    EXCHANGE_HOT_WALLETS, HIGH_RISK_EXCHANGES, HIGH_RISK_EXCHANGES_FLAT,
    EXCHANGE_HOT_WALLETS_FLAT, ALL_EXCHANGE_ADDRS, DEPOSIT_DETECTION_PARAMS,
    OFAC_SANCTIONED, OFAC_SANCTIONED_ADDRS,
)

# ==================== 核心分析引擎 ====================
class AMLAnalyzer:
    def __init__(self, blacklist: Dict[str, Dict],
                 evm_clients: Dict[str, EVMClient],
                 tronscan: TronScanClient,
                 tracer: BridgeTracer = None,
                 time_window_days: int = 0):
        self.blacklist = blacklist
        self.evm_clients = evm_clients   # {chain_name: EVMClient}
        self.tron = tronscan
        self.tracer = tracer or BridgeTracer()
        self.time_window_days = time_window_days
        self.eth_price_usd = self._fetch_eth_price()

    def _fetch_eth_price(self) -> float:
        try:
            eth_client = self.evm_clients.get("ethereum")
            if eth_client:
                d = eth_client._get({"module": "stats", "action": "ethprice"})
                if d and isinstance(d.get("result"), dict):
                    price = float(d["result"].get("ethusd", 0))
                    if price > 0:
                        print(f"  ETH price: ${price:,.2f}")
                        return price
        except Exception:
            pass
        print("  ETH price: fallback $2,500.00")
        return 2500.0

    def _classify_contract_action(self, method: str, native_value: float, token_effects: List[dict]) -> str:
        method_l = (method or "").lower()
        stable_effects = [e for e in token_effects if e.get("is_stablecoin")]
        nonzero_effects = [e for e in token_effects if e.get("amount", 0) > 0]
        dirs = {e.get("direction") for e in stable_effects}

        if "approve" in method_l:
            return "Approval"
        if "swap" in method_l or ("multicall" in method_l and "IN" in dirs and "OUT" in dirs):
            return "Swap / Router Call"
        if "bridge" in method_l or "deposit" in method_l or "withdraw" in method_l:
            return "Bridge / Deposit / Withdraw"
        if stable_effects:
            return "Stablecoin Transfer" if len(stable_effects) == 1 else "Stablecoin Movement"
        if nonzero_effects:
            return "Other ERC20 Movement"
        if native_value > 0:
            return "Native ETH Transfer"
        return "Contract Call / No Asset Effect"

    def _build_contract_interactions(self, report: RiskReport, normal_txs: List[dict],
                                     token_txs: List[dict], chain_cfg: ChainConfig,
                                     chain_name: str, address: str) -> None:
        """Aggregate outer calls and inner ERC20 Transfer effects by tx hash."""
        addr_norm = normalize(address)
        configured_stables = {
            sym.upper(): normalize(contract)
            for sym, contract in (chain_cfg.stablecoin_contracts or {}).items()
        }
        effects_by_hash: Dict[str, List[dict]] = {}

        for tx in token_txs:
            tx_hash = tx.get("hash") or tx.get("transactionHash")
            if not tx_hash:
                continue
            sym = (tx.get("_sym") or tx.get("tokenSymbol") or "").upper().strip()
            contract = normalize(tx.get("contractAddress", ""))
            try:
                dec = int(tx.get("tokenDecimal", "") or chain_cfg.token_decimals(sym))
            except Exception:
                dec = chain_cfg.token_decimals(sym)
            try:
                amount = int(tx.get("value", "0") or "0") / (10 ** dec)
            except Exception:
                amount = 0.0
            if amount <= 0:
                continue

            frm = normalize(tx.get("from", ""))
            to = normalize(tx.get("to", "") or "")
            if to == addr_norm:
                direction, counterparty = "IN", frm
            elif frm == addr_norm:
                direction, counterparty = "OUT", to
            else:
                direction, counterparty = "OTHER", ""

            is_stable = sym in configured_stables and contract == configured_stables[sym]
            method_id_raw = tx.get("methodId", "") or ""
            function_name_raw = tx.get("functionName", "") or ""
            if method_id_raw.lower().strip() == "0x":
                method_id_raw = ""
            effects_by_hash.setdefault(tx_hash, []).append({
                "direction": direction,
                "counterparty": counterparty,
                # 显式带出 from / to，避免下游只能看到 direction 推回
                "from": frm,
                "to": to,
                "amount": round(amount, 6),
                "sym": sym,
                "token_contract": contract,
                "token_decimals": dec,
                # method_id / method 是 Etherscan tokentx 返回的"外壳交易"信息
                # 这里继续保留原值，并加一份 decoded label 供展示
                "method_id": method_id_raw,
                "method": function_name_raw or method_id_raw,
                "method_label": decode_method(method_id_raw, function_name_raw),
                "ts": tx.get("timeStamp", ""),
                "is_stablecoin": is_stable,
                "token_status": "configured_stablecoin_contract" if is_stable else "other_erc20",
            })

        interactions = []
        seen_hashes = set()
        for tx in normal_txs:
            tx_hash = tx.get("hash", "")
            if not tx_hash:
                continue
            seen_hashes.add(tx_hash)
            frm = normalize(tx.get("from", ""))
            to = normalize(tx.get("to", "") or "")
            try:
                native_value = int(tx.get("value", "0") or "0") / 1e18
            except Exception:
                native_value = 0.0
            if to == addr_norm:
                direction, counterparty = "IN", frm
            elif frm == addr_norm:
                direction, counterparty = "OUT", to
            else:
                direction, counterparty = "OTHER", to or frm

            input_data = tx.get("input", "") or ""
            method_id_raw = tx.get("methodId", "") or ""
            function_name_raw = tx.get("functionName", "") or ""
            # methodId 偶尔会被 Etherscan 设成 "0x"（input 为空时的占位），归一为空
            if method_id_raw.lower().strip() == "0x":
                method_id_raw = ""
            method_raw = function_name_raw or method_id_raw
            method_label = decode_method(method_id_raw, function_name_raw)
            if not method_label and input_data in ("", "0x"):
                method_label = "Transfer"      # 没 input data 就是裸转账
            token_effects = effects_by_hash.get(tx_hash, [])
            interactions.append({
                "tx_hash": tx_hash,
                "ts": tx.get("timeStamp", ""),
                "chain": chain_name,
                "from": frm,
                "to": to,
                "direction": direction,
                "counterparty": counterparty,
                "native_value": round(native_value, 12),
                "method_id": method_id_raw,
                "method": method_raw or ("Transfer" if input_data in ("", "0x") else "unknown"),
                "method_label": method_label,
                "input_present": bool(input_data and input_data != "0x"),
                "is_contract_call": bool(input_data and input_data != "0x"),
                "status": "success" if tx.get("isError", "0") == "0" else "failed",
                "token_effects": token_effects,
                "action_type": self._classify_contract_action(method_raw, native_value, token_effects),
            })

        for tx_hash, token_effects in effects_by_hash.items():
            if tx_hash in seen_hashes:
                continue
            # TOKEN_ONLY：normal_txs 里没匹到外壳（地址不是 tx.from 也不是 tx.to，
            # 比如 Safe 多签代付 / 路由器内部 inner call）。此时把 token transfer 自己
            # 携带的 methodId/functionName 作为这条交互的 method。
            first_effect = token_effects[0] if token_effects else {}
            method_id_raw = first_effect.get("method_id", "") or ""
            # first_effect["method"] 已经是 functionName-or-methodId，复原 functionName
            method_raw = first_effect.get("method", "") or ""
            function_name_raw = method_raw if method_raw and method_raw != method_id_raw else ""
            method_label = decode_method(method_id_raw, function_name_raw) or "not captured"
            interactions.append({
                "tx_hash": tx_hash,
                "ts": first_effect.get("ts", ""),
                "chain": chain_name,
                "from": "",
                "to": "",
                "direction": "TOKEN_ONLY",
                "counterparty": "",
                "native_value": 0.0,
                "method_id": method_id_raw,
                "method": method_raw or "not captured",
                "method_label": method_label,
                "input_present": False,
                "is_contract_call": True,
                "status": "unknown",
                "token_effects": token_effects,
                "action_type": self._classify_contract_action(method_raw, 0.0, token_effects),
            })

        report.contract_interactions.extend(
            sorted(interactions, key=lambda x: x.get("ts", ""), reverse=True)
        )

    # ---------- 稳定币余额一致性校验 ----------
    def _check_balance_consistency(self, address: str, token_txs: List[dict],
                                   client: EVMClient, chain_cfg: ChainConfig) -> dict:
        """
        汇总链上所有稳定币实际余额，与历史转账记录的收支差对比。
        差异过大说明存在未追踪的资金流动。
        仅在 MAX_TX_FETCH 未截断时结果可信。
        """
        addr_norm = normalize(address)

        # 查所有稳定币余额并汇总（decimals 统一按链配置处理）
        stable_contracts = chain_cfg.stablecoin_contracts or {"USDT": chain_cfg.usdt_contract}
        actual_balance = 0.0
        for sym, contract in stable_contracts.items():
            balance_data = client._get({
                "module": "account", "action": "tokenbalance",
                "contractaddress": contract,
                "address": address,
                "tag": "latest",
            })
            if balance_data and isinstance(balance_data.get("result"), str):
                try:
                    decimals = chain_cfg.token_decimals(sym)
                    actual_balance += int(balance_data["result"]) / (10 ** decimals)
                except Exception:
                    pass
            time.sleep(REQUEST_DELAY)

        total_in = 0.0
        total_out = 0.0
        tx_count = 0
        for tx in token_txs:
            symbol = (tx.get("tokenSymbol") or "").upper()
            if symbol not in STABLECOIN_SYMBOLS:
                continue
            f = normalize(tx.get("from", ""))
            t = normalize(tx.get("to", "") or "")
            try:
                decimals = int(tx.get("tokenDecimal", "6") or "6")
                val = int(tx.get("value", "0") or "0") / (10 ** decimals)
            except Exception:
                val = 0.0
            if t == addr_norm:
                total_in += val
            elif f == addr_norm:
                total_out += val
            tx_count += 1

        expected = total_in - total_out
        discrepancy = actual_balance - expected
        discrepancy_pct = abs(discrepancy) / max(total_in, 1.0) * 100
        is_fast_transit = (
            total_in > 10_000
            and actual_balance < total_in * 0.05
            and total_out > total_in * 0.9
        )
        is_unexplained_gap = (
            abs(discrepancy) > 5_000
            and discrepancy_pct > 20
            and tx_count >= 5
        )
        return {
            "actual_usdt_balance": round(actual_balance, 2),
            "total_in": round(total_in, 2),
            "total_out": round(total_out, 2),
            "expected_balance": round(expected, 2),
            "discrepancy": round(discrepancy, 2),
            "discrepancy_pct": round(discrepancy_pct, 1),
            "is_fast_transit": is_fast_transit,
            "is_unexplained_gap": is_unexplained_gap,
            "tx_count_used": tx_count,
            "truncated": len(token_txs) >= MAX_TX_FETCH,
        }

    # ---------- 目标链 1 跳黑名单检测 ----------
    def _check_dst_hop1(self, address: str, chain: str) -> List[dict]:
        cfg = CHAIN_SCANNERS.get(chain, {})
        api = cfg.get("api")
        key = cfg.get("key", "")
        if not api:
            return []
        hits: List[dict] = []
        addr_norm = normalize(address)
        try:
            for action in ["txlist", "tokentx"]:
                params = {
                    "module": "account", "action": action,
                    "address": address, "sort": "desc", "offset": 50, "page": 1,
                }
                if key:
                    params["apikey"] = key
                time.sleep(REQUEST_DELAY)
                r = requests.get(api, params=params, timeout=10)
                txs = r.json().get("result", [])
                if not isinstance(txs, list):
                    continue
                for tx in txs:
                    f = normalize(tx.get("from", ""))
                    t = normalize(tx.get("to", "") or "")
                    if f == addr_norm:
                        other = t
                        direction = "OUT"
                    elif t == addr_norm:
                        other = f
                        direction = "IN"
                    else:
                        continue
                    if other and other != addr_norm and other in self.blacklist:
                        info = self.blacklist[other]
                        entry = {"address": other, "chain": info["chain"],
                                 "blacklist_time": info["time"], "direction": direction}
                        if entry not in hits:
                            hits.append(entry)
        except Exception as e:
            print(f"  [WARN] 目标链({chain})查询失败: {e}", file=sys.stderr)
        return hits[:5]

    # ---------- USDT getLogs 查询（捕获 transferFrom 类型转账）----------
    def _get_usdt_logs(self, address: str, client: EVMClient,
                       chain_cfg: ChainConfig,
                       from_block: int = 0,
                       to_block: int = 99999999) -> List[dict]:
        """getLogs 回退：为所有稳定币合约各查一次 Transfer 事件"""
        TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        addr_norm = normalize(address)
        padded = "0x" + "0" * 24 + addr_norm[2:]
        results = []
        backup = client.backup_url
        base = backup if backup else client.primary_url

        stable_contracts = chain_cfg.stablecoin_contracts or {"USDT": chain_cfg.usdt_contract}
        for sym, contract in stable_contracts.items():
            for role, topic_key in [("sender", "topic1"), ("receiver", "topic2")]:
                time.sleep(REQUEST_DELAY)
                params = {
                    "module": "logs", "action": "getLogs",
                    "address": contract,
                    "topic0": TRANSFER_TOPIC,
                    topic_key: padded,
                    "topic0_1_opr" if role == "sender" else "topic0_2_opr": "and",
                    "fromBlock": from_block, "toBlock": to_block,
                    "page": 1, "offset": MAX_TX_FETCH,
                }
                try:
                    r = requests.get(base, params=params, timeout=15)
                    logs = r.json().get("result", [])
                    if isinstance(logs, list):
                        for log in logs:
                            log["_role"] = role
                            log["_sym"] = sym
                        results.extend(logs)
                except Exception:
                    pass

        return results

    # ---------- 单条 EVM 链分析（1-hop + 2-hop）----------
    def _analyze_evm_chain(self, address: str, report: RiskReport,
                           chain_cfg: ChainConfig, client: EVMClient,
                           chain_name: str):
        addr_norm = normalize(address)
        chain_label = chain_cfg.name

        # 时间窗口截止时间（0 = 不限制）
        time_cutoff = 0
        from_block = 0
        to_block = 99999999
        if self.time_window_days > 0:
            time_cutoff = int(time.time()) - self.time_window_days * 86400
            from_block = client.get_block_by_time(time_cutoff, closest="after")
            latest_block = client.get_block_by_time(int(time.time()), closest="before")
            if from_block > 0:
                to_block = latest_block or to_block
                print(f"  [{chain_label}] 时间窗口 {self.time_window_days} 天 ≈ blocks {from_block:,} → {to_block:,}")
        report.analysis_windows[chain_name] = {
            "days": self.time_window_days,
            "from_timestamp": time_cutoff,
            "to_timestamp": int(time.time()),
            "from_block": from_block,
            "to_block": to_block,
        }

        print(f"  [{chain_label}] 查询普通交易（最多 {MAX_PAGES} 页 × {PAGE_SIZE} 条）...")
        normal_txs = client.get_normal_txs(address, limit=PAGE_SIZE,
                                           max_pages=MAX_PAGES, time_cutoff=time_cutoff,
                                           from_block=from_block, to_block=to_block)
        if len(normal_txs) >= PAGE_SIZE * MAX_PAGES:
            report.warnings.append(
                f"[{chain_label}] Normal tx cap reached ({PAGE_SIZE*MAX_PAGES}), history may be incomplete"
            )

        # ── 按稳定币逐一拉取 Token 转账 + 余额 ────────────────────────
        stable_contracts = chain_cfg.stablecoin_contracts or {"USDT": chain_cfg.usdt_contract}
        # 汇总所有稳定币 txs 供后续对手方发现
        token_txs: List[dict] = []
        for sym, contract in stable_contracts.items():
            decimals = chain_cfg.token_decimals(sym)
            time.sleep(REQUEST_DELAY)
            stxs = client.get_token_transfers(address, contract=contract,
                                              limit=PAGE_SIZE, max_pages=MAX_PAGES,
                                              time_cutoff=time_cutoff,
                                              from_block=from_block, to_block=to_block)
            # 实际余额（API 直接查）
            time.sleep(REQUEST_DELAY)
            balance = client.get_token_balance(address, contract, decimals)

            # 计算该资产流入/流出，同时收集全量流水
            asset_in, asset_out = 0.0, 0.0
            for tx in stxs:
                f = normalize(tx.get("from", ""))
                t = normalize(tx.get("to", "") or "")
                try:
                    val = int(tx.get("value", "0") or "0") / (10 ** decimals)
                except Exception:
                    val = 0.0
                direction = ""
                counterparty = ""
                if t == addr_norm:
                    asset_in += val
                    direction, counterparty = "IN", f
                elif f == addr_norm:
                    asset_out += val
                    direction, counterparty = "OUT", t
                if direction and val > 0:
                    report.transactions.append({
                        "ts":           tx.get("timeStamp", ""),
                        "direction":    direction,
                        "amount":       round(val, 6),
                        "sym":          sym,
                        "token_contract": normalize(contract),
                        "token_decimals": decimals,
                        "method_id":     tx.get("methodId", ""),
                        "method":        tx.get("functionName", "") or tx.get("methodId", ""),
                        "action_type":   "Stablecoin Transfer",
                        "chain":        chain_name,
                        "counterparty": counterparty,
                        "tx_hash":      tx.get("hash", ""),
                    })

            # 快速中转检测（per asset）
            is_fast_transit = (
                asset_in > 10_000
                and balance < asset_in * 0.05
                and asset_out > asset_in * 0.9
            )
            if is_fast_transit:
                report.warnings.append(
                    f"[{chain_label}][{sym}] Fast transit: inflow ${asset_in:,.0f} / "
                    f"outflow ${asset_out:,.0f} / balance ${balance:,.2f}"
                )

            if stxs or balance > 0:
                # 窗口前隐含余额：balance + outflow - inflow
                # 若为正，说明地址在分析窗口之前就持有该资产
                # 若为负，说明转账记录不完整（API 分页上限触发）
                pre_window_balance = round(balance + asset_out - asset_in, 2)
                truncated = len(stxs) >= PAGE_SIZE * MAX_PAGES

                key = f"{sym}@{chain_name}"
                report.per_asset[key] = {
                    "sym": sym, "chain": chain_name,
                    "decimals": decimals,
                    "start_block": from_block,
                    "end_block": to_block,
                    "start_balance": pre_window_balance,
                    "end_balance": round(balance, 2),
                    "start_balance_source": "reconstructed: end_balance + outflow - inflow",
                    "end_balance_source": "tokenbalance latest",
                    "historical_balance_verified": False,
                    "balance_source": "end=tokenbalance latest; start=reconstructed from window flows",
                    "flow_in": round(asset_in, 2),
                    "flow_out": round(asset_out, 2),
                    "balance": round(balance, 2),
                    "pre_window_balance": pre_window_balance,
                    "truncated": truncated,
                    "tx_count": len(stxs),
                    "is_fast_transit": is_fast_transit,
                    "taint_in": 0.0, "taint_out": 0.0,
                }

            # 为 tx 打上 token 标签，归入总池供后续 1-hop/2-hop 使用
            for tx in stxs:
                tx["_sym"] = sym
            token_txs.extend(stxs)

            # 汇总到 report 总流量（评分用）
            report.total_inflow_usdt  += asset_in
            report.total_outflow_usdt += asset_out
            if asset_in or asset_out:
                truncated_flag = " [截断!]" if len(stxs) >= PAGE_SIZE * MAX_PAGES else ""
                print(f"  [{chain_label}] {sym}: 流入 {asset_in:,.2f} / 流出 {asset_out:,.2f} / "
                      f"余额 {balance:,.2f} / 窗口前余额 {balance+asset_out-asset_in:,.2f}{truncated_flag}")

            if len(stxs) >= PAGE_SIZE * MAX_PAGES:
                report.warnings.append(
                    f"[{chain_label}][{sym}] Transfer cap reached ({PAGE_SIZE*MAX_PAGES}), "
                    f"history incomplete — inflow/outflow understated, pre-window balance may be negative"
                )

        # ── 全量 ERC20 token 转账（非稳定币）────────────────────────────
        # 目的：捕获 LINK/WBTC/UNI 等与风险地址的往来，用于 CP 表展示
        # 限 1 页（≤1000 条），不影响评分分母，只补充 by_sym 可见性
        time.sleep(REQUEST_DELAY)
        all_token_txs = client.get_token_transfers(address, limit=1000, max_pages=1,
                                                   time_cutoff=time_cutoff,
                                                   from_block=from_block, to_block=to_block)
        _stable_set = set(STABLECOIN_SYMBOLS)
        # 用合约地址过滤稳定币（tokenSymbol 不可靠，如 "USD TETHER"、乱码等变体）
        _stable_contracts = {normalize(a) for a in (chain_cfg.stablecoin_contracts or {}).values()
                             if a}
        _stable_contracts.add(normalize(chain_cfg.usdt_contract or ""))
        for tx in all_token_txs:
            sym_t    = (tx.get("tokenSymbol") or "").upper().strip()
            contract = normalize(tx.get("contractAddress", ""))
            if contract in _stable_contracts:
                continue   # 按合约地址过滤，避免 "USD TETHER" 等变体漏网
            if not sym_t or sym_t in _stable_set:
                continue
            try:
                dec = int(tx.get("tokenDecimal", "18") or "18")
                val = int(tx.get("value", "0") or "0") / (10 ** dec)
            except Exception:
                val = 0.0
            if val <= 0:
                continue
            tx["_sym"] = sym_t
            token_txs.append(tx)

            # 同步写入 report.transactions，让 CP 表能展示所有 token（不只是风险 CP）
            frm_t = normalize(tx.get("from", ""))
            to_t  = normalize(tx.get("to", "") or "")
            if to_t == addr_norm:
                direction_t, cp_t = "IN", frm_t
            elif frm_t == addr_norm:
                direction_t, cp_t = "OUT", to_t
            else:
                continue
            if cp_t and cp_t != addr_norm:
                report.transactions.append({
                    "ts":          tx.get("timeStamp", ""),
                    "direction":   direction_t,
                    "amount":      round(val, 6),
                    "sym":         sym_t,
                    "token_contract": contract,
                    "token_decimals": dec,
                    "method_id":     tx.get("methodId", ""),
                    "method":        tx.get("functionName", "") or tx.get("methodId", ""),
                    "action_type":   "Other ERC20 Transfer",
                    "chain":       chain_name,
                    "counterparty": cp_t,
                    "tx_hash":     tx.get("hash", ""),
                })

        # ── ETH 原生代币 per-asset 追踪 ───────────────────────────────────
        eth_in = eth_out = 0.0
        eth_tx_count = 0
        for tx in normal_txs:
            frm = normalize(tx.get("from", ""))
            t   = normalize(tx.get("to", "") or "")
            try:
                val = int(tx.get("value", "0") or "0") / 1e18
            except Exception:
                val = 0.0
            if val <= 0:
                continue
            eth_tx_count += 1
            if t == addr_norm:
                eth_in += val
            elif frm == addr_norm:
                eth_out += val

        # 仅主链记录 account_info
        if not report.account_info:
            time.sleep(REQUEST_DELAY)
            report.account_info = client.get_account_info(address)

        # ETH 余额从 account_info 解析
            eth_balance = 0.0
        if report.account_info:
            try:
                eth_balance = float(report.account_info.get("balance", "0").split()[0])
            except Exception:
                pass

        if eth_in > 0 or eth_out > 0 or eth_balance > 0:
            ep = self.eth_price_usd
            eth_in_usd  = round(eth_in  * ep, 2)
            eth_out_usd = round(eth_out * ep, 2)
            eth_bal_usd = round(eth_balance * ep, 2)
            key = f"ETH@{chain_name}"
            report.per_asset[key] = {
                "sym": chain_cfg.native_token, "chain": chain_name,
                "start_block": from_block,
                "end_block": to_block,
                "start_balance": round(eth_bal_usd + eth_out_usd - eth_in_usd, 2),
                "end_balance": eth_bal_usd,
                "start_native_balance": round(eth_balance + eth_out - eth_in, 6),
                "end_native_balance": round(eth_balance, 6),
                "start_balance_source": "reconstructed: end_native_balance + native_outflow - native_inflow",
                "end_balance_source": "native balance latest",
                "historical_balance_verified": False,
                "balance_source": "end=native balance latest; start=reconstructed from window flows",
                "flow_in":          eth_in_usd,
                "flow_out":         eth_out_usd,
                "balance":          eth_bal_usd,
                "pre_window_balance": round(eth_bal_usd + eth_out_usd - eth_in_usd, 2),
                "truncated":        len(normal_txs) >= PAGE_SIZE * MAX_PAGES,
                "tx_count":         eth_tx_count,
                "is_fast_transit":  (eth_in_usd > 10_000 and eth_bal_usd < eth_in_usd * 0.05
                                     and eth_out_usd > eth_in_usd * 0.9),
                "taint_in": 0.0, "taint_out": 0.0,
                "eth_amount_in":  round(eth_in, 6),
                "eth_amount_out": round(eth_out, 6),
                "eth_balance":    round(eth_balance, 6),
            }
            # ETH 不计入稳定币评分分母，单独记录供 % of Flow 展示用
            report.total_eth_usd_in  += eth_in_usd
            report.total_eth_usd_out += eth_out_usd
            if eth_in_usd or eth_out_usd:
                print(f"  [{chain_label}] ETH: 流入 {eth_in:.4f} (${eth_in_usd:,.0f}) / "
                      f"流出 {eth_out:.4f} (${eth_out_usd:,.0f}) / 余额 {eth_balance:.4f}")
            is_eth_fast_transit = (
                eth_in_usd > 10_000
                and eth_bal_usd < eth_in_usd * 0.05
                and eth_out_usd > eth_in_usd * 0.9
            )
            if is_eth_fast_transit:
                report.warnings.append(
                    f"[{chain_label}][ETH] Fast transit: inflow {eth_in:.4f} ETH (${eth_in_usd:,.0f}) / "
                    f"outflow {eth_out:.4f} ETH (${eth_out_usd:,.0f}) / balance {eth_balance:.4f} ETH"
                )

        # ETH 交易加入 report.transactions，供 counterparty_table 使用（金额以 USD 计）
        _eth_proto = {"0x0000000000000000000000000000000000000000"}
        for tx in normal_txs:
            frm = normalize(tx.get("from", ""))
            t   = normalize(tx.get("to", "") or "")
            try:
                val = int(tx.get("value", "0") or "0") / 1e18
            except Exception:
                val = 0.0
            if val <= 0:
                continue
            direction = counterparty = ""
            if t == addr_norm:
                direction, counterparty = "IN", frm
            elif frm == addr_norm:
                direction, counterparty = "OUT", t
            if direction and counterparty and counterparty not in _eth_proto:
                report.transactions.append({
                    "ts":           tx.get("timeStamp", ""),
                    "direction":    direction,
                    "amount":       round(val, 6),          # 原始 ETH，不转 USD
                    "amount_usd":   round(val * self.eth_price_usd, 2),  # 仅供 total_usd 计算
                    "sym":          chain_cfg.native_token,
                    "method_id":     tx.get("methodId", ""),
                    "method":        tx.get("functionName", "") or tx.get("methodId", "") or "Transfer",
                    "action_type":   "Native Transfer",
                    "chain":        chain_name,
                    "counterparty": counterparty.lower(),
                    "tx_hash":      tx.get("hash", ""),
                })

        self._build_contract_interactions(
            report, normal_txs, token_txs, chain_cfg, chain_name, address
        )

        usdt_logs = []
        if len(normal_txs) == 0 and len(token_txs) == 0:
            print(f"  [{chain_label}] txlist/tokentx 无结果，尝试稳定币 getLogs...")
            usdt_logs = self._get_usdt_logs(address, client, chain_cfg,
                                            from_block=from_block, to_block=to_block)
            if usdt_logs:
                print(f"  [{chain_label}] getLogs 获取到 {len(usdt_logs)} 条稳定币 Transfer 事件")

        # 去重合并
        _seen: Set[tuple] = set()
        all_txs = []
        for tx in normal_txs + token_txs:
            k = (tx.get("hash", ""),
                 normalize(tx.get("from", "")),
                 normalize(tx.get("to", "") or tx.get("contractAddress", "")))
            if k not in _seen:
                _seen.add(k)
                all_txs.append(tx)

        if time_cutoff > 0 and usdt_logs:
            before = len(usdt_logs)
            usdt_logs = [lg for lg in usdt_logs if int(lg.get("timeStamp", 0)) >= time_cutoff]
            if before != len(usdt_logs):
                print(f"  [{chain_label}] getLogs 时间过滤: {before}→{len(usdt_logs)}")

        report.total_transactions += len(all_txs) + len(usdt_logs)
        print(f"  [{chain_label}] {len(normal_txs)} 普通 + {len(token_txs)} ERC20 Token"
              + (f" + {len(usdt_logs)} getLogs事件" if usdt_logs else ""))

        PROTOCOL_CONTRACTS = {
            chain_cfg.usdt_contract,
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC ETH
            "0x0000000000000000000000000000000000000000",
        }

        counterparties: Set[str] = set()
        counterparty_dir_stats: Dict[str, Dict[str, int]] = {}
        counterparty_stats: Dict[str, Dict] = {}
        # 记录被分析地址与每个对手方的实际 USDT 往来（用于 2-hop 金额）
        cp_usdt_flow: Dict[str, Dict[str, float]] = {}  # cp -> {"IN": x, "OUT": y}

        # 风险积累器：key = (counterparty, risk_type, via_address)
        risky_accum: Dict[tuple, dict] = {}

        def _add_risk(cp: str, risk_type: str, category: str, weight: float,
                      direction: str, usdt_amt: float, tx_hash: str, ts: str,
                      hop: int = 1, via: str = "", token: str = "",
                      native_amt: float = 0.0):
            key = (cp, risk_type, via)
            if key not in risky_accum:
                risky_accum[key] = {
                    "category": category, "category_weight": weight,
                    "counterparty": cp, "in_usdt": 0.0, "out_usdt": 0.0,
                    "tx_hashes": [], "timestamps": [], "hop": hop, "via_address": via,
                    "token": token,
                    # 非稳定币转账的原始金额（按方向累加）
                    "native_in": {},   # {sym: amount}
                    "native_out": {},  # {sym: amount}
                }
            entry = risky_accum[key]
            if direction == "IN":
                entry["in_usdt"] += usdt_amt
                if native_amt > 0 and token:
                    entry["native_in"][token] = entry["native_in"].get(token, 0.0) + native_amt
            else:
                entry["out_usdt"] += usdt_amt
                if native_amt > 0 and token:
                    entry["native_out"][token] = entry["native_out"].get(token, 0.0) + native_amt
            if tx_hash and len(entry["tx_hashes"]) < 5:
                entry["tx_hashes"].append(tx_hash)
                entry["timestamps"].append(ts)

        # ── 遍历所有交易 ──────────────────────────────────────────────
        chain_inflow = 0.0
        chain_outflow = 0.0

        for tx in all_txs:
            frm = normalize(tx.get("from", ""))
            to  = normalize(tx.get("to", "") or tx.get("contractAddress", ""))
            if frm == addr_norm:
                other, direction = to, "OUT"
            elif to == addr_norm:
                other, direction = frm, "IN"
            else:
                continue
            if not other or other == addr_norm or other in PROTOCOL_CONTRACTS:
                continue

            sym = (tx.get("_sym") or tx.get("tokenSymbol") or "ETH").upper()
            is_stable = sym in STABLECOIN_SYMBOLS
            is_eth = (sym == "ETH")
            try:
                dec = int(tx.get("tokenDecimal", "18") or "18")
                if sym == "DAI": dec = 18
                amt = int(tx.get("value", "0") or "0") / (10 ** dec)
            except Exception:
                amt = 0.0
            # 污染评分：稳定币用面值，ETH 用折 USD（其他代币不参与评分）
            usdt_amt = amt if is_stable else (amt * self.eth_price_usd if is_eth else 0.0)

            # 流量已在 per-asset 循环里累加，这里只做 chain 分链记录
            if is_stable:
                if direction == "IN":
                    chain_inflow += amt
                else:
                    chain_outflow += amt

            counterparties.add(other)
            counterparty_dir_stats.setdefault(other, {"IN": 0, "OUT": 0})[direction] += 1
            s = counterparty_stats.setdefault(other, {"count": 0, "total_value": 0.0, "max_value": 0.0})
            s["count"] += 1
            if is_stable:
                s["total_value"] += amt
                s["max_value"] = max(s["max_value"], amt)
                # 记录实际稳定币边金额，供 2-hop 评分使用
                flow = cp_usdt_flow.setdefault(other, {"IN": 0.0, "OUT": 0.0})
                flow[direction] += amt

            tx_hash = tx.get("hash", "")
            ts = tx.get("timeStamp", "")

            for chk, chk_dir in [(to, "OUT" if frm == addr_norm else "IN"),
                                  (frm, "IN"  if frm != addr_norm else "OUT")]:
                if not chk or chk == addr_norm or chk in PROTOCOL_CONTRACTS:
                    continue

                # native_amt 只给非稳定币 ERC20（ETH 已折 USD 进 usdt_amt，不需要再走 native）
                _native_amt = amt if (not is_stable and not is_eth) else 0.0

                if chk in self.blacklist:
                    _add_risk(chk, "blacklist", "blacklist",
                              CATEGORY_WEIGHTS["blacklist"], chk_dir, usdt_amt, tx_hash, ts,
                              token=sym, native_amt=_native_amt)

                if chk in OFAC_SANCTIONED_ADDRS:
                    ofac_info = OFAC_SANCTIONED[chk]
                    _add_risk(chk, "ofac_sanctioned", "ofac_sanctioned",
                              CATEGORY_WEIGHTS["ofac_sanctioned"], chk_dir, usdt_amt, tx_hash, ts,
                              via=ofac_info.get("entity", ""),
                              token=sym, native_amt=_native_amt)

                if chk in MIXER_CONTRACTS:
                    report.mixer_interactions.append({
                        "mixer": MIXER_CONTRACTS[chk], "contract": chk,
                        "tx": tx_hash, "direction": chk_dir, "chain": chain_name,
                    })
                    _add_risk(chk, "mixer", "mixer",
                              CATEGORY_WEIGHTS["mixer"], chk_dir, usdt_amt, tx_hash, ts,
                              token=sym, native_amt=_native_amt)

                bridge_info = BRIDGE_REGISTRY.get(chk)
                if bridge_info:
                    entry = {
                        "bridge": bridge_info["name"], "contract": chk,
                        "tx": tx_hash, "direction": chk_dir,
                        "token": sym, "traceable": bridge_info["traceable"],
                        "method": bridge_info["method"], "dst_chains": bridge_info["dst_chains"],
                        "chain": chain_name,
                    }
                    if bridge_info["traceable"]:
                        report.bridge_interactions.append(entry)
                    else:
                        report.opaque_bridge_interactions.append(entry)
                        _add_risk(chk, "opaque_bridge", "opaque_bridge",
                                  CATEGORY_WEIGHTS["opaque_bridge"], chk_dir, usdt_amt, tx_hash, ts,
                                  token=sym, native_amt=_native_amt)

                if chk in HIGH_RISK_EXCHANGES:
                    report.high_risk_exchanges.append({
                        "exchange": HIGH_RISK_EXCHANGES_FLAT[chk], "contract": chk,
                        "tx": tx_hash, "direction": chk_dir, "chain": chain_name,
                    })
                    _add_risk(chk, "high_risk_exchange", "high_risk_exchange",
                              CATEGORY_WEIGHTS["high_risk_exchange"], chk_dir, usdt_amt, tx_hash, ts,
                              token=sym, native_amt=_native_amt)

        # USDT getLogs 补充对手方
        for log in usdt_logs:
            topics = log.get("topics", [])
            if len(topics) < 3:
                continue
            log_from = "0x" + topics[1][-40:]
            log_to   = "0x" + topics[2][-40:]
            role = log.get("_role", "")
            other = log_to if role == "sender" else log_from
            direction = "OUT" if role == "sender" else "IN"
            if other and other != addr_norm:
                counterparties.add(other)
                counterparty_dir_stats.setdefault(other, {"IN": 0, "OUT": 0})[direction] += 1
                counterparty_stats.setdefault(other, {"count": 0, "total_value": 0.0, "max_value": 0.0})["count"] += 1

        report.total_counterparties += len(counterparties)
        report.per_chain_inflow[chain_name] = round(chain_inflow, 2)
        report.per_chain_outflow[chain_name] = round(chain_outflow, 2)
        print(f"  [{chain_label}] 1-hop 共 {len(counterparties)} 个对手方 | "
              f"稳定币流入 {chain_inflow:,.2f} / 流出 {chain_outflow:,.2f}")

        # ── 风险积累器 → RiskIndicator（1-hop）────────────────────────
        for (cp, risk_type, via), data in risky_accum.items():
            hop_d = HOP_DECAY[data["hop"]]
            # 合并所有方向的原始非稳定币数量，供 counterparty_table 补 by_sym 用
            all_native = {}
            for sym_k, v in data.get("native_in",  {}).items():
                all_native[sym_k] = all_native.get(sym_k, 0.0) + v
            for sym_k, v in data.get("native_out", {}).items():
                all_native[sym_k] = all_native.get(sym_k, 0.0) + v

            for d, amt in [("IN", data["in_usdt"]), ("OUT", data["out_usdt"])]:
                if amt > 0:
                    report.indicators.append(RiskIndicator(
                        indicator_type=f"{risk_type}_{'received' if d == 'IN' else 'sent'}",
                        category=data["category"],
                        category_weight=data["category_weight"],
                        counterparty=cp, direction=d, amount_usdt=amt,
                        hop=data["hop"], hop_decay=hop_d,
                        tx_hashes=data["tx_hashes"], timestamps=data["timestamps"],
                        via_address=data["via_address"],
                        chain=chain_name,
                        token=data.get("token", ""),
                        native_amounts=all_native,
                    ))
            if data["in_usdt"] == 0.0 and data["out_usdt"] == 0.0:
                # 构造实际转账说明（非稳定币）
                native_parts = []
                for sym_k, v in data.get("native_in", {}).items():
                    native_parts.append(f"received {v:,.4f} {sym_k}")
                for sym_k, v in data.get("native_out", {}).items():
                    native_parts.append(f"sent {v:,.4f} {sym_k}")
                if native_parts:
                    native_note = ", ".join(native_parts)
                else:
                    token_name = data.get("token", "")
                    tx_count = len(data['tx_hashes'])
                    if token_name and token_name != "ETH":
                        native_note = f"{tx_count} contract call(s) to {token_name}, no token transfer (possibly approve/allowance)"
                    else:
                        native_note = f"{tx_count} contract call(s), no ETH/token transfer (possibly approve or other contract interaction)"
                report.indicators.append(RiskIndicator(
                    indicator_type=f"{risk_type}_no_stable",
                    category=data["category"],
                    category_weight=data["category_weight"],
                    counterparty=cp, direction="UNKNOWN", amount_usdt=0.0,
                    hop=data["hop"], hop_decay=hop_d,
                    tx_hashes=data["tx_hashes"], timestamps=data["timestamps"],
                    via_address=data["via_address"],
                    chain=chain_name,
                    note=native_note,
                    native_amounts=all_native,
                ))

        # ── top_counterparties（展示用，只取当前链）──────────────────────
        _excl = (PROTOCOL_CONTRACTS | ALL_BRIDGE_ADDRS
                 | set(MIXER_CONTRACTS) | set(HIGH_RISK_EXCHANGES) | KNOWN_DEX_ADDRS)
        scored = [(a, s, s["max_value"]*0.6 + s["total_value"]*0.3 + s["count"]*0.1)
                  for a, s in counterparty_stats.items()
                  if a not in _excl and a not in self.blacklist]
        scored.sort(key=lambda x: x[2], reverse=True)
        for a, s, _ in scored[:10]:
            report.top_counterparties.append({
                "address": a, "tx_count": s["count"],
                "total_value": round(s["total_value"], 4), "max_value": round(s["max_value"], 4),
                "in_count": counterparty_dir_stats.get(a, {}).get("IN", 0),
                "out_count": counterparty_dir_stats.get(a, {}).get("OUT", 0),
                "chain": chain_name,
            })

        # ── 2-hop 分析 ───────────────────────────────────────────────
        # 遍历目标地址的普通对手方（非已知协议地址），检测它们是否
        # 直接与黑名单/混币器/不透明桥/高风险交易所交互。
        # 衰减：hop1=1.0, hop2=0.3（每多一跳，证据强度显著下降）
        _protocol_excl = (set(self.blacklist) | ALL_BRIDGE_ADDRS
                          | set(MIXER_CONTRACTS) | set(HIGH_RISK_EXCHANGES) | KNOWN_DEX_ADDRS)

        def _score_cp_node(txs, cp_addr) -> Dict[str, tuple]:
            """计算 cp 的真实污染比例（taint_ratio）。

            公式：taint_ratio = Σ(风险往来金额 × 类别权重) / cp 该方向 USDT 总流量

            返回 {direction: (taint_ratio, best_category, best_risky_entity, tx_hash, ts)}
            - taint_ratio: 0~1，cp 在该方向上有多少比例的资金与风险实体相关
            - best_category: 权重最高的风险类别（用于展示和 floor 判断）
            - best_risky_entity: 对应的风险地址（溯源证据）
            后续可在此函数内加入洗钱手法识别（peel chain、structuring 等）。
            """
            in_total  = 0.0   # cp 的 USDT 总流入（样本）
            out_total = 0.0   # cp 的 USDT 总流出（样本）
            in_risky_weighted  = 0.0  # Σ(risky_usdt × weight)，IN 方向
            out_risky_weighted = 0.0  # Σ(risky_usdt × weight)，OUT 方向
            best_in  = None   # (cat, weight, risky_addr, hash, ts)
            best_out = None

            for tx in txs:
                t = normalize(tx.get("to", "") or "")
                f = normalize(tx.get("from", "") or "")
                if f == cp_addr and t and t != cp_addr:
                    other, d = t, "OUT"
                elif t == cp_addr and f and f != cp_addr:
                    other, d = f, "IN"
                else:
                    continue
                if not other or other == addr_norm or other in PROTOCOL_CONTRACTS:
                    continue

                sym = (tx.get("tokenSymbol") or "").upper()
                try:
                    dec = int(tx.get("tokenDecimal", "18") or "18")
                    amt = int(tx.get("value", "0") or "0") / (10 ** dec)
                except Exception:
                    amt = 0.0
                usdt = amt if sym in STABLECOIN_SYMBOLS else 0.0

                h  = tx.get("hash", "")
                ts = tx.get("timeStamp", "")

                # 累计 cp 的总稳定币流量（分子分母都需要）
                if d == "IN":
                    in_total += usdt
                else:
                    out_total += usdt

                # 识别 other 的风险类别（取最高权重）
                risk_cat, risk_w = None, 0.0
                if other in self.blacklist and CATEGORY_WEIGHTS["blacklist"] > risk_w:
                    risk_cat, risk_w = "blacklist", CATEGORY_WEIGHTS["blacklist"]
                if other in MIXER_CONTRACTS and CATEGORY_WEIGHTS["mixer"] > risk_w:
                    risk_cat, risk_w = "mixer", CATEGORY_WEIGHTS["mixer"]
                if other in OPAQUE_BRIDGE_ADDRS and CATEGORY_WEIGHTS["opaque_bridge"] > risk_w:
                    risk_cat, risk_w = "opaque_bridge", CATEGORY_WEIGHTS["opaque_bridge"]
                if other in HIGH_RISK_EXCHANGES_FLAT and CATEGORY_WEIGHTS["high_risk_exchange"] > risk_w:
                    risk_cat, risk_w = "high_risk_exchange", CATEGORY_WEIGHTS["high_risk_exchange"]
                if other in ALL_BRIDGE_ADDRS and other not in OPAQUE_BRIDGE_ADDRS \
                        and CATEGORY_WEIGHTS["transparent_bridge"] > risk_w:
                    risk_cat, risk_w = "transparent_bridge", CATEGORY_WEIGHTS["transparent_bridge"]

                if risk_cat:
                    if d == "IN":
                        in_risky_weighted += usdt * risk_w
                        if best_in is None or risk_w > best_in[1]:
                            best_in = (risk_cat, risk_w, other, h, ts)
                    else:
                        out_risky_weighted += usdt * risk_w
                        if best_out is None or risk_w > best_out[1]:
                            best_out = (risk_cat, risk_w, other, h, ts)

            result: Dict[str, tuple] = {}
            if best_in is not None:
                taint = min(in_risky_weighted / in_total, 1.0) if in_total > 0 else 0.0
                result["IN"] = (taint, best_in[0], best_in[2], best_in[3], best_in[4])
            if best_out is not None:
                taint = min(out_risky_weighted / out_total, 1.0) if out_total > 0 else 0.0
                result["OUT"] = (taint, best_out[0], best_out[2], best_out[3], best_out[4])
            return result

        if HOP2_ENABLED and counterparties:
            # 2-hop 中间节点：排除已知高风险地址（它们已在 1-hop 检测到）
            # 优先分析有实际稳定币/ETH 往来的对手方，最多 3 个（控制 API 调用量）
            hop2_candidates = sorted(
                [cp for cp in counterparties if cp not in _protocol_excl],
                key=lambda cp: cp_usdt_flow.get(cp, {}).get("IN", 0) + cp_usdt_flow.get(cp, {}).get("OUT", 0),
                reverse=True,
            )[:5]
            hop2_nodes = hop2_candidates
            if hop2_nodes:
                print(f"  [{chain_label}] 2-hop 分析 {len(hop2_nodes)} 个中间节点...")

            hop_d = HOP_DECAY[2]

            # 并发拉取对手方交易（I/O 密集）。原来是串行 + 每个 sleep 0.25s，
            # 把 5 次/秒的限速额度用成了串行；这里在额度内并发，单地址快数倍。
            # 只并行「取数」；评分和写 report.indicators 仍串行——避免对共享 report
            # 的并发写，也无需加锁。client 用独立 requests 调用，并发安全。
            def _fetch_cp(cp: str):
                txs = client.get_normal_txs(cp, limit=100) + client.get_token_transfers(cp, limit=100)
                return cp, txs

            with ThreadPoolExecutor(max_workers=min(5, len(hop2_nodes))) as pool:
                fetched = list(pool.map(_fetch_cp, hop2_nodes))

            for cp, cp_all_txs in fetched:
                cp_risk = _score_cp_node(cp_all_txs, cp)
                if not cp_risk:
                    continue

                # cp 是被评分的节点：counterparty=cp, via_address=cp 接触的风险实体
                # d 是 CP 相对于风险实体的方向，≠ 被分析地址相对于 CP 的方向。
                # 修正：对每个被分析地址↔CP 的实际稳定币边（IN/OUT），取 cp_risk 最高污染比例。
                edge = cp_usdt_flow.get(cp, {})
                # 为每个 analyzed_dir 取 cp_risk 中最高的 taint_ratio
                best: Dict[str, tuple] = {}  # analyzed_dir -> (taint_ratio, cat, risky_entity, h, ts)
                for d, (taint_ratio, cat, risky_entity, h, ts) in cp_risk.items():
                    if taint_ratio == 0:
                        continue
                    for analyzed_dir in ("IN", "OUT"):
                        if edge.get(analyzed_dir, 0.0) <= 0:
                            continue
                        if analyzed_dir not in best or taint_ratio > best[analyzed_dir][0]:
                            best[analyzed_dir] = (taint_ratio, cat, risky_entity, h, ts)
                for analyzed_dir, (taint_ratio, cat, risky_entity, h, ts) in best.items():
                    report.indicators.append(RiskIndicator(
                        indicator_type=f"cp_node_{cat}",
                        category=cat,
                        category_weight=taint_ratio,  # cp 的真实污染比例，非类别权重常量
                        counterparty=cp,
                        direction=analyzed_dir,
                        amount_usdt=edge.get(analyzed_dir, 0.0),
                        hop=2,
                        hop_decay=hop_d,
                        tx_hashes=[h] if h else [],
                        timestamps=[ts] if ts else [],
                        via_address=risky_entity,
                        chain=chain_name,
                    ))

        # ── 透明桥跨链追踪 ─────────────────────────────────────────────
        if BRIDGE_TRACE_ENABLED and report.bridge_interactions:
            out_bridges = [b for b in report.bridge_interactions
                           if b.get("direction") == "OUT" and b.get("chain") == chain_name]
            seen_tx: Set[str] = set()
            if out_bridges:
                print(f"  [{chain_label}] 透明桥跨链追踪（{min(len(out_bridges), 5)} 笔）...")
            for b in out_bridges[:5]:
                tx_hash = b.get("tx", "")
                if not tx_hash or tx_hash in seen_tx:
                    continue
                seen_tx.add(tx_hash)
                time.sleep(REQUEST_DELAY)
                result = self.tracer.resolve(
                    tx_hash=tx_hash, method=b.get("method", ""),
                    src_address=addr_norm, dst_chains_hint=b.get("dst_chains", []),
                )
                if not result:
                    print(f"  [{chain_label}]   {b['bridge']}: 无法解析对端地址")
                    continue
                dst_addr  = normalize(result.get("dst_address", ""))
                dst_chain = result.get("dst_chain", "")
                finding = {
                    "bridge": b["bridge"], "src_tx": tx_hash,
                    "dst_chain": dst_chain, "dst_address": dst_addr,
                    "dst_tx": result.get("dst_tx", ""),
                    "blacklisted": False, "blacklist_info": {}, "hop1_blacklisted": [],
                    "src_chain": chain_name,
                }
                if dst_addr and dst_addr in self.blacklist:
                    finding["blacklisted"] = True
                    finding["blacklist_info"] = self.blacklist[dst_addr]
                    print(f"  [!!!] 桥接目标命中黑名单: {dst_addr} ({dst_chain})")
                    report.indicators.append(RiskIndicator(
                        indicator_type="cross_chain_blacklist",
                        category="blacklist",
                        category_weight=CATEGORY_WEIGHTS["blacklist"],
                        counterparty=dst_addr, direction="OUT", amount_usdt=0.0,
                        hop=1, hop_decay=HOP_DECAY[1],
                        tx_hashes=[tx_hash], timestamps=[],
                        chain=chain_name,
                        note=f"跨链对端黑名单 ({dst_chain})",
                    ))
                elif dst_addr and dst_chain and dst_chain != chain_name:
                    hop1 = self._check_dst_hop1(dst_addr, dst_chain)
                    if hop1:
                        finding["hop1_blacklisted"] = hop1
                        print(f"  [!] 桥对端 {dst_chain}:{dst_addr[:16]}... 1跳有 {len(hop1)} 个黑名单")
                        report.indicators.append(RiskIndicator(
                            indicator_type="cross_chain_hop1_blacklist",
                            category="transparent_bridge_with_bl",
                            category_weight=CATEGORY_WEIGHTS["transparent_bridge_with_bl"],
                            counterparty=dst_addr, direction="OUT", amount_usdt=0.0,
                            hop=2, hop_decay=HOP_DECAY[2],
                            tx_hashes=[tx_hash], timestamps=[],
                            chain=chain_name,
                            note=f"跨链对端1跳黑名单 ({dst_chain})",
                        ))
                    else:
                        report.indicators.append(RiskIndicator(
                            indicator_type="transparent_bridge",
                            category="transparent_bridge",
                            category_weight=CATEGORY_WEIGHTS["transparent_bridge"],
                            counterparty=dst_addr, direction="OUT", amount_usdt=0.0,
                            hop=1, hop_decay=HOP_DECAY[1],
                            tx_hashes=[tx_hash], timestamps=[],
                            chain=chain_name,
                            note=f"透明桥无黑名单 ({dst_chain})",
                        ))
                report.cross_chain_findings.append(finding)

    # ---------- Tron 分析 ----------
    def _analyze_tron(self, address: str, report: RiskReport):
        tron_b58 = hex_to_tron_base58(address)
        report.tron_address = tron_b58
        print(f"  [TRON] 地址转换: {address} → {tron_b58}")
        trc20_txs = self.tron.get_trc20_transfers(tron_b58)
        trx_txs   = self.tron.get_transactions(tron_b58)
        report.account_info = self.tron.get_account_info(tron_b58)
        report.total_transactions = len(trc20_txs) + len(trx_txs)
        print(f"  [TRON] {len(trc20_txs)} TRC20 + {len(trx_txs)} TRX")

        counterparties: Set[str] = set()
        addr_b58_lower = tron_b58.lower()
        for tx in trc20_txs:
            f = (tx.get("from_address") or tx.get("transferFromAddress") or "").lower()
            t = (tx.get("to_address")   or tx.get("transferToAddress")   or "").lower()
            for a in [f, t]:
                if a and a != addr_b58_lower:
                    counterparties.add(a)
        for tx in trx_txs:
            for a in [(tx.get("ownerAddress") or "").lower(), (tx.get("toAddress") or "").lower()]:
                if a and a != addr_b58_lower:
                    counterparties.add(a)

        report.total_counterparties = len(counterparties)
        print(f"  [TRON] {len(counterparties)} 个对手方")

        bl_tron = {a: info for a, info in self.blacklist.items() if info.get("chain") == "tron"}
        for cp_b58 in counterparties:
            try:
                cp_hex = _tron_b58_to_hex(cp_b58)
                if cp_hex and cp_hex in bl_tron:
                    info = bl_tron[cp_hex]
                    report.indicators.append(RiskIndicator(
                        indicator_type="blacklist_received",
                        category="blacklist",
                        category_weight=CATEGORY_WEIGHTS["blacklist"],
                        counterparty=cp_b58, direction="IN", amount_usdt=0.0,
                        hop=1, hop_decay=HOP_DECAY[1],
                        tx_hashes=[], timestamps=[],
                        chain="tron",
                        note=f"Tron 黑名单，封禁: {info['time']}",
                    ))
            except Exception:
                pass

    # ---------- 风险评分（污染比例模型）----------
    def _calculate_risk(self, report: RiskReport):
        if report.is_blacklisted:
            # 名单命中是确定性风险（list_based），不是资金流污染。
            # 因此不把 flow 暴露字段伪造成 1.0——它们保持默认 0（未计算），
            # 由 risk_basis + score_breakdown 透明说明 100 分的来源。
            report.risk_score = 100
            report.risk_level = "CRITICAL"
            report.risk_basis = "list_based"
            breakdown = {"basis": "list_based", "direct_blacklist_match": 100}
            if report.usdt_blacklist_time:
                breakdown["usdt_blacklist_time"] = report.usdt_blacklist_time
            if report.ofac_sdn_match:
                breakdown["ofac_sdn_entity"] = report.ofac_entity or "Unknown"
            report.score_breakdown = breakdown
            return

        # 分母：稳定币 + ETH 折 USD，与分子保持一致（分子已含 ETH usdt_amt）
        total_in  = report.total_inflow_usdt  + report.total_eth_usd_in
        total_out = report.total_outflow_usdt + report.total_eth_usd_out
        total_flow = total_in + total_out

        received_taint = 0.0
        sent_taint     = 0.0
        presence_only: List[RiskIndicator] = []

        for ind in report.indicators:
            if ind.amount_usdt == 0.0:
                presence_only.append(ind)
                continue
            effective = ind.amount_usdt * ind.category_weight * ind.hop_decay
            if ind.direction == "IN" and total_in > 0:
                received_taint += effective / total_in
            elif ind.direction == "OUT" and total_out > 0:
                sent_taint += effective / total_out

        received_taint = min(received_taint, 1.0)
        sent_taint     = min(sent_taint, 1.0)

        taint_ratio = max(received_taint, sent_taint)

        if total_flow == 0 and presence_only:
            report.warnings.append("No stablecoin or ETH transactions found. Score based on association only — accuracy limited.")

        # Presence-only: interactions with risk entities but no stablecoin/ETH transfer
        # Does not affect score, surfaced for manual review.
        _category_en = {
            "blacklist":          "Blacklist",
            "ofac_sanctioned":    "OFAC Sanctioned",
            "mixer":              "Mixer",
            "opaque_bridge":      "Opaque Bridge",
            "high_risk_exchange": "High-Risk Exchange",
        }
        for ind in presence_only:
            label   = _category_en.get(ind.category, ind.category.replace("_", " ").title())
            hop_tag = f"{ind.hop}-hop " if ind.hop > 1 else ""
            via     = f" via {ind.via_address[:10]}..." if ind.via_address else ""
            if ind.native_amounts:
                parts  = [f"{v:,.4f} {s}" for s, v in ind.native_amounts.items()]
                detail = f"transferred: {', '.join(parts)}"
            elif ind.note:
                detail = ind.note
            else:
                detail = "no fund transfer detected"
            report.warnings.append(
                f"[Non-financial contact] {hop_tag}{label}: {ind.counterparty}{via}"
                f" — {detail} (not scored)"
            )

        report.received_exposure = round(received_taint, 4)
        report.sent_exposure     = round(sent_taint, 4)
        report.taint_ratio       = round(taint_ratio, 4)
        report.risk_basis        = "flow_based"
        final_score = round(min(taint_ratio * 100, 100), 2)
        report.risk_score = final_score

        hop2_cats = {ind.category for ind in report.indicators if ind.hop == 2 and ind.amount_usdt > 0}

        report.risk_level = risk_level(report.risk_score)

        report.score_breakdown = {
            "basis": "flow_based",
            "received_taint_pct": round(received_taint * 100, 2),
            "sent_taint_pct":     round(sent_taint * 100, 2),
            "final_score":        final_score,
            "hop2_categories":    sorted(hop2_cats),
        }

        # ── 对手方聚合表 ────────────────────────────────────────────────
        self._build_counterparty_table(report)

    def _build_counterparty_table(self, report: RiskReport):
        """按 (地址, 方向) 聚合所有稳定币流水，附加风险标签和污染贡献。"""
        from collections import defaultdict

        # 聚合: key=(counterparty, direction) → {sym: amount}
        # 稳定币 amount = USD 面值；原生代币(ETH/BNB等) amount = 原始数量
        agg: Dict[tuple, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        # total_usd = 稳定币 + 原生代币折 USD，用于排序
        agg_usd: Dict[tuple, float] = defaultdict(float)
        # stable_usd = 仅稳定币 USD，用于稳定币表"Total"列和 % of Flow
        agg_stable_usd: Dict[tuple, float] = defaultdict(float)
        # native_usd = 仅原生代币折 USD（有 amount_usd 字段的），用于 ETH 表 % of Flow
        agg_native_usd: Dict[tuple, float] = defaultdict(float)
        for tx in report.transactions:
            key = (tx["counterparty"].lower(), tx["direction"])
            agg[key][tx["sym"]] += tx["amount"]
            # amount_usd 只有原生代币(ETH/BNB)才有，稳定币用 amount，其他 ERC20 用 0
            native_usd_val = tx.get("amount_usd", 0.0)
            if tx["sym"] in STABLECOIN_SYMBOLS:
                agg_stable_usd[key] += tx["amount"]
                agg_usd[key] += tx["amount"]
            elif native_usd_val:          # 原生代币（有 amount_usd）
                agg_native_usd[key] += native_usd_val
                agg_usd[key] += native_usd_val
            # 其他 ERC20：不计入 agg_usd（无可靠 USD 价格）

        # 从 indicators 取各对手方的污染贡献（分母与评分保持一致：稳定币 + ETH）
        total_in  = report.total_inflow_usdt  + report.total_eth_usd_in
        total_out = report.total_outflow_usdt + report.total_eth_usd_out
        taint_by_cp: Dict[str, float] = {}   # counterparty.lower() → taint_pct
        for ind in report.indicators:
            if ind.amount_usdt == 0.0:
                continue
            basis = total_in if ind.direction == "IN" else total_out
            if basis > 0:
                pct = ind.amount_usdt * ind.category_weight * ind.hop_decay / basis * 100
                cp_key = ind.counterparty.lower()
                taint_by_cp[cp_key] = taint_by_cp.get(cp_key, 0.0) + pct

        # 数据库查询：对手方风险标签
        def _get_tags(addr: str) -> List[str]:
            tags = []
            a = addr.lower()
            if a in self.blacklist:
                tags.append("blacklist")
            if a in OFAC_SANCTIONED_ADDRS:
                tags.append("ofac_sanctioned")
            if a in {c.lower() for c in MIXER_CONTRACTS}:
                tags.append("mixer")
            if a in {c.lower() for c in OPAQUE_BRIDGE_ADDRS}:
                tags.append("opaque_bridge")
            if a in {c.lower() for c in HIGH_RISK_EXCHANGES_FLAT}:
                tags.append("high_risk_exchange")
            return tags

        rows = []
        existing_cps: Set[tuple] = set()
        for (cp, direction), by_sym in agg.items():
            total_usd = agg_usd[(cp, direction)]
            existing_cps.add((cp, direction))
            rows.append({
                "address":         cp,
                "direction":       direction,
                "total_usd":       round(total_usd, 2),
                "stable_usd":      round(agg_stable_usd[(cp, direction)], 2),
                "native_usd":      round(agg_native_usd[(cp, direction)], 2),
                "by_sym":          {sym: round(v, 6 if sym not in STABLECOIN_SYMBOLS else 2)
                                    for sym, v in sorted(by_sym.items())},
                "risk_tags":       _get_tags(cp),
                "taint_pct":       round(taint_by_cp.get(cp, 0.0), 2),
                "contract_only":   False,
            })

        # 合约交互（presence_only）：value=0 的黑名单/mixer 联系，不在 transactions 里
        # 补入 CP 表格，让它们在 Entity 列显示风险标签，direction 用 CONTACT
        seen_contact: Set[str] = set()
        for ind in report.indicators:
            if ind.amount_usdt != 0.0:
                continue
            cp = ind.counterparty.lower()
            if cp in seen_contact:
                continue
            seen_contact.add(cp)
            # 如果该 CP 已有实际转账行，在那行的 risk_tags 里补上标签即可，不重复加行
            matched = [r for r in rows if r["address"] == cp]
            if matched:
                for r in matched:
                    for tag in _get_tags(cp):
                        if tag not in r["risk_tags"]:
                            r["risk_tags"].append(tag)
            else:
                # 完全没有资金往来的合约交互，单独加一行
                rows.append({
                    "address":       cp,
                    "direction":     ind.direction if ind.direction != "UNKNOWN" else "CONTACT",
                    "total_usd":     0.0,
                    "by_sym":        {},
                    "risk_tags":     _get_tags(cp),
                    "taint_pct":     0.0,
                    "contract_only": True,
                    "contact_note":  ind.note or "contract interaction",
                })

        # 把 indicator 里记录的非稳定币原始数量补进对应 CP 行的 by_sym
        # 这样风险对手方（黑名单/Mixer/OFAC）涉及的 LINK/BNB 等也能在 token 表里显示
        for ind in report.indicators:
            if not ind.native_amounts:
                continue
            cp = ind.counterparty.lower()
            for row in rows:
                if row["address"] == cp:
                    for sym, amt in ind.native_amounts.items():
                        if sym not in row["by_sym"]:
                            row["by_sym"][sym] = 0.0
                        row["by_sym"][sym] = round(row["by_sym"][sym] + amt, 6)

        # 排序：有资金往来的按金额降序，纯合约交互排最后
        rows.sort(key=lambda r: (r.get("contract_only", False),
                                 r["direction"] == "OUT",
                                 -r["total_usd"]))
        report.counterparty_table = rows

    # ---------- 主入口 ----------
    def analyze(self, address: str, chain: Optional[str] = None,
                chains: Optional[List[str]] = None) -> RiskReport:
        """
        chain  : 指定单链（"ethereum"/"bsc"/... 或 "tron"），None = 自动
        chains : 指定多链列表（优先级高于 chain），None = 自动
        """
        addr_norm = normalize(address)

        # 判断链类型
        if chain == "tron":
            run_tron = True
            evm_chains_to_run = []
        elif chains:
            run_tron = False
            evm_chains_to_run = [c for c in chains if c in EVM_CHAIN_REGISTRY]
        elif chain and chain in EVM_CHAIN_REGISTRY:
            run_tron = False
            evm_chains_to_run = [chain]
        elif chain is None:
            # 自动检测：黑名单中标记为 tron，或地址不以 0x 开头
            bl_chain = self.blacklist.get(addr_norm, {}).get("chain", "")
            if bl_chain == "tron" or not address.startswith("0x"):
                run_tron = True
                evm_chains_to_run = []
            else:
                run_tron = False
                # 默认只跑 Ethereum；跨链活动由 BridgeTracer 在链内追踪
                # 需要多链分析时用 --chains ethereum,bsc,polygon 显式指定
                evm_chains_to_run = ["ethereum"]
        else:
            run_tron = False
            evm_chains_to_run = ["ethereum"]

        # 决定 report 的主链标签
        if run_tron:
            primary_chain = "tron"
        elif len(evm_chains_to_run) == 1:
            primary_chain = evm_chains_to_run[0]
        else:
            primary_chain = "multi-evm"

        report = RiskReport(address=addr_norm, chain=primary_chain)

        print(f"\n{'='*60}")
        print(f"分析地址: {addr_norm}")
        print(f"链类型:   {primary_chain}")
        print(f"{'='*60}")

        if addr_norm in self.blacklist:
            info = self.blacklist[addr_norm]
            report.is_blacklisted = True
            report.usdt_blacklist_time = info["time"]
            report.blacklist_time = info["time"]   # 向后兼容
            report.warnings.append(f"[!] Address is on the USDT blacklist (banned: {info['time']})")
            print(f"  [!!!] 直接命中黑名单！封禁时间: {info['time']}")

        if addr_norm in OFAC_SANCTIONED_ADDRS:
            ofac = OFAC_SANCTIONED[addr_norm]
            report.is_blacklisted = True
            report.ofac_sdn_match = True
            entity = ofac.get("entity", "Unknown")
            report.ofac_entity = entity
            currency = ofac.get("currency", "")
            if not report.blacklist_time:
                report.blacklist_time = "OFAC SDN"   # 向后兼容兜底（未命中 USDT 时）
            report.warnings.append(f"[!] Address is on the OFAC SDN sanctions list (entity: {entity}, currency: {currency})")
            print(f"  [!!!] 直接命中 OFAC 制裁名单！实体: {entity}")

        if run_tron:
            self._analyze_tron(addr_norm, report)
            report.chains_analyzed = ["tron"]
        else:
            for chain_name in evm_chains_to_run:
                client = self.evm_clients.get(chain_name)
                cfg = EVM_CHAIN_REGISTRY.get(chain_name)
                if client is None or cfg is None:
                    print(f"  [WARN] 链 {chain_name} 未配置，跳过")
                    continue
                self._analyze_evm_chain(addr_norm, report, cfg, client, chain_name)
                report.chains_analyzed.append(chain_name)

        self._calculate_risk(report)
        return report

