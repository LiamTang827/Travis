#!/usr/bin/env python3
"""
Replay an existing analyzer results.json through the NEW printer.

Sandbox 这里挡了 api.etherscan.io，跑不了真实 batch。但我们有一份之前的
JSON（artifacts/reports/eth_test_10_preview/results.json），里面包含
contract_interactions 的旧 schema（没有 from/to per-effect，没 method_label）。
本脚本：
  1. 加载这份 JSON
  2. 把每条 token_effect 用 decode_method 重新打上 method_label
  3. 用新增的 print_contract_interactions 打印 IN/OUT + from/to 视觉

这就把"旧数据 + 新展示逻辑"接起来了，能让用户直观看到新版输出。
"""
import json
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cripto_analyst.aml_analyzer import (
    RiskReport, decode_method, print_contract_interactions, print_report,
)


JSON_PATH = Path(__file__).resolve().parents[1] / "artifacts" / "reports" / "eth_test_10_preview" / "results.json"
OUT_DIR   = Path(__file__).resolve().parents[1] / "artifacts" / "reports_v2"


def _upgrade_interaction(it: dict) -> dict:
    """旧 schema → 新 schema 就地补字段。"""
    # 外层 method_label
    it.setdefault("method_label", decode_method(it.get("method_id", ""), it.get("method", "")))
    # 每个 effect 加 from/to/method_label
    for eff in it.get("token_effects") or []:
        # 旧版只有 direction + counterparty；推出 from/to
        d = eff.get("direction", "")
        cp = eff.get("counterparty", "")
        # 当前地址（被分析的）从外层 interaction 取不到——但 from/to 在 interaction 里有
        if d == "IN":
            eff.setdefault("from", cp)
            eff.setdefault("to",   it.get("to", "") or "")
        elif d == "OUT":
            eff.setdefault("from", it.get("from", "") or "")
            eff.setdefault("to",   cp)
        else:
            eff.setdefault("from", "")
            eff.setdefault("to",   "")
        # inner label
        eff.setdefault(
            "method_label",
            decode_method(eff.get("method_id", ""), eff.get("method", "")),
        )
    return it


def _dict_to_report(d: dict) -> RiskReport:
    r = RiskReport(address=d["address"], chain=d.get("chain", "ethereum"))
    # 只搬印出需要用到的字段，其它字段保持默认即可
    for key in (
        "tron_address", "is_blacklisted", "blacklist_time", "risk_score",
        "risk_level", "taint_ratio", "account_info",
        "total_inflow_usdt", "total_outflow_usdt", "total_eth_usd_in", "total_eth_usd_out",
        "total_counterparties", "total_transactions", "chains_analyzed",
        "per_chain_inflow", "per_chain_outflow", "warnings",
        "indicators", "score_breakdown", "top_counterparties",
        "bridge_interactions", "opaque_bridge_interactions", "mixer_interactions",
        "high_risk_exchanges", "cross_chain_findings", "contract_interactions",
        "transactions",
    ):
        if key in d and hasattr(r, key):
            setattr(r, key, d[key])
    # 处理 indicators：原 dataclass 里是 RiskIndicator，这里只为打印用，跳过
    if isinstance(getattr(r, "indicators", None), list):
        # print_report 用的是 ind.category / ind.amount_usdt / ind.hop ...
        # 这些都是 dict-style，但代码访问的是属性。简单 SimpleNamespace 包一层。
        from types import SimpleNamespace
        r.indicators = [
            SimpleNamespace(**i) if isinstance(i, dict) else i
            for i in r.indicators
        ]
    return r


def main():
    with open(JSON_PATH) as f:
        reports = json.load(f)
    print(f"[*] loaded {len(reports)} reports from {JSON_PATH}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for idx, raw in enumerate(reports, 1):
        addr = raw["address"]
        print(f"\n{'='*90}\n[{idx}/{len(reports)}] {addr}\n{'='*90}")
        # 升级 schema
        for it in raw.get("contract_interactions") or []:
            _upgrade_interaction(it)
        # 包成 RiskReport 仅用于打印
        report = _dict_to_report(raw)

        # 只打 contract_interactions section
        n = len(report.contract_interactions)
        print(f"  contract_interactions: {n}")
        if n == 0:
            print("  （该地址无合约交互，跳过详表）")
            continue

        # 限 12 行，方便看
        print_contract_interactions(report, limit=12)

        # 保存到文件
        import io
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        print(f"地址: {addr}  (合约交互 {n} 笔)")
        print_contract_interactions(report, limit=30)
        sys.stdout = old
        out_path = OUT_DIR / f"{addr.lower()}_contracts_v2.txt"
        out_path.write_text(buf.getvalue(), encoding="utf-8")
        print(f"  [已保存] {out_path}")


if __name__ == "__main__":
    main()
