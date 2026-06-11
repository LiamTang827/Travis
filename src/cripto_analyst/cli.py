#!/usr/bin/env python3
"""命令行入口：单地址 / 多链 / 批量分析。"""

import sys
import time
import json
import argparse

from .config import BLACKLIST_CSV
from .utils import load_blacklist, detect_chain
from .chains import EVMClient, TronScanClient, EVM_CHAIN_REGISTRY
from .bridge_tracer import BridgeTracer
from .analyzer import AMLAnalyzer
from .reporting import print_report, export_json, print_transactions, LEVEL_COLORS

# ==================== CLI ====================
def main():
    parser = argparse.ArgumentParser(
        description="Travis — TRAceable Verification Intelligence System",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("address", nargs="?", help="要分析的地址（0x 格式）")
    parser.add_argument("--chain", help="强制指定链（ethereum/bsc/polygon/arbitrum/optimism/avalanche/base/tron）")
    parser.add_argument("--chains", help="分析多条链，逗号分隔（如 ethereum,bsc,polygon）")
    parser.add_argument("--blacklist", default=BLACKLIST_CSV, help=f"黑名单 CSV 路径（默认: {BLACKLIST_CSV}）")
    parser.add_argument("--days", type=int, default=365, metavar="N",
                        help="只分析最近 N 天的交易（默认 365，0 = 不限）")
    parser.add_argument("--no-hop2",  action="store_true", help="禁用 2 跳分析（加快速度）")
    parser.add_argument("--no-trace", action="store_true", help="禁用透明桥跨链追踪（加快速度）")
    parser.add_argument("--json", metavar="FILE", help="同时导出 JSON 报告到指定文件")
    parser.add_argument("--csv", metavar="FILE", help="批量模式下导出 CSV 汇总表（可用 Excel/Numbers 打开）")
    parser.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    parser.add_argument("--full",   action="store_true", help="打印完整稳定币流水（所有对手方地址和金额）")
    parser.add_argument("--batch", metavar="FILE", help="批量分析：从文件逐行读取地址")
    parser.add_argument("--output", metavar="DIR", help="将每个地址的报告保存为 <DIR>/<地址>.txt")
    args = parser.parse_args()

    global HOP2_ENABLED, BRIDGE_TRACE_ENABLED
    if args.no_hop2:
        HOP2_ENABLED = False
    if args.no_trace:
        BRIDGE_TRACE_ENABLED = False

    # 解析 --chains
    chains_list = None
    if args.chains:
        chains_list = [c.strip() for c in args.chains.split(",") if c.strip()]

    print("[*] 加载黑名单...")
    blacklist = load_blacklist(args.blacklist)
    print(f"[*] 已加载 {len(blacklist)} 个黑名单地址")

    # 为每条 EVM 链创建独立客户端
    evm_clients = {name: EVMClient(cfg) for name, cfg in EVM_CHAIN_REGISTRY.items()}
    tronscan  = TronScanClient()
    tracer    = BridgeTracer()
    analyzer  = AMLAnalyzer(blacklist, evm_clients, tronscan, tracer,
                            time_window_days=args.days)

    if args.batch:
        with open(args.batch) as f:
            addresses = [line.strip() for line in f if line.strip()]
        print(f"[*] 批量模式：共 {len(addresses)} 个地址")
        reports = []
        for i, addr in enumerate(addresses, 1):
            print(f"\n[{i}/{len(addresses)}] 处理: {addr}")
            report = analyzer.analyze(addr, chain=args.chain, chains=chains_list)
            print_report(report, use_color=not args.no_color, output_dir=args.output or "")
            reports.append(report)
            time.sleep(0.5)
        print(f"\n{'='*60}")
        print(f"批量分析汇总")
        print(f"{'='*60}")
        for r in reports:
            lc_c = LEVEL_COLORS.get(r.risk_level, "") if not args.no_color else ""
            rc_c = LEVEL_COLORS["RESET"] if not args.no_color else ""
            bl_cnt = sum(1 for ind in r.indicators if "blacklist" in ind.category and ind.hop == 1)
            bridges = len(r.bridge_interactions)
            print(f"  {r.address[:20]}...  {lc_c}{r.risk_level:8s}{rc_c}  "
                  f"分数:{r.risk_score:6.2f}  直接黑名单:{bl_cnt}  桥:{bridges}")
        if args.json:
            import dataclasses
            with open(args.json, "w") as f:
                json.dump([dataclasses.asdict(r) for r in reports], f, ensure_ascii=False, indent=2)
            print(f"[INFO] 批量 JSON 已保存: {args.json}")

        if args.csv:
            import csv as _csv
            with open(args.csv, "w", newline="", encoding="utf-8-sig") as f:
                writer = _csv.writer(f)
                writer.writerow([
                    "地址", "链", "风险等级", "分数",
                    "稳定币流入", "稳定币流出", "稳定币余额合计",
                    "黑名单", "OFAC制裁", "快速中转",
                    "1hop类别", "2hop类别",
                    "直接黑名单笔数", "混币器笔数", "不透明桥笔数",
                    "各币种明细",
                    "警告信息",
                ])
                for r in reports:
                    hop1_cats = sorted({ind.category for ind in r.indicators if ind.hop == 1 and ind.amount_usdt > 0})
                    hop2_cats = sorted({ind.category for ind in r.indicators if ind.hop == 2 and ind.amount_usdt > 0})
                    bl_cnt  = sum(1 for ind in r.indicators if ind.category in ("blacklist", "ofac_sanctioned") and ind.hop == 1)
                    mix_cnt = sum(1 for ind in r.indicators if ind.category == "mixer" and ind.hop == 1)
                    ob_cnt  = sum(1 for ind in r.indicators if ind.category == "opaque_bridge" and ind.hop == 1)
                    is_transit = any(a.get("is_fast_transit") for a in r.per_asset.values())
                    total_balance = round(sum(a.get("balance", 0) for a in r.per_asset.values()), 2)
                    # 每种稳定币的流入/流出/余额（展平成多列）
                    asset_detail = "; ".join(
                        "{} 流入{:.0f}/流出{:.0f}/余额{:.2f}{}".format(
                            a["sym"], a["flow_in"], a["flow_out"], a["balance"],
                            "⚡" if a.get("is_fast_transit") else ""
                        )
                        for a in sorted(r.per_asset.values(), key=lambda x: x["sym"])
                        if a["flow_in"] > 0 or a["flow_out"] > 0 or a["balance"] > 0
                    )
                    writer.writerow([
                        r.address,
                        r.chain,
                        r.risk_level,
                        r.risk_score,
                        round(r.total_inflow_usdt, 2),
                        round(r.total_outflow_usdt, 2),
                        total_balance,
                        "是" if r.is_blacklisted else "否",
                        "是" if any(ind.category == "ofac_sanctioned" for ind in r.indicators) else "否",
                        "是" if is_transit else "否",
                        " | ".join(hop1_cats),
                        " | ".join(hop2_cats),
                        bl_cnt, mix_cnt, ob_cnt,
                        asset_detail,
                        " // ".join(r.warnings),
                    ])
            print(f"[INFO] 批量 CSV 已保存: {args.csv}")

    elif args.address:
        report = analyzer.analyze(args.address, chain=args.chain, chains=chains_list)
        print_report(report, use_color=not args.no_color, output_dir=args.output or "")
        if args.full:
            print_transactions(report, show_all=True)
        if args.json:
            export_json(report, args.json)

    else:
        print("\n[*] 进入交互模式（输入 q 退出）")
        while True:
            try:
                addr = input("\n请输入地址: ").strip()
                if addr.lower() in ("q", "quit", "exit"):
                    break
                if not addr:
                    continue
                chain_input = input(
                    f"链类型 [{'/'.join(list(EVM_CHAIN_REGISTRY.keys()) + ['tron', 'auto'])}]: "
                ).strip().lower()
                chain_arg = chain_input if chain_input not in ("auto", "") else None
                report = analyzer.analyze(addr, chain=chain_arg)
                print_report(report, use_color=not args.no_color)
            except KeyboardInterrupt:
                break
        print("\n[*] 退出")


if __name__ == "__main__":
    main()
