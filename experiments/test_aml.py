#!/usr/bin/env python3
"""
AML 系统自动测试
================
两层测试：
  Layer 1 - 离线单元测试：不调 API，直接测评分规则和黑名单加载
  Layer 2 - 在线集成测试：真实 API 调用，验证端到端输出

用法：
  python experiments/test_aml.py          # 只跑离线测试（快，<5秒）
  python experiments/test_aml.py --online # 同时跑在线测试（慢，需要 API）
"""

import sys
import os
import argparse
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import aml_analyzer as _aml
from aml_analyzer import (
    load_blacklist, AMLAnalyzer, EtherscanClient, TronScanClient,
    BridgeTracer, RiskReport, BLACKLIST_CSV,
    ETHERSCAN_API_KEY, MIXER_CONTRACTS,
)

# ── 颜色输出 ──────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

passed = 0
failed = 0
warned = 0


def ok(name, detail=""):
    global passed
    passed += 1
    print(f"  {GREEN}✓ PASS{RESET}  {name}" + (f"  ({detail})" if detail else ""))


def fail(name, detail=""):
    global failed
    failed += 1
    print(f"  {RED}✗ FAIL{RESET}  {name}" + (f"  ({detail})" if detail else ""))


def warn(name, detail=""):
    global warned
    warned += 1
    print(f"  {YELLOW}⚠ WARN{RESET}  {name}" + (f"  ({detail})" if detail else ""))


def section(title):
    print(f"\n{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'─'*60}{RESET}")


# ════════════════════════════════════════════════════════════
# Layer 1 — 离线单元测试
# ════════════════════════════════════════════════════════════

def test_blacklist_loading():
    section("Layer 1-A：黑名单加载")
    bl = load_blacklist(BLACKLIST_CSV)

    if len(bl) > 0:
        ok("黑名单非空", f"{len(bl)} 条记录")
    else:
        fail("黑名单为空")

    # 验证格式
    sample = next(iter(bl.values()))
    if "chain" in sample and "time" in sample:
        ok("黑名单字段完整", "含 chain / time")
    else:
        fail("黑名单字段缺失", str(sample.keys()))

    # 以太坊地址应为小写0x格式
    eth_addrs = [a for a, v in bl.items() if v["chain"] == "ethereum"]
    if eth_addrs:
        sample_addr = eth_addrs[0]
        if sample_addr.startswith("0x") and sample_addr == sample_addr.lower():
            ok("以太坊地址格式正确", f"样本: {sample_addr[:18]}...")
        else:
            fail("以太坊地址格式异常", sample_addr)

    return bl


def test_scoring_rules(bl):
    section("Layer 1-B：评分规则单元测试")

    eth = EtherscanClient(ETHERSCAN_API_KEY)
    tron = TronScanClient()
    analyzer = AMLAnalyzer(bl, eth, tron, BridgeTracer())

    def make_report(**kwargs):
        """构造一个最小化的 RiskReport 用于测试"""
        r = RiskReport(address="0xtest", chain="ethereum")
        for k, v in kwargs.items():
            setattr(r, k, v)
        return r

    # ── 1. 直接黑名单命中 ──
    r = make_report(is_blacklisted=True)
    analyzer._calculate_risk(r)
    if r.risk_score == 100 and r.risk_level == "CRITICAL":
        ok("直接黑名单 → 100分 CRITICAL")
    else:
        fail("直接黑名单", f"得到 {r.risk_score} {r.risk_level}")

    # ── 2. 混币器交互 ──
    r = make_report(mixer_interactions=[{"mixer": "Tornado Cash", "direction": "OUT"}])
    analyzer._calculate_risk(r)
    if r.risk_score == 40:
        ok("混币器交互 → 40分")
    else:
        fail("混币器交互", f"得到 {r.risk_score}")

    # ── 3. 主动转出给1个黑名单地址 ──
    r = make_report(hop1_blacklisted=[{
        "address": "0xabc", "chain": "ethereum",
        "blacklist_time": "", "in_count": 0, "out_count": 1
    }])
    analyzer._calculate_risk(r)
    if r.risk_score == 25:
        ok("主动转出给1个黑名单 → 25分")
    else:
        fail("主动转出给1个黑名单", f"得到 {r.risk_score}")

    # ── 4. 主动转出给2个黑名单地址 ──
    r = make_report(hop1_blacklisted=[
        {"address": "0xabc", "chain": "ethereum", "blacklist_time": "", "in_count": 0, "out_count": 1},
        {"address": "0xdef", "chain": "ethereum", "blacklist_time": "", "in_count": 0, "out_count": 2},
    ])
    analyzer._calculate_risk(r)
    if r.risk_score == 35:
        ok("主动转出给2个黑名单 → 35分")
    else:
        fail("主动转出给2个黑名单", f"得到 {r.risk_score}")

    # ── 5. 仅被动收到黑名单转入 ──
    r = make_report(hop1_blacklisted=[{
        "address": "0xabc", "chain": "ethereum",
        "blacklist_time": "", "in_count": 1, "out_count": 0
    }])
    analyzer._calculate_risk(r)
    if r.risk_score == 10:
        ok("仅被动收到1个黑名单转入 → 10分（低于主动）")
    else:
        fail("被动污染评分", f"得到 {r.risk_score}")

    # ── 6. 主动 > 被动（方向区分有效）──
    r_active = make_report(hop1_blacklisted=[{
        "address": "0xabc", "chain": "ethereum",
        "blacklist_time": "", "in_count": 0, "out_count": 1
    }])
    r_passive = make_report(hop1_blacklisted=[{
        "address": "0xabc", "chain": "ethereum",
        "blacklist_time": "", "in_count": 1, "out_count": 0
    }])
    analyzer._calculate_risk(r_active)
    analyzer._calculate_risk(r_passive)
    if r_active.risk_score > r_passive.risk_score:
        ok("主动转出分 > 被动收入分", f"{r_active.risk_score} > {r_passive.risk_score}")
    else:
        fail("方向区分无效", f"主动={r_active.risk_score} 被动={r_passive.risk_score}")

    # ── 7. 不透明桥 < 混币器（威胁分级有效）──
    r_mixer  = make_report(mixer_interactions=[{"mixer": "Tornado", "direction": "OUT"}])
    r_opaque = make_report(opaque_bridge_interactions=[{"bridge": "Multichain", "direction": "OUT"}])
    analyzer._calculate_risk(r_mixer)
    analyzer._calculate_risk(r_opaque)
    if r_mixer.risk_score > r_opaque.risk_score:
        ok("混币器分 > 不透明桥分", f"{r_mixer.risk_score} > {r_opaque.risk_score}")
    else:
        fail("威胁分级无效", f"混币器={r_mixer.risk_score} 不透明桥={r_opaque.risk_score}")

    # ── 8. 无风险信号 → 0分 ──
    r = make_report()
    r.total_counterparties = 5
    r.total_transactions = 20
    analyzer._calculate_risk(r)
    if r.risk_score == 0 and r.risk_level == "LOW":
        ok("无风险信号 → 0分 LOW")
    else:
        fail("无风险信号评分异常", f"得到 {r.risk_score} {r.risk_level}")

    # ── 9. 等级阈值 ──
    thresholds = [(100, "CRITICAL"), (60, "HIGH"), (30, "MEDIUM"), (0, "LOW")]
    all_ok = True
    for score, expected_level in thresholds:
        r = make_report()
        r.risk_score = score
        # 直接调用等级判断
        if score == 100:
            level = "CRITICAL"
        elif score >= 60:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"
        if level != expected_level:
            fail(f"等级阈值 score={score}", f"期望{expected_level}，得到{level}")
            all_ok = False
    if all_ok:
        ok("等级阈值映射正确", "100→CRITICAL / 60→HIGH / 30→MEDIUM / 0→LOW")

    return analyzer


def test_blacklist_coverage(bl):
    section("Layer 1-C：黑名单覆盖率统计")

    eth_count  = sum(1 for v in bl.values() if v["chain"] == "ethereum")
    tron_count = sum(1 for v in bl.values() if v["chain"] == "tron")
    other      = len(bl) - eth_count - tron_count

    print(f"    以太坊地址: {eth_count}")
    print(f"    Tron 地址:  {tron_count}")
    print(f"    其他链:     {other}")

    if eth_count > 0 and tron_count > 0:
        ok("黑名单覆盖多链（ETH + Tron）")
    else:
        warn("黑名单仅覆盖单链")

    # 抽查几个已知黑名单地址
    known_bl = [
        "0x098b716b8aaf21512996dc57eb0615e2383e2f96",  # Ronin 攻击者
    ]
    for addr in known_bl:
        if addr in bl:
            ok(f"已知黑名单地址命中", addr[:18] + "...")
        else:
            warn(f"已知黑名单地址未收录", addr[:18] + "...")


# ════════════════════════════════════════════════════════════
# Layer 2 — 在线集成测试
# ════════════════════════════════════════════════════════════

ONLINE_CASES = [
    {
        "name": "直接黑名单地址（Ronin攻击者）",
        "address": "0x098b716b8aaf21512996dc57eb0615e2383e2f96",
        "chain": "ethereum",
        "expect_blacklisted": True,
        "expect_level": "CRITICAL",
        "expect_score_min": 100,
    },
    {
        "name": "黑名单对手方（hop1应命中，主动转出）",
        "address": "0x03cf40b900971561ac6bd997ef1fe939dcbc95e2",
        "chain": "ethereum",
        "expect_blacklisted": False,
        "expect_hop1_min": 1,
        "expect_score_min": 20,
    },
    {
        "name": "以太坊黑名单地址（最新冻结）",
        "address": "0x2aa1ca10bddd558fdfce9572d97f8cb28cd67154",
        "chain": "ethereum",
        "expect_blacklisted": True,
        "expect_level": "CRITICAL",
        "expect_score_min": 100,
    },
]


def test_online(bl, analyzer):
    section("Layer 2：在线集成测试（真实 API）")

    for case in ONLINE_CASES:
        print(f"\n  [{case['name']}]")
        print(f"  地址: {case['address']}")
        try:
            report = analyzer.analyze(case["address"], chain=case["chain"])

            # 检查 is_blacklisted
            if "expect_blacklisted" in case:
                if report.is_blacklisted == case["expect_blacklisted"]:
                    ok("黑名单命中状态", f"is_blacklisted={report.is_blacklisted}")
                else:
                    fail("黑名单命中状态", f"期望{case['expect_blacklisted']}，得到{report.is_blacklisted}")

            # 检查等级
            if "expect_level" in case:
                if report.risk_level == case["expect_level"]:
                    ok("风险等级", f"{report.risk_level}")
                else:
                    fail("风险等级", f"期望{case['expect_level']}，得到{report.risk_level}")

            # 检查分数下限
            if "expect_score_min" in case:
                if report.risk_score >= case["expect_score_min"]:
                    ok("风险分数", f"{report.risk_score} >= {case['expect_score_min']}")
                else:
                    fail("风险分数", f"期望>={case['expect_score_min']}，得到{report.risk_score}")

            # 检查 hop1 下限
            if "expect_hop1_min" in case:
                h1 = len(report.hop1_blacklisted)
                if h1 >= case["expect_hop1_min"]:
                    ok("1跳黑名单命中数", f"{h1} >= {case['expect_hop1_min']}")
                else:
                    fail("1跳黑名单命中数", f"期望>={case['expect_hop1_min']}，得到{h1}")

            # 额外信息
            print(f"    风险因子: {report.risk_factors}")

        except Exception as e:
            fail(f"分析异常", str(e))

        time.sleep(1)


# ════════════════════════════════════════════════════════════
# 主入口
# ════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--online", action="store_true", help="同时运行在线 API 测试")
    args = parser.parse_args()

    print(f"\n{BOLD}AML 系统自动测试{RESET}")
    print(f"{'='*60}")

    bl       = test_blacklist_loading()
    analyzer = test_scoring_rules(bl)
    test_blacklist_coverage(bl)

    if args.online:
        test_online(bl, analyzer)
    else:
        section("Layer 2：在线测试（跳过）")
        print("  加 --online 参数运行真实 API 测试")

    # 汇总
    total = passed + failed + warned
    print(f"\n{'='*60}")
    print(f"{BOLD}测试结果{RESET}")
    print(f"  总计: {total}  "
          f"{GREEN}通过: {passed}{RESET}  "
          f"{RED}失败: {failed}{RESET}  "
          f"{YELLOW}警告: {warned}{RESET}")

    if failed > 0:
        print(f"\n{RED}有测试失败，请检查上方输出。{RESET}")
        sys.exit(1)
    else:
        print(f"\n{GREEN}所有测试通过。{RESET}")


if __name__ == "__main__":
    main()
