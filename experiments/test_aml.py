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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from cripto_analyst import aml_analyzer as _aml
from cripto_analyst.aml_analyzer import (
    load_blacklist, AMLAnalyzer, EVMClient, TronScanClient,
    BridgeTracer, RiskReport, RiskIndicator, BLACKLIST_CSV,
    EVM_CHAIN_REGISTRY, MIXER_CONTRACTS,
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

    evm_clients = {name: EVMClient(cfg) for name, cfg in EVM_CHAIN_REGISTRY.items()}
    tron = TronScanClient()
    analyzer = AMLAnalyzer(bl, evm_clients, tron, BridgeTracer())

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

    def make_indicator(category, weight, direction, amount, hop=1):
        """构造一条最小化风险证据（当前比例模型的评分单元）"""
        return RiskIndicator(
            indicator_type=f"test_{category}", category=category,
            category_weight=weight, counterparty="0xcp",
            direction=direction, amount_usdt=amount,
            hop=hop, hop_decay=1.0, tx_hashes=["0xhash"], timestamps=["0"],
        )

    # ── 2. 污染比例语义：score = 风险加权金额 / 总流量 × 100 ──
    #     总流入 10000，其中 2000 来自黑名单（权重 1.0）→ taint=0.2 → 20 分
    r = make_report(total_inflow_usdt=10000.0,
                    indicators=[make_indicator("blacklist", 1.0, "IN", 2000.0)])
    analyzer._calculate_risk(r)
    if r.risk_score == 20.0 and r.received_exposure == 0.2:
        ok("污染比例语义", "2000/10000 黑名单流入 → 20分")
    else:
        fail("污染比例语义", f"得到 {r.risk_score} (exposure={r.received_exposure})")

    # ── 3. 类别权重分级：同金额下 blacklist(1.0) > mixer(0.5) > 透明桥(0.3) ──
    scores = {}
    for cat, w in [("blacklist", 1.0), ("mixer", 0.5), ("transparent_bridge", 0.3)]:
        r = make_report(total_inflow_usdt=10000.0,
                        indicators=[make_indicator(cat, w, "IN", 1000.0)])
        analyzer._calculate_risk(r)
        scores[cat] = r.risk_score
    if scores["blacklist"] > scores["mixer"] > scores["transparent_bridge"]:
        ok("类别权重分级", f"黑名单{scores['blacklist']} > 混币器{scores['mixer']} > 透明桥{scores['transparent_bridge']}")
    else:
        fail("类别权重分级", f"{scores}")

    # ── 4. 方向独立核算：IN 污染只进 received，OUT 只进 sent，取 max ──
    r = make_report(total_inflow_usdt=10000.0, total_outflow_usdt=10000.0,
                    indicators=[make_indicator("blacklist", 1.0, "IN", 1000.0),
                                make_indicator("mixer", 0.5, "OUT", 8000.0)])
    analyzer._calculate_risk(r)
    if (r.received_exposure == 0.1 and r.sent_exposure == 0.4
            and r.taint_ratio == 0.4 and r.risk_score == 40.0):
        ok("方向独立核算", "IN 0.1 / OUT 0.4 → taint=max=0.4 → 40分")
    else:
        fail("方向独立核算",
             f"recv={r.received_exposure} sent={r.sent_exposure} taint={r.taint_ratio} 分数={r.risk_score}")

    # ── 5. 2-hop 用中间人真实污染比例当权重（无距离折扣 hack）──
    #     cp 的 taint_ratio=0.05 作为 category_weight → 1000×0.05/10000 → 0.5 分
    r = make_report(total_inflow_usdt=10000.0,
                    indicators=[make_indicator("cp_node_blacklist", 0.05, "IN", 1000.0, hop=2)])
    analyzer._calculate_risk(r)
    if r.risk_score == 0.5:
        ok("2-hop 真实污染比例", "1000×0.05/10000 → 0.5分（无 ×0.3 距离 hack）")
    else:
        fail("2-hop 真实污染比例", f"得到 {r.risk_score}")

    # ── 6. presence-only：有接触但无资金往来 → 不计分，只进 warnings ──
    r = make_report(total_inflow_usdt=10000.0,
                    indicators=[make_indicator("mixer", 0.5, "IN", 0.0)])
    analyzer._calculate_risk(r)
    has_warning = any("Non-financial contact" in w for w in r.warnings)
    if r.risk_score == 0.0 and has_warning:
        ok("presence-only 不计分", "amount=0 → 0分 + 人工复核 warning")
    else:
        fail("presence-only 处理", f"分数={r.risk_score} warning={has_warning}")

    # ── 7. 封顶：风险金额超过总流量 → taint 封顶 1.0 → 100 分 ──
    r = make_report(total_inflow_usdt=1000.0,
                    indicators=[make_indicator("blacklist", 1.0, "IN", 5000.0)])
    analyzer._calculate_risk(r)
    if r.risk_score == 100.0 and r.taint_ratio == 1.0:
        ok("taint 封顶 1.0", "风险金额 > 总流量 → 100分")
    else:
        fail("taint 封顶", f"得到 {r.risk_score} (taint={r.taint_ratio})")

    # ── 8. 无风险信号 → 0分 ──
    r = make_report()
    r.total_counterparties = 5
    r.total_transactions = 20
    analyzer._calculate_risk(r)
    if r.risk_score == 0 and r.risk_level == "LOW":
        ok("无风险信号 → 0分 LOW")
    else:
        fail("无风险信号评分异常", f"得到 {r.risk_score} {r.risk_level}")

    # ── 9. 等级阈值（测真实代码路径：≥80 CRITICAL / ≥45 HIGH / ≥20 MEDIUM）──
    #     用流入占比构造目标分数，断言 _calculate_risk 产出的 risk_level
    thresholds = [(85.0, "CRITICAL"), (50.0, "HIGH"), (25.0, "MEDIUM"), (5.0, "LOW")]
    all_ok = True
    for amount, expected_level in thresholds:
        r = make_report(total_inflow_usdt=100.0,
                        indicators=[make_indicator("blacklist", 1.0, "IN", amount)])
        analyzer._calculate_risk(r)
        if r.risk_level != expected_level:
            fail(f"等级阈值 score={r.risk_score}", f"期望{expected_level}，得到{r.risk_level}")
            all_ok = False
    if all_ok:
        ok("等级阈值映射正确", "85→CRITICAL / 50→HIGH / 25→MEDIUM / 5→LOW")

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
# Layer 1-D — 机制统一定义层（混币器 + 桥的可追踪性判别）
# ════════════════════════════════════════════════════════════

def test_mechanism_definitions():
    section("Layer 1-D：机制统一定义（is_tracing_boundary + 指纹判别）")
    from cripto_analyst.threat_intel.mechanisms import (
        classify, classify_by_fingerprint, REGISTRY, Kind, MappingSource,
    )

    # 1. 统一定义：映射不可还原 ⇔ 追踪边界
    boundary_sources = {MappingSource.OFFCHAIN_PRIVATE, MappingSource.ZK_DESTROYED, MappingSource.NONE}
    ok_def = all(
        m.is_tracing_boundary == (m.mapping_source in boundary_sources)
        for m in REGISTRY.values()
    )
    ok("is_tracing_boundary 与映射可观测性一致" if ok_def else "", "") if ok_def \
        else fail("is_tracing_boundary 定义", "与 mapping_source 不一致")

    # 2. 混币器与不透明桥归为同类边界（report 的核心命题）
    mixers = [m for m in REGISTRY.values() if m.kind == Kind.MIXER]
    opaque_bridges = [m for m in REGISTRY.values()
                      if m.kind == Kind.BRIDGE and m.is_tracing_boundary]
    if all(m.is_tracing_boundary for m in mixers) and opaque_bridges:
        ok("混币器与不透明桥同为追踪边界",
           f"{len(mixers)} 混币器 + {len(opaque_bridges)} 不透明桥")
    else:
        fail("统一边界命题", "混币器或不透明桥未被判为边界")

    # 3. 透明桥不是边界（映射经索引器/Rollup 可还原）
    transparent = [m for m in REGISTRY.values()
                   if m.kind == Kind.BRIDGE and not m.is_tracing_boundary]
    if transparent and all(not m.is_tracing_boundary for m in transparent):
        ok("透明桥可追踪（非边界）", f"{len(transparent)} 个")
    else:
        fail("透明桥判别", "")

    # 4. 第 0 级：地址精确命中（已知 Stargate Router）
    m = classify("0x8731d54e9d02c286767d56ac03e8037c07e01e98")
    if m and m.kind == Kind.BRIDGE and not m.is_tracing_boundary and not m.inferred:
        ok("地址精确命中已知桥", m.name)
    else:
        fail("地址精确命中", f"得到 {m}")

    # 5. 第 1 级：指纹认出未登记的 Tornado fork（字典做不到的事）
    fork = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"  # 不在注册表
    m = classify(fork, event_topics=[
        "0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196",  # Tornado Deposit
    ])
    if m and m.kind == Kind.MIXER and m.inferred and m.is_tracing_boundary:
        ok("指纹认出未登记混币器部署", "inferred=True, boundary=True")
    else:
        fail("指纹判别（第 1 级）", f"得到 {m}")

    # 6. 不误判：未知地址 + 无指纹 → 无判断
    if classify("0x1111111111111111111111111111111111111111") is None:
        ok("普通地址不误判", "classify → None")
    else:
        fail("误判普通地址", "")


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
    test_mechanism_definitions()

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
