# ============================================================
# law.py
# 检测结果 → HKMA AML/CFT 法规条款自动映射
# 法规来源：HKMA Guideline on AML/CFT for
#           Licensed Stablecoin Issuers (Aug 2025)
#           + AMLO Cap.615 + FATF Rec.16
# ============================================================

# ── 检测器 → 法规条款映射表 ──────────────────────────────────
DETECTOR_LAW_MAP = {
    "blacklist": [
        {
            "ref":   "§7.5, §7.8",
            "title": "制裁名单筛查",
            "desc":  "持牌稳定币发行人须对客户及交易方进行制裁筛查，"
                     "发现疑似命中须立即启动强化核查，不得执行相关交易。",
            "action": "立即冻结，向JFIU提交STR，保存所有证据记录",
        },
        {
            "ref":   "§8.1, §8.5",
            "title": "可疑交易报告义务",
            "desc":  "发现合理怀疑的洗钱/恐怖融资活动，须尽快向JFIU提交STR。",
            "action": "提交STR，防止泄露(tipping off)，保存记录7年",
        },
    ],
    "mixer": [
        {
            "ref":   "§5.4, §5.10",
            "title": "持续监控 — 混币器交互",
            "desc":  "与已知混币器（Tornado Cash等OFAC制裁合约）交互属于"
                     "高风险洗钱红旗指标，须触发强化尽职调查(EDD)。",
            "action": "升级至EDD，获取高管审批，考虑终止业务关系",
        },
        {
            "ref":   "§4.18, §4.20",
            "title": "强化尽职调查(EDD)",
            "desc":  "高风险客户须获取高级管理层批准方可建立/维持业务关系。",
            "action": "获取MLRO/董事会批准，记录批准决定及理由",
        },
    ],
    "smurfing": [
        {
            "ref":   "§5.5, §5.11",
            "title": "持续监控 — 拆单交易(Smurfing)",
            "desc":  "将大额资金拆分为多笔小额交易以规避报告阈值，"
                     "是典型洗钱手法，须触发可疑交易分析。",
            "action": "人工复核交易模式，评估是否提交STR",
        },
    ],
    "peel_chain": [
        {
            "ref":   "§5.5, §5.11",
            "title": "持续监控 — Peel Chain资金剥离",
            "desc":  "通过连续地址跳转逐步剥离资金痕迹，"
                     "属于链上洗钱典型手法，须追踪资金最终去向。",
            "action": "追踪资金流向，记录完整路径，考虑提交STR",
        },
    ],
    "fanout": [
        {
            "ref":   "§5.5",
            "title": "持续监控 — 蜘蛛网分散转账",
            "desc":  "短时间内将资金分散至大量地址，"
                     "疑似规避追踪的分散化洗钱手法。",
            "action": "分析资金最终归集地址，评估整体风险",
        },
    ],
    "bipartite": [
        {
            "ref":   "§5.5, §5.11",
            "title": "持续监控 — 二分图协同转账",
            "desc":  "多个地址同时激活并协同转账，疑似有组织的洗钱网络。",
            "action": "关联分析所有涉及地址，整体评估并报告",
        },
    ],
    "crosschain": [
        {
            "ref":   "§6.2, §6.5",
            "title": "跨链桥交互 — 旅行规则合规",
            "desc":  "通过跨链桥转移资产须遵守旅行规则(Travel Rule)，"
                     "确保发起方和受益方信息随交易传递。",
            "action": "核查旅行规则合规性，不透明桥须触发EDD",
        },
    ],
    "defi": [
        {
            "ref":   "§5.11, §1.10",
            "title": "DeFi滥用 — 高风险产品/服务",
            "desc":  "去中心化金融协议（DEX闪兑、流动性池、闪贷）"
                     "被用于规避AML控制，属于高风险产品使用场景。",
            "action": "加强对DeFi相关交易的监控，评估合规风险",
        },
    ],
    "nft": [
        {
            "ref":   "§5.11",
            "title": "NFT洗钱 — 可疑资产交易",
            "desc":  "通过NFT进行价格操纵式交易（wash trading）"
                     "将非法资金洗白，须识别并报告。",
            "action": "核查NFT交易对手方及价格合理性，考虑提交STR",
        },
    ],
    "dusting": [
        {
            "ref":   "§5.4, §4.39",
            "title": "尘埃攻击 — 钱包筛查触发",
            "desc":  "收到来自黑名单地址的微量资金（尘埃攻击），"
                     "须立即对相关地址进行强化筛查。",
            "action": "对来源地址进行制裁筛查，记录筛查结果",
        },
    ],
    "pig_butchering": [
        {
            "ref":   "§5.11, §8.1",
            "title": "猪杀盘诈骗 — 资金追踪",
            "desc":  "检测到典型猪杀盘（Pig Butchering）三段式资金流动模式，"
                     "属于电信诈骗相关洗钱活动。",
            "action": "立即冻结相关账户，向警方及JFIU报告，配合调查",
        },
    ],
    "reverse_taint": [
        {
            "ref":   "§5.4, §7.5",
            "title": "反向污染 — 主动接触黑名单",
            "desc":  "目标地址主动向已知黑名单地址转账，"
                     "属于直接参与洗钱活动的高风险行为。",
            "action": "立即暂停业务关系，提交STR，保存完整交易记录",
        },
    ],
    "pagerank": [
        {
            "ref":   "§5.4, §2.2",
            "title": "风险传播 — 网络中心风险节点",
            "desc":  "PageRank分析显示该地址在高风险交易网络中处于核心位置，"
                     "间接风险敞口极高。",
            "action": "全面评估网络关联风险，考虑升级监控级别",
        },
    ],
    "lof": [
        {
            "ref":   "§5.5",
            "title": "异常检测 — 交易行为偏离正常",
            "desc":  "LOF局部离群因子检测显示交易行为明显异常，"
                     "须人工复核分析异常原因。",
            "action": "人工复核异常交易，评估是否存在洗钱风险",
        },
    ],
}

# ── 评分/风险等级 → 法规处置要求 ─────────────────────────────
RISK_LEVEL_LAW = {
    "CRITICAL": {
        "ref":      "§4.30, §8.1, §8.5, §7.5",
        "title":    "极高风险 — 强制处置要求",
        "requires": [
            "立即冻结账户及相关资产",
            "24小时内向JFIU提交可疑交易报告(STR) [§8.5]",
            "获取MLRO和高级管理层审批 [§4.20]",
            "保存所有相关记录至少7年 [§9.1]",
            "不得向客户泄露已提交STR（防止tipping off） [§8.2]",
            "配合执法机构调查",
        ],
    },
    "HIGH": {
        "ref":      "§4.18, §4.20, §5.2",
        "title":    "高风险 — 强化尽职调查(EDD)",
        "requires": [
            "立即升级至强化尽职调查(EDD) [§4.18]",
            "获取高级管理层审批方可维持业务关系 [§4.20]",
            "加强持续监控频率 [§5.2]",
            "评估是否需要提交STR [§8.1]",
            "记录EDD措施及决策依据",
        ],
    },
    "MEDIUM": {
        "ref":      "§4.18, §5.3",
        "title":    "中等风险 — 标准尽职调查加强",
        "requires": [
            "执行标准尽职调查(SDD→CDD) [§4.18]",
            "提高监控频率，关注可疑交易模式 [§5.3]",
            "记录风险评估依据",
        ],
    },
    "LOW": {
        "ref":      "§4.18",
        "title":    "低风险 — 持续监控",
        "requires": [
            "维持标准监控 [§5.2]",
            "定期复审客户风险等级 [§5.3]",
        ],
    },
}

# ── 旅行规则阈值参考 ─────────────────────────────────────────
TRAVEL_RULE_REF = {
    "ref":       "FATF Rec.16 / §6.5",
    "threshold": "HKD 8,000",
    "desc":      "单笔稳定币转账等值港元8,000或以上，须随交易传递"
                 "发起方与受益方完整身份信息。",
}


def generate_law_section(
    detector_results: dict,
    risk_level: str,
    score_breakdown: dict,
) -> dict:
    """
    根据检测结果生成法规引用部分

    参数:
        detector_results: analyze.py 中的 detector_results dict
        risk_level:       最终风险等级字符串
        score_breakdown:  scorer.py 中的 score_breakdown dict

    返回:
        {
          "risk_level_law": {...},      # 风险等级对应的处置要求
          "triggered_laws": [...],      # 命中检测器对应的法规列表
          "summary": "...",             # 可读摘要
        }
    """
    triggered_laws = []
    seen_refs = set()

    for detector_name, result in detector_results.items():
        if not (isinstance(result, dict) and result.get("detected")):
            continue
        laws = DETECTOR_LAW_MAP.get(detector_name, [])
        for law in laws:
            if law["ref"] not in seen_refs:
                seen_refs.add(law["ref"])
                triggered_laws.append({
                    "detector": detector_name,
                    "ref":      law["ref"],
                    "title":    law["title"],
                    "desc":     law["desc"],
                    "action":   law["action"],
                    "severity": result.get("severity", "MEDIUM"),
                })

    # 按严重程度排序
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    triggered_laws.sort(key=lambda x: sev_order.get(x["severity"], 4))

    risk_law = RISK_LEVEL_LAW.get(risk_level, RISK_LEVEL_LAW["LOW"])

    summary_parts = [f"触发 {len(triggered_laws)} 条法规引用"]
    if risk_level in ("CRITICAL", "HIGH"):
        summary_parts.append(f"须立即执行 {risk_law['ref']} 规定的处置措施")

    return {
        "risk_level_law":  risk_law,
        "triggered_laws":  triggered_laws,
        "travel_rule_ref": TRAVEL_RULE_REF,
        "summary":         " | ".join(summary_parts),
    }


def format_law_report_text(law_section: dict) -> str:
    """生成法规部分的可读文本，用于终端输出"""
    lines = [
        "─" * 55,
        " 法规合规要求 (HKMA AML/CFT Guideline Aug 2025)",
        "─" * 55,
    ]

    rl = law_section.get("risk_level_law", {})
    lines.append(f" [{rl.get('ref','')}] {rl.get('title','')}")
    for req in rl.get("requires", []):
        lines.append(f"   ✦ {req}")

    tl = law_section.get("triggered_laws", [])
    if tl:
        lines += ["", " 命中法规条款:"]
        BADGE = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
        for law in tl:
            b = BADGE.get(law["severity"], "🟡")
            lines.append(f"   {b} {law['ref']}  {law['title']}")
            lines.append(f"      → {law['desc'][:60]}")
            lines.append(f"      ⚡ 处置: {law['action']}")

    lines.append("─" * 55)
    return "\n".join(lines)
