# Final Report 引用索引（2026-06-16）

> 合并源：`docs/final_report/references.bib`（44 条 = report2 的 38 + 本轮新增 6）。
> 强 ★★★ 必引核心 ｜ 支撑 ★★ 用得上 ｜ 边角 ★ 仅相关小节用到才留，否则砍。
> ⭐ = 本轮新增。

## Related Work §A 图 AML 与检测
- ★★★ weber2019 — GCN 反洗钱（Elliptic）：资源型基准，对标"数据壁垒非算法"
- ★★ bellei2024 — Elliptic2 子图学习
- ★ elliptic_dataset2019 — Elliptic 数据集（提到数据集才引）
- ★ effendi2024 — FHE 协作 AML（偏，隐私协作才引）

## Related Work §B 跨链溯源（你的主战场）
- ★★★ ⭐connector2025 — 最近邻，纯链上关联，**必引并 differentiate**（你不主张解析创新）
- ★★★ sun2025track — Track&Trace 多链关联
- ★★★ mazorra2023 — ETH-Polygon 桥追踪（启发式匹配，对照你的协议级证据）
- ★★ ren2025survey — 溯源技术综述
- ★★ ⭐bridgeshield2025 — 统一建模但目标是攻击检测（正交对照）
- ★★ ⭐trmCrossChainSwapTraceability2026 — 业界"七模型一框架"，industry validation
- ★ elliptic2023 — $7B 跨链洗钱（动机统计，也可进 Intro）

## Related Work §C 多跳风险评分 / taint
- ★★★ moser2014 — Poison/Haircut，奠基，**对比 baseline 候选**
- ★★ hercog2019 — TaintRank（PageRank 类比）
- ★★★ liao2025 — Circle Transaction Proximity（反向：距合法锚点）

## Related Work §D 机器学习 stablecoin AML
- ★★★ juvinski2026 — StableAML，最贴近的 stablecoin 专项 ML
- ★★ kute2026 — 可解释+公平 AML（面向金融机构，SHAP）→ 也进监管/可解释
- ★ watson2025 — LLM 增强解释（可解释线，偏）
- ★ nicholls2024 — LLM XAI Bitcoin（偏）
- ★ sun2024llm — LLM 区块链安全综述（偏，可砍）

## Related Work §E 监管框架
- ★★★ fatf2023 — FATF VASP 标准（Travel Rule）
- ★★★ euaiact2024 — EU AI Act 高风险系统（你的可解释性=监管对齐论据）
- ★★ brownworth2024 — Tornado Cash 制裁监管研究
- ★★ chainalysis2024 — 洗钱报告（行业统计）
- ★★ chainalysisReactor2026 — Reactor 商业工具（对比"黑盒 vs 证据优先"）
- ★ chainalysisRonin2022 — Ronin 案例（chain-hopping 例证）
- ★ chainalysisTornado2022 — Tornado 制裁解读

## Related Work §F 可解释性 & 隐私合规（→ 也是 Future Work）
- ★★★ buterin2023 — Privacy Pools / 实用均衡（你 ZK 设想的根）
- ★★ constantinides2025 — zkMixer
- ★★ chaudhary2023 — zkFi
- ★★ ⭐veilaudit2025 — Auditor-Only Linkability（你"可验证合规+隐私"的学术实现）
- ★★ ⭐zkcross2024 — 隐私保护跨链审计架构（by-design，对照你的 post-hoc）

## Methodology §记账模型
- ★★★ ⭐montecrypto2024 — 记账守恒不变量（检测盗窃）；对照你的"溯源归属"记账，**必引**

## Methodology §跨链解析 / 协议级证据 + 稳定币发行方控制面
- ★★★ circleCCTP2026 + circleCCTPTechnical2026 — CCTP burn-mint，**你的最强证据锚**
- ★★★ tetherFreeze225m2023 — Tether 冻结（黑名单证据源 + 发行方执法）
- ★★ tetherIssuancePrimer2024 — 发行方控制面（Intro 稳定币论证）
- ★★ blocksec2023 — USDT 黑名单"冻结前已转移"（**passive-taint 动机核心**，也进 Intro）
- ★★ wormholeTokenTransfers2026 — Wormhole 机制（桥 registry 依据）
- ★★ acrossApiDocs2026 — Across status API（你的 Across 案例依据）
- ★★ layerzeroScanDocs2026 — LayerZero Scan（你的 Stargate 案例依据）
- ★ circleSolanaPremint2024 — USDC Solana 预铸（Solana 案例才引）

## 边角 / 候选砍掉（仅相关案例出现才留）
- ★ hyperliquidHyperevm2026 / hyperliquidTransfers2026 — HyperEVM，niche，除非正文讨论 HyperEVM 否则砍
- ★ bttcBridge2025 — BTTC 桥，niche 例子，可砍

## 一句话
强核心约 22 条足够撑起一份 30–40 页 final report 的 Related Work + Methodology；
LLM 可解释那几条（watson/nicholls/sun2024llm）和两条 Hyperliquid、bttc 是可砍的边角，
按正文是否真的用到再决定。
