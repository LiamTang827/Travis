# Related Work 定位：能站住的那一句话（2026-06-14）

> 触发：检索发现桥溯源/统一/ZK 审计已有强工作。结论不是改方向，是**收窄声称**。
> 引用按 arXiv ID 标注（准确）；最终 BibTeX 的作者字段需从各 arXiv 页面拉取，**不要凭空写作者名**。

## 能站住的一句话（写进 Introduction 的 contribution）

> 我们**不**主张在跨链桥解析或 ZK 合规审计上领先。本工作的贡献是一个面向**普通用户**的、
> **证据优先**的框架，它用单一的「映射可观测性」定义把**混币器与跨链桥统一为同一类追踪边界**
> （`is_tracing_boundary`），并把该分类接入一个**比例化的被动污染（passive-taint）暴露打分**——
> 这个"统一边界定义 + 暴露打分 + 普通用户视角"的交集，是现有工作未覆盖的空位。

## 差异化（每条都要在 Related Work 写明，避免 overclaim）

| 现有工作 | 它做了什么 | 我**不**碰 / 我**不同**在哪 |
|---|---|---|
| **CONNECTOR** (arXiv 2409.04937, IEEE) | 纯链上自动关联 deposit↔withdrawal，95.81% | 它桥解析**更强**（纯链上、过评审）。**不声称解析创新**；我用 API 是务实基线，CONNECTOR 式纯链上是 trustless 升级路径（写进 Future Work） |
| **Track and Trace** (2504.01822, =bib sun2025track) | 多链自动发现跨链交易 | 同上，属 resolution 红海 |
| **BridgeShield** (2508.20517) | 统一建模源链+链下+目标链 | 目的是**攻击检测**（异构图挖掘），非 AML 暴露；统一的目标不同 |
| **TRM "七模型一框架"** | 商业溯源框架 | proprietary、非学术；可引来佐证"业界亦如此收敛"，但不占学术空位 |
| **VeilAudit** (2510.12153, USENIX'26) | ZK + Auditor-Only Linkability + 门限身份揭示 | 这是我 ZK 设想的学术实现。**不声称 ZK 原创**，引为 Future Work 的对接对象 |
| **zkCross** (eprint 2024/888) | 跨链隐私保护审计 | 同上 |
| **Count of Monte Crypto** (2410.01107) | 记账模型防御 | 对接我的 Accounting Models 一节，可引为该视角的安全侧工作 |
| **SoK 桥安全/架构** (2312.12573, 2403.00405) | 按信任模型/架构/攻击面分类桥 | 不按"可观测性"、不为 AML、不含混币器统一 |

## 我**唯一**主张原创的交集（收缩到这里）

1. **混币器 ⊕ 桥的统一**：用「进出映射是否可公开还原」一个谓词把两者归为同类边界。
   现有桥分类（SoK）不含混币器；CONNECTOR/Track&Trace 做关联但不做边界统一。
2. **统一边界 → 比例 passive-taint 暴露打分**：把"追踪边界"接入"被污染资金占比"度量，
   且具备抗 dusting 的内生性质（见 #3 dusting 实验）。
3. **普通用户视角**：不是法执/机构工具；输出可验证暴露 + 诚实边界，而非黑盒风险分。

## 要新增进 bib 的（5 条，作者待从 arXiv 拉取）

connector2024 (2409.04937) · veilaudit2025 (2510.12153) · bridgeshield2025 (2508.20517) ·
montecrypto2024 (2410.01107) · zkcross2024 (eprint 2024/888)

已整理成可合并 BibTeX 片段：`docs/final_report/related_work_new_refs.bib`。

注：CONNECTOR 已有 IEEE TIFS 2025 版本，最终 key 建议用 `connector2025`；TRM blog 不是学术论文，但可作为 industry framing 引用，key 为 `trmCrossChainSwapTraceability2026`。

## 可直接放进 Related Work 的英文定位段落

Recent cross-chain tracing work makes it important to narrow the claim of this project. CONNECTOR~\cite{connector2025} directly addresses source-to-destination association for bridge applications, and does so in a more trustless way than the prototype here: it identifies deposit transactions from bridge-contract traces and matches withdrawals from execution logs, without relying on private bridge APIs or internal ledgers. Track-and-Trace~\cite{sun2025track} and related studies also treat cross-chain resolution as a first-class problem. Therefore, this report does not claim novelty in bridge resolution itself. The Across and Stargate/LayerZero cases are used as evidence-first engineering baselines: they show how a user-facing tracing system can record a bridge link when protocol evidence is available, and how it should label the middle step when the link depends on an indexer such as the Across API or LayerZero Scan. A trustless upgrade path would be to replace these API-assisted joins with CONNECTOR-style public-log association where the target bridge exposes enough on-chain structure.

Other work unifies cross-chain systems for different purposes. BridgeShield~\cite{bridgeshield2025} jointly models source-chain behavior, off-chain coordination, and destination-chain behavior in a heterogeneous graph, but its goal is attack detection for bridge security rather than AML exposure explanation. Count of Monte Crypto~\cite{montecrypto2024} studies accounting invariants for bridge defense, which is closest to the accounting-model discussion in this report. Industry tooling has converged on a similar observability lens: TRM Labs describes cross-chain swaps as multiple linkage models with different "truth locations" and different confidence levels~\cite{trmCrossChainSwapTraceability2026}. This supports the framing that traceability depends on where a mechanism places the observable join, but it does not by itself provide an open academic method for user-facing exposure scoring.

Privacy-preserving audit systems occupy a separate line of work. zkCross~\cite{zkcross2024} and VeilAudit~\cite{veilaudit2025} show that zero-knowledge and auditor-only linkability can support cross-chain accountability without full public disclosure. This report treats those systems as future-work directions rather than implemented contributions. Its narrower contribution is the combination of three elements: a single mapping-observability predicate that classifies mixers and opaque bridges as tracing boundaries, a proportional passive-taint exposure score built on that boundary definition, and an ordinary-user-facing explanation of what is known, what is inferred, and where tracing must stop.

## 动作顺序

1. （本文件已完成）锁定定位逻辑；
2. 写作 Related Work 时按上表逐条 differentiate，Introduction 用"能站住那一句"；
3. **优先级仍回到 Evaluation**：定位是 report-quality（20%），技术分（46%）靠实验——
   先打 #3 dusting（半天）。定位不阻塞建实验，两条线并行。
