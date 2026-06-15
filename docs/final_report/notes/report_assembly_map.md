# Final Report 总装图：把所有线索钉到章节（2026-06-14）

> 把本轮所有讨论（统一定义 / CCTP / CONNECTOR 定位 / 协议级证据 / dusting / ZK / 机构审计）
> 映射到具体章节。标注：🟢 现在就能写（素材/代码已就绪）｜🔴 需先做实验。
> 贯穿全文的**创新主线**：被动污染问题重定义 → 映射可观测性统一定义 → 比例暴露打分
> → 证据优先（CCTP 为最强锚、混币器/不透明桥为边界）→ 诚实极限 → ZK 未来。

## 1. Introduction 🟢
- 保留并**抬高** passive-taint 问题重定义（这是创新①，是全文 spine 的起点）。
- 写入三段式 contribution（能站住那一句）：问题重定义 + 统一可观测性定义 + 比例暴露打分。
- 明确**不**主张：桥解析、ZK 审计。Scope：普通用户 / EVM 稳定币 / USDC·USDT。
- 新内容点：把贡献收缩为"交集"，对应 related_work_positioning.md。

## 2. Related Work 🟢（草稿已在 related_work_positioning.md）
- 新增并 differentiate：CONNECTOR/Track&Trace（解析红海，不主张）、BridgeShield（攻击检测，目标不同）、
  VeilAudit/zkCross（ZK 审计＝未来工作）、TRM 七模型（业界平行，闭源）、Count of Monte Crypto（记账防御）。
- 保留 Möser/TaintRank/Liao 打分谱系。新内容点：2024–2026 这批文献整段是新的。

## 3. System Modeling 🟢
- 用重构后的分层架构（pip 包 / 8 模块 / 依赖单向向下）作 System 一节的图。
- 新内容点：模块化架构 + `is_tracing_boundary` 作为系统的核心抽象。

## 4. Methodology —— 创新主体，新内容最密集
- 4.1 Traceability Formalization 🟢：证据类型表**升级**为"确定性（协议 ID）vs 启发式（金额/时间）"
  两分——这就是"协议级证据 vs CONNECTOR 启发式"的落点。
- 4.2 Accounting Models 🟢：保留，挂 Count of Monte Crypto。
- 4.3 **统一机制定义（核心创新，最大新内容）** 🟢：`is_tracing_boundary` 谓词 + 映射可观测性光谱；
  混币器与不透明桥被统一为同类边界。**CCTP=最左锚（最强证据），混币器/不透明桥=最右（边界）**。
  代码已实现（mechanisms.py），写作时直接引 `is_tracing_boundary` + 6 项测试。
- 4.4 Cross-Chain Resolution 🟢：三层流程 + **CCTP 作为协议级证据的理想形态**
  （burn-mint、唯一 nonce、目标交易自带 Circle 签名来源凭证、信任坍缩进发行方）；
  对比协议 ID（确定）vs CONNECTOR 启发式匹配（概率）。诚实标注当前"索引器取回"步 + trustless 升级路径。
- 4.5 比例 taint 暴露打分 🟢：4/23 重构后的统一公式（占比 × 权重 × 方向独立 × max），
  点出 **dusting 内生鲁棒性**——把边界定义接到暴露分，是创新③。
- 4.6 Adaptive BFS + Hop Decay 🟢：保留；诚实标 ×0.6 工程参数，挂 compare_propagation 对比实验。

## 5. Evaluation —— 技术分 46% 所在
- 5.1 桥批量解析（按机制成功率）🔴：Across 已跑 ✅；需补 Stargate + 不透明桥对照
  → resolution rate by mapping_source ＝ 光谱命题的实测。
- 5.2 协议级证据案例集 🔴(部分)：CCTP（最强，待建 run_cctp_bridge_trace_case）+ 现有 Across/Stargate/Solana/Tron。
- 5.3 传播策略对比 🔴：current vs haircut vs improved（脚本就绪，缺真实数据输入）→ design choice vs alternatives。
- 5.4 对抗 dusting 鲁棒性 🔴：三种打分模型同台，量化比例模型抗污染 → 创新③的实证（半天，最高 ROI）。
- 5.5 Pilot 🟢：降级为描述性示例（不扩样，已定性）。

## 6. Discussion / Fundamental Limits 🟢
- 归属不可达（信息论边界）、隐私悖论、黑名单反应性、枚举不完备、**主动污染攻击（接 5.4）**、
  registry 腐烂、机构审计视角（法律权能不解链上极限）。

## 7. Conclusion + Future Work 🟢（final 必备新章）
- Conclusion：证明了什么（统一定义 + 暴露打分 + 证据优先，CCTP 锚），没证明什么（诚实边界）。
- Future Work：① ZK proof-of-clean-funds（收款方池子设计 + Privacy Pools/VeilAudit）；
  ② trustless 桥解析（去索引器，CONNECTOR 式链上 ID 扫描）；③ 第 2 级行为机制判别；④ 归属极限。

## 执行策略：两条线并行
- **写作线（🟢，现在就能动）**：1→2→3→4→6→7 的 spine 大部分可写——因为定义、架构、CCTP 论证、
  极限、未来工作都不依赖新实验。先把这条 spine 写出来，报告骨架立住。
- **实验线（🔴，喂第 5 章）**：5.4 dusting（半天）→ 5.1 多机制 + 5.2 CCTP case → 5.3 传播对比。
- 两线汇合于第 5 章。50% 新内容主要来自：4.3/4.4 重写 + 第 5 章实验 + 6/7 新章。
