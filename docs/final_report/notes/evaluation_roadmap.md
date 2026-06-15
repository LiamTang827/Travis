# Evaluation 实施路线图（喂 final report 第 5 章 · technical merit 46%）

> 2026-06-14 起。原则：每个实验有明确的 ① 做什么 ② 改哪个文件 ③ 度量指标
> ④ 产出表 ⑤ 工作量。guidelines 第 5 章硬要求："comparing to existing works,
> results supporting design choices versus alternative choices."

## #1 跨链桥批量解析 — 按机制的解析成功率 ⚙️ 进行中

- **状态**：Across 单机制已跑通 ✅（`artifacts/bridge_batch_resolution/`）
  445 个 V3 事件 → 66 笔稳定币候选 → 抽 20 笔 → **20/20 经 status API 解析到 fill**。
- **问题**：单机制 100% 太干净，不构成"对比"。真正的表需要**跨机制对比**。
- **做什么（三步把它变成真结果）**：
  1. `MAX_CASES_TO_VERIFY` 20→50，给更有意义的分母 + 记录失败原因分类；
  2. 新增 Stargate 批量变体（扫 Stargate 事件、走 LayerZero Scan 解析）——message-passing 机制；
  3. 新增不透明桥尝试（Orbiter/Synapse 一笔）→ 预期**无法解析** → 对照点。
- **改哪**：`run_across_batch_resolution.py`（调 MAX + 失败分类）；
  新建 `run_stargate_batch_resolution.py`（复制结构，换事件签名 + 解析器）。
- **度量**：resolution rate by `mapping_source`。
- **产出表 1**：indexer_api 机制 X% / rollup_derivation Y% / offchain_private 0%。
  → 这张表同时**实测了"可观测性光谱"命题**：成功率随 mapping_source 下降。
- **工作量**：1–2 天。

## #2 风险传播策略对比 — design choice vs alternatives

- **状态**：三种策略已实现（`compare_propagation.py`：current ×0.6 / Möser haircut /
  type-aware improved），合成场景能跑；**真实数据档缺输入**
  （`ml/data/transfers/0x0027....json` 不存在）。
- **做什么**：
  1. 用 `experiments/ml/fetch_transfers.py` 对 5–10 个地址（含已知 tainted + clean）
     拉真实 transfer，存成 `build_graph_from_transfers` 要的 JSON 格式；
  2. 跑三种策略，输出对比：同一 tainted 地址各给多少分、clean 地址误报率。
- **改哪**：`fetch_transfers.py` 跑一批 → 填 `ml/data/transfers/`；
  `compare_propagation.py` 的 `scenario_real_data` 即可激活；加一个汇总表输出。
- **度量**：三策略在同一子图上的打分差异 + 对 clean 地址的误报。
- **产出表 2**：current vs haircut vs improved。
- **工作量**：1 天（数据 + 跑）。

## #3 对抗鲁棒性 — dusting 主动污染攻击（用户自己提的批评 → 变成结果）

- **状态**：未建。**纯合成数据，不调 API，最高性价比**。
- **做什么**：合成 dusting 场景（给高流量地址打 10 USDT 脏款），跑三种打分模型
  （比例 taint / 旧加分制 / compliance_engine 跳数制），量化各自被攻击撬动的分数。
  预期：比例模型因分母存在近乎免疫（10/100000→0.01 分），二元/加分制一击中标。
- **改哪**：新建 `experiments/test_adversarial_dusting.py`，import 三种打分。
- **度量**：dusting 前后分数变化 Δ，按攻击金额扫一条曲线。
- **产出表 4**：对抗鲁棒性（比例模型的内生抗 dusting 是 4/23 重构的意外收益）。
- **工作量**：半天。直接回应 fundamental_limits 的"主动污染"。

## #4 可观测性光谱量化 — "不透明桥有多像混币器"

- **状态**：未建。依赖 #1 的不透明桥交易样本。
- **做什么**：对不透明桥转账，用"金额+时间窗"尝试重连源→目标，测重连成功率。
  成功率越低 = 越靠近混币器（光谱越右）。把"桥可以有混币功能"从论断变成实测。
- **产出表 3**：各机制的启发式重连成功率（透明桥不需要、不透明桥低、混币器≈0）。
- **工作量**：1 天（依赖 #1 数据）。

## #5 指纹判别器接入实时管线（feature，非实验）

- **状态**：`classify_by_fingerprint` 已实现 + 测试，但**未在 analyzer 实时调用**
  （它需要合约的事件 topic / 选择器，要先抓取）。
- **做什么**：analyzer 遇到未知合约对手方时，抓其近期事件 topic0，跑指纹 →
  实时认出未登记的 Tornado fork。让第 1 级判别器从"单测通过"变成"真在跑"。
- **改哪**：`analyzer.py` 对手方分类处 + `chains.py` 加一个取合约事件的方法。
- **工作量**：1–2 天。让机制统一层的价值落到实处。

## 排序（按 报告回报 ÷ 工作量）

```
Tier 1（必做，直接 = Evaluation 表）：#3 dusting（半天）→ #1 多机制（1-2天）→ #2 传播对比（1天）
Tier 2（有时间则强）：              #4 光谱量化 → #5 实时指纹
```

先打 #3（半天出一张最锋利的对抗表）和 #1 收尾（已跑通一半），两者合计 ~2 天，
就能让第 5 章从"4 个单案例"变成"3 张统计/对比表"。
