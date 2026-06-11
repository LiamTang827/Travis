# Final Report 合并清单（report 1 + report 2 → final）

> 生成日期：2026-06-11。结论：沿用 report 2（2026-06-10 版）的章节骨架，
> 但受 50% 新内容红线约束，旧章节文字需重写压缩，页数预算向 Evaluation 倾斜。

## Guidelines 硬约束（CS65xx, 2026 Jan 版）

- **截止 2026-07-21**，迟交每天扣该项满分的 20%；presentation 7/27–31（15 分钟 + 3–5 分钟问答）
- **占分**：report 质量 20% + technical merit 46%（全课 66%）
- **篇幅**：~30–40 页（不含代码）
- **与两份 interim 重叠 ≤50%，新内容 ≥50%**（Turnitin 查，超线 severe penalties）
- 第 5 章必须是 "Evaluations **comparing to existing works**, and results supporting
  the design choices **versus alternative choices**"
- 必含章节：Intro / Related Work / System Modeling / Methodology / Evaluation /
  **Conclusion** / **Future Work** / References
- 格式：Times New Roman 12、单倍行距、margins 2.54cm、封面（姓名/学号/题目/导师）
- **GenAI 使用必须声明**（引用 + copy-editing 声明），源代码交 Canvas，PDF ≤10MB
- A/A+ 标准：完成度达到可投会议/期刊

## 新内容从哪来（凑足 ≥50% 的候选清单，按性价比排序）

1. **桥解析批量化**：`run_across_batch_resolution.py` 已存在——把单案例扩成
   N 笔交易的解析成功率表（成功率、失败原因分类、按机制分组）。
   直接满足 "results supporting design choices"。
2. **打分公式对比实验**：同一测试集上跑三种打分——统一 taint 比例公式 vs
   report 1 旧加分制 vs compliance_engine 的 100/50/25 跳数制。
   既是 "versus alternative choices"，又顺手解决双引擎定位问题（变 baseline）。
3. **与 existing works 对比**：实现 Poison / Haircut（Möser et al.，已在引用列表）
   作为 baseline 与 taint 公式对比——满足 "comparing to existing works"。
4. **扩大 pilot**：150 seeds → 500+，让 traceability_continuation 从 2 条变成
   有统计意义的数字；按桥类别出统计表。
5. **消融**：固定深度 vs 自适应深度 BFS（节点预算、误报对比）。
6. 4 月 23 日 taint 重构的方法论重写（report 2 自称 proportional model 未实现，
   所以这部分写出来就是新内容）。

## 页数预算建议（35 页目标）

Intro 3–4 / Related Work 4–5（重写压缩）/ System Modeling 3–4 /
Methodology 8–10 / **Evaluation 10–12** / Conclusion + Future Work 2 / Ref 2–3

## 两份报告章节对照

| 章节 | report 1 (main.tex, 481 行) | report 2 (en.tex, 601 行) | final report 处理 |
|---|---|---|---|
| Introduction | 6 小节 | 7 小节（多 Scope 小节） | 用 report 2，更新时态（interim → final） |
| Related Work | 7 小节 | 7 小节（同构，措辞更新） | 用 report 2 |
| System Modeling | 2 小节 | 2 小节 | 用 report 2 + 检查架构图是否最新 |
| Methodology | Risk Scoring / Sampling Bias / ML Pipeline | Traceability Formalization / Accounting Models / Bridge Registry / Cross-Chain Resolution / Adaptive BFS+Hop Decay | **report 2 五小节为主干**，回填 report 1 的 Risk Scoring（按重构后 taint 公式改写）；Sampling Bias 压缩合入；ML Pipeline 降级为一小节并明确"研究实验"定位 |
| Analysis / Evaluation | Model Comparison / Confusion Matrix / Feature Importance / Module Status / Limitations | Across / Stargate / 桥处理总表 / Solana+Tron / Fundamental Limits | 合并为统一 Evaluation：桥案例×4 + traceability pilot 为主，ML 图表（confusion matrix 等）作为辅助小节保留 |
| Milestones / Next Report | 有 | 有 | **删除**，换成 Conclusion + Future Work（final report 必备） |

## report 1 独有、需要决定去留的素材

- `figures/confusion_matrix.pdf`、`importance_xgboost.pdf`、`importance_randomforest.pdf`、`model_comparison.pdf` → 建议保留进 ML 辅助小节
- Sampling Bias Corrections 一节 → 压缩为段落
- BFS 风险评分细节 → **必须按 2026-04-23 重构后的统一 taint 公式重写**（commit f1e7520），不能照抄 report 1 的旧加分制

## 必须解决的一致性问题

1. **proportional model 口径矛盾**：report 2 Introduction（passive taint 小节）写
   "I have not implemented that proportional model yet"，但 4 月 23 日代码已实现
   节点级比例 taint（contribution = amount × risk / total_flow，见仓库 README）。
   final report 需统一口径：建议写"节点级比例公式已实现（1–2 hop），
   任意深度路径级 flow accounting 仍未实现（BFS 深层传播仍为 ×0.6 max-decay）"。
2. **×0.6 hop decay 定位**：沿用 report 2 的说法——它是距离描述符
   （descriptor of distance），不是证据，不参与证据链构造。
3. **compliance_engine（ChainSentinel）角色**：与 src/cripto_analyst 双引擎并存、
   打分哲学不同（100/50/25 跳数 vs taint 比例）。final report 写谁？
   ——待与队友确认分工后定调（团队分工：一人整体框架，一人混币器/桥）。

## 素材位置速查

- 桥案例证据：`artifacts/bridge_trace_case/*.{json,md}`（Across / Stargate / Solana / Tron）
- pilot 实验：`artifacts/traceability_pilot/summary.md`（150 seeds, 107 evidence rows）
- 两份 bib：`docs/interim_report/sample.bib` + `docs/second_interim_report/sample.bib`，合并去重
- 格式要求：`docs/reference/Project_Guidelines_2026 Jan_updated.pdf`（动笔前对照 final report 章节要求）
