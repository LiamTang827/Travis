# Project Structure

这个仓库现在按用途分层，避免代码、数据、报告和训练产物混在根目录。

```text
src/cripto_analyst/   核心 AML 引擎
compliance_engine/    ChainSentinel 合规引擎（多链 collector + 检测器 + 前端 API）
data/                 输入数据和测试地址
experiments/          ML、Dune/Etherscan 探索脚本、桥溯源脚本、Notebook 生成脚本
artifacts/            生成产物、训练日志、报告输出
docs/                 文档和阶段报告
```

## 数据位置

- `data/blacklists/usdt_blacklist.csv`：USDT 黑名单。
- `data/wallets/`：wallet address Excel 和测试地址文本。
- `data/raw/`：原始 Excel 数据，例如 `USDT_full_2018.xlsx`。
- `data/test_cases/`：测试案例和批量测试结果 CSV。
- `experiments/ml/data/`：ML 数据集、transfer JSON、模型输出。
- `experiments/traceability/`：跨链桥溯源案例脚本（Across、Stargate、Tron、Solana）。
- `artifacts/bridge_trace_case/`：桥溯源案例的 JSON/MD 证据输出。
- `artifacts/reports/`：分析报告、Notebook、JSON 输出。
- `artifacts/logs/`：运行日志和临时输出。

## 报告区（docs/）

- `docs/interim_report/`：第一次中期报告（report 1）LaTeX 源 + 图。
- `docs/second_interim_report/`：第二次中期报告（report 2）中英文 LaTeX 源 + 图。
- `docs/final_report/`：final report 工作区，合并 report 1 + 2；`figures/` 放最终图，`notes/` 放合并笔记，详见其 README。
- `docs/reference/`：项目 proposal 和 guideline PDF。

## 可信度边界

`src/cripto_analyst` 是核心逻辑。`experiments/ml` 目前是研究实验区，已经有真实数据和模型产物，但标签审计、负样本质量、数据版本和复现实验链路还不够完整，不建议直接把 ML 输出当生产风控结论。
