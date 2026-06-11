# Travis / CriptoAnalyst

TRAceable Verification Intelligence System.

链上 AML 风险分析项目。给定钱包地址，核心引擎会查询链上交易、USDT 黑名单、OFAC 地址、混币器、跨链桥和高风险交易所，输出风险分数和证据链。

前后端 Web 层已移除；当前仓库按“核心代码 / 数据 / 实验 / 产物 / 文档”重新整理。

## 快速开始

```bash
pip install requests python-dotenv
cp .env.example .env
```

`.env` 里填 API key。不填时部分链会尝试公开备用端点，但速度和覆盖会差一些。

```bash
# 单链分析
PYTHONPATH=src python3 -m cripto_analyst.aml_analyzer 0xYourAddress --chain ethereum

# 多链分析
PYTHONPATH=src python3 -m cripto_analyst.aml_analyzer 0xYourAddress --chains ethereum,bsc,polygon

# 只看最近 90 天
PYTHONPATH=src python3 -m cripto_analyst.aml_analyzer 0xYourAddress --chain ethereum --days 90

# 导出 JSON 报告
PYTHONPATH=src python3 -m cripto_analyst.aml_analyzer 0xYourAddress --chain ethereum --json artifacts/reports/report.json

# 深度资金图追踪
PYTHONPATH=src python3 -m cripto_analyst.trace_graph 0xYourAddress --chain ethereum --depth 3
```

## 当前结构

```text
.
├── src/cripto_analyst/          # 核心 AML 引擎
│   ├── aml_analyzer.py
│   ├── trace_graph.py
│   ├── cross_chain_tracer.py
│   └── threat_intel/
├── data/                        # 输入数据和测试地址
│   ├── blacklists/
│   ├── raw/
│   ├── test_cases/
│   └── wallets/
├── experiments/                 # ML、探索脚本、Notebook 工具
│   ├── ml/
│   ├── notebooks/
│   └── scripts/
├── artifacts/                   # 生成产物
│   ├── logs/
│   ├── reports/
│   └── training/
└── docs/                        # 说明文档和阶段报告
```

## 重要数据

| 路径 | 内容 |
|---|---|
| `data/blacklists/usdt_blacklist.csv` | USDT 黑名单 |
| `data/wallets/wallet_addresses - share.xlsx` | wallet address 数据 |
| `data/wallets/副本wallet_addresses - share.xlsx` | wallet address 副本 |
| `data/raw/USDT_full_2018.xlsx` | 原始 USDT Excel 数据 |
| `data/test_cases/` | 测试地址、测试结果 CSV |
| `src/cripto_analyst/threat_intel/` | 混币器、桥、交易所、OFAC 地址库 |
| `experiments/ml/data/` | ML 标签、特征矩阵、transfers JSON、模型输出 |
| `artifacts/reports/` | 已生成 AML 报告、Notebook、JSON |
| `artifacts/training/catboost_info/` | CatBoost 训练日志 |

## ML 可信度

`experiments/ml` 里已经有真实训练数据和模型产物，但我仍然建议把它视为研究实验，而不是生产判定模块。

主要原因：

- 标签来源混合了 Tether 黑名单、OFAC 和采样正常地址，仍需标签审计。
- `normal` 样本可能包含未知风险地址，负样本可信度不足。
- 需要固定数据快照、模型版本、训练参数和评估报告。
- 需要检查时间泄漏和同地址/相关地址泄漏。

当前更适合作为特征探索和模型原型。生产评分仍应以 `src/cripto_analyst/aml_analyzer.py` 的规则和证据链为主。

## 文档

- [docs/PROJECT_STRUCTURE.md](docs/PROJECT_STRUCTURE.md)
- [docs/TRACE_LOGIC.md](docs/TRACE_LOGIC.md)

本工具仅供学术研究与合规分析用途。链上风险评分不应作为单独的执法、封禁或资产处置依据。
