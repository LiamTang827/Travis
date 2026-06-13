# 代码资产清单（重要性 × 完整性 × 报告对应）

> 2026-06-11 重构时生成。准绳：report 1 / report 2 实际描述过的方法 = 核心；
> 主流程引用的 = 支撑；两者都不沾的 = 已清理或归档。

## 第一层：核心引擎（src/cripto_analyst/）— final report 正文系统

| 文件 | 重要性 | 完整性 | 报告对应 |
|---|---|---|---|
| `aml_analyzer.py` | ★★★ 核心 | 可跑，14 项离线测试全过 | R1 Risk Scoring（已按 4/23 比例 taint 公式演化）+ R2 Bridge Registry / Cross-Chain Resolution（内置 BridgeTracer） |
| `trace_graph.py` | ★★★ 核心 | 可跑；树级传播仍为 ×0.6 工程参数（已如实注释） | R1 BFS / 自适应深度 / 中转识别 + R2 Adaptive-Depth BFS and Hop Decay |
| `threat_intel/mechanisms.py` + `mechanisms.json` | ★★★ 核心定义层 | 统一定义 + 两级判别器，6 项测试 | R2 Bridge Registry：把散落三表的"映射可观测性"提升为可执行定义 |
| `threat_intel/` 其余 | ★★★ 核心数据 | exchanges/OFAC 注册表 | 外部标签源 |

## 第二层：6 月跨链桥实验（experiments/traceability/）— report 2 证据生成器

| 脚本 | 报告对应 | 产物状态 |
|---|---|---|
| `run_across_bridge_trace_case.py` | R2 §Across trace | ✅ artifacts/bridge_trace_case/across_* |
| `run_stargate_bridge_trace_case.py` | R2 §Stargate trace | ✅ stargate_*（6/11 重跑过） |
| `run_solana_bridge_trace_case.py` | R2 §Non-EVM Surfaces | ✅ solana_*（registry-only） |
| `run_tron_bridge_trace_case.py` | R2 §Non-EVM Surfaces | ✅ tron_*（token-level） |
| `run_traceability_pilot.py` | R2 pilot（150 seeds，**描述性**：1-hop 注册表匹配，非溯源统计；不扩样，final report 降级为示例小节） | ✅ artifacts/traceability_pilot/ |
| `run_across_batch_resolution.py` | **final report 批量实验** | ⚠️ 产物缺失（bridge_batch_resolution/ 不存在）→ 待跑，Evaluation 弹药 #1 |
| `run_multichain_surface_smoke.py` | 多链冒烟 | ⚠️ 产物缺失 → 待跑 |

全部自包含（仅依赖 requests/dotenv），不 import src——可独立复跑，证据可复现。

## 第三层：对比实验弹药（experiments/）

| 文件 | 价值 |
|---|---|
| `compare_propagation.py` | **已实现三种传播策略**：`propagate_current`（×0.6 max）/ `propagate_haircut`（Möser 金额比例）/ `propagate_improved`（节点类型感知+多路径合并），含 real_data / convergent_paths / cex_damping 三场景 → final report "design choice vs alternatives" 的现成骨架 |
| `test_aml.py` | 14 项测试；Layer 1-B 已重写为当前比例模型（旧版测的是 4/23 前的加分制魔法数） |
| `replay_existing_json.py` / `debug_contract_interactions.py` | 离线调试工具，保留 |
| `ml/`（4 件套） | R1 ML Pipeline；定位=研究实验（README 已声明），final report 降级为辅助小节 |

## 本次重构清理记录（2026-06-11）

1. **`cross_chain_tracer.py`（475 行）移出 src** → `experiments/scripts/bridge/legacy_cross_chain_tracer.py`。
   零 import 引用的孤儿模块；生效的桥解析是 aml_analyzer 内的 BridgeTracer。docstring 已写明归档状态 + CelerTracer 已知 bug；`PROJECT_ROOT` 改为 parents[3]。
2. **trace_graph.py 删死代码**：`NODE_PROPAGATION_RATE` / `ENTITY_PROPAGATION_OVERRIDE`（写了从未用，思想已在 compare_propagation.py 实现）+ 10 个死 import + 对 experiments.ml 的反向依赖 + `--legacy` 假注释（CLI 无此参数）。DEPTH_DECAY 注释改为如实描述（工程参数，对比实验见 compare_propagation.py）。
3. **test_aml.py 修复 + 重写**：裸 import → 包 import；`EtherscanClient(KEY)` → `EVMClient(ChainConfig)` 多链 dict 签名；Layer 1-B 六个旧模型断言（40/25/35/10 分魔法数）重写为比例模型测试；测试 9 原来自测自（本地重新实现阈值逻辑），改为断言 `_calculate_risk` 真实输出（≥80/≥45/≥20）。

## 机制统一定义层（2026-06-14，第三轮重构）

把 report 2 散落在三张表里的同一性质（"进出映射不可还原"）提升为**可执行定义**，
回答"不是只弄 JSON"：

- **数据层** `mechanisms.json`：合并旧 `mixers.json` + `bridges.json` 为单一事实来源，
  49 条，统一 schema（kind / mechanism / mapping_source / evidence_strength / resolution_method）。
- **定义层** `mechanisms.py`：`MappingSource` 枚举 + `Mechanism` 数据类 +
  **核心谓词 `is_tracing_boundary`**（mapping 不可还原 ⇔ 追踪边界，把混币器与不透明桥
  归为同类实例）。
- **判别器**：`classify()` 两级——第 0 级地址精确查（零误判）→ 第 1 级协议指纹
  （`classify_by_fingerprint`，用 keccak256 离线验证的 Tornado 选择器/事件 topic0，
  能认出**未登记的同协议部署**——这是字典做不到的）。
- 旧常量 MIXER_CONTRACTS / BRIDGE_REGISTRY / OPAQUE_BRIDGE_ADDRS 全部从统一注册表
  **派生**，与旧值逐字节一致（14/35/6），调用方零改动；旧两个 JSON 已删。
- 测试：test_aml.py 新增 Layer 1-D 六项（定义自洽、统一边界命题、两级判别、不误判），
  全套 20 项通过。
- 报告对应：这就是把 "Bridge Registry" 一节从"按身份查表"提升到"按映射可观测性定义"
  的代码实现；`is_tracing_boundary` 谓词 = report 里那个统一定义的可执行形式。
- 仍是 Future Work：第 2 级行为/统计判别（认出全新协议，非已知协议的新部署）。

## 已知不一致（保留行为，写作时处理）

- ~~**等级阈值两套**~~：✅ 已于 2026-06-11 架构重构中统一到 `config.risk_level`
  （≥80 CRITICAL / ≥45 HIGH / ≥20 MEDIUM），评分引擎与树展示共用。
  注意：trace_graph 的展示颜色边界从 60/30 变为 45/20（行为变更，已记录）。
- **树级 ×0.6 与节点级比例公式哲学不统一**：R2 已定位 hop decay 为"距离描述符而非证据"，保持该口径；用 compare_propagation.py 跑对比实验作为 design-choice 支撑。
- `compliance_engine/`：本次未触碰（AI 生成、待定 baseline 角色，见 merge_inventory.md）。

## 架构重构（2026-06-11，第二轮）

2888 行单体 `aml_analyzer.py` 按职责拆为 8 个模块（职责 → 文件）：

```
配置/权重/统一阈值   config.py        137 行
链注册表/查询客户端  chains.py        391 行
地址/黑名单工具      utils.py          91 行
桥对端解析          bridge_tracer.py   73 行
数据模型            models.py          92 行
核心评分引擎        analyzer.py     1506 行
报告输出            reporting.py     510 行
CLI 入口            cli.py           165 行
```

- `aml_analyzer.py` 保留为**向后兼容转发层**：全仓旧 import 零修改继续工作。
- 运行时开关陷阱已处理：trace_graph 改为直接 import `analyzer` 模块设置
  BRIDGE_TRACE_ENABLED / HOP2_ENABLED（经 shim 设置不会生效，shim docstring 有警告）。
- `pyproject.toml`：`pip install -e .` 即装，新命令 `travis-analyze` / `travis-trace`，
  告别 PYTHONPATH=src hack；threat_intel JSON 注册表打包为 package-data。
- 验证：10 模块独立可导入、旧路径全兼容、开关生效、14/14 测试通过、双 CLI 正常。
- final report System Modeling 章节可直接引用此模块图（配置/数据/IO/引擎/展示分层）。
