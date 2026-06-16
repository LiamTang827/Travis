# Travis 系统 输入/输出 完整规格（2026-06-16）

> 本系统有四个入口，逐个给出**输入**和**输出**的完整字段。
> 一句话总览：**输入 = 一个地址（或一笔交易哈希）+ API key；输出 = 一个可拆解到具体交易的风险/暴露证据，外加诚实的追踪边界标注。**

---

## 0. 全局前置输入（所有入口共用）

| 输入 | 来源 | 说明 |
|---|---|---|
| `ETHERSCAN_API_KEY` | `.env` | 必需；EVM 多链查询（Etherscan V2 统一端点） |
| 黑名单 CSV | `data/blacklists/usdt_blacklist.csv` | USDT 冻结地址，~2900 条 |
| 威胁情报注册表 | `src/cripto_analyst/threat_intel/` | mechanisms.json（53 条：桥+混币器，含 CCTP）、exchanges.json、ofac_sanctioned.json |

---

## 1. `travis-analyze` —— 单/多链地址风险分析（核心入口）

### 输入
| 参数 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `address` | 位置参数 | — | 要分析的地址（0x / Tron base58） |
| `--chain` | str | 自动判断 | 强制指定单链（ethereum/bsc/polygon/arbitrum/optimism/avalanche/base/tron） |
| `--chains` | str | — | 多链，逗号分隔（如 `ethereum,bsc,polygon`） |
| `--days` | int | 365 | 只看最近 N 天（0=不限） |
| `--no-hop2` | flag | off | 关闭 2 跳分析（提速） |
| `--no-trace` | flag | off | 关闭透明桥跨链追踪（提速） |
| `--json FILE` | path | — | 导出完整 JSON 报告 |
| `--csv FILE` | path | — | 批量模式导出 CSV 汇总 |
| `--batch FILE` | path | — | 从文件逐行读地址批量分析 |
| `--output DIR` | path | — | 每个地址报告存为 `<DIR>/<地址>.txt` |
| `--full` | flag | off | 打印全部稳定币流水 |

### 输出（`RiskReport` 数据结构，终端 + 可选 JSON）
**评分结果（核心）**
| 字段 | 类型 | 含义 |
|---|---|---|
| `risk_score` | float 0–100 | = taint_ratio × 100 |
| `risk_level` | str | CRITICAL≥80 / HIGH≥45 / MEDIUM≥20 / LOW（统一阈值 `config.risk_level`） |
| `taint_ratio` | float 0–1 | = max(received_exposure, sent_exposure)，被污染资金占比 |
| `received_exposure` | float 0–1 | 收款侧污染比例 |
| `sent_exposure` | float 0–1 | 付款侧污染比例 |

**证据与对手方**
| 字段 | 含义 |
|---|---|
| `indicators[]` | 评分的最小证据单元：每条含 category / category_weight / counterparty / direction / amount_usdt / hop / tx_hashes / chain（**每一分都可拆回具体交易**） |
| `top_counterparties[]` | 高频对手方（展示用） |
| `bridge_interactions[]` | 透明桥交互（含 CCTP，traceable=true） |
| `opaque_bridge_interactions[]` | 不透明桥交互（追踪边界） |
| `mixer_interactions[]` | 混币器交互（追踪边界） |
| `cross_chain_findings[]` | 跨链追踪结果（源 tx → 目标链/目标地址） |
| `per_asset{}` | 每种稳定币的独立 taint/流量 |
| `counterparty_table[]` | 对手方聚合（地址+方向+金额+风险标签+taint_pct） |
| `transactions[]` | 全量稳定币流水（JSON 始终写入） |
| `warnings[]` | 诚实边界：presence-only（有接触无资金，不计分）、单链覆盖等 |
| `score_breakdown{}` | 评分可解释分解 |

### 库 API 等价物
```python
from cripto_analyst.analyzer import AMLAnalyzer
report = analyzer.analyze(address, chain="ethereum")   # 入: 地址 → 出: RiskReport
```

---

## 2. `travis-trace` —— BFS 资金溯源树

### 输入
| 参数 | 默认 | 含义 |
|---|---|---|
| `address` | — | 根地址 |
| `--chain` | ethereum | 链（ethereum/tron） |
| `--depth` | 3 | 最大追踪深度 |
| `--children` | 5 | 每节点最大子节点数 |
| `--nodes` | 50 | 全局节点上限 |
| `--depth-bonus` | 1 | 可疑分支额外深度 |
| `--time-window` | 0 | 只分析最近 N 天 |
| `--json FILE` | — | 导出树 JSON |
| `--mermaid FILE` | — | 导出 Mermaid 流程图（.md） |

### 输出（`TraceNode` 树）
每个节点字段：`address / chain / depth / node_type`（clean/blacklisted/mixer/opaque_bridge/bridge_dst/high_risk/suspect）`/ risk_score / via_bridge / subtree_max_risk / subtree_blacklist_count / contamination_score / in_degree / converge_from / children[]`。
终端输出：树状图 + 高风险汇总（黑名单/混币器/不透明桥/跨链/中转嫌疑）。

---

## 3. 机制判别器 `classify()` —— 归一化的统一入口

### 输入
```python
from cripto_analyst.threat_intel.mechanisms import classify
classify(address, selectors=(), event_topics=())
```
- `address`：要判别的合约地址；
- `selectors` / `event_topics`：可选，该合约被观测到的函数选择器 / 事件 topic0（用于第 1 级指纹）。

### 输出：`Mechanism` 对象 或 `None`
| 字段 | 含义 |
|---|---|
| `address / name` | 地址 / 名称 |
| `kind` | bridge / mixer |
| `mapping_source` | onchain_event / rollup_derivation / indexer_api / offchain_private / zk_destroyed / none |
| `evidence_strength` | strong / moderate / weak / none |
| `mechanism` | burn_mint / message_passing / liquidity_fill / maker_fill / zk_pool / … |
| `is_tracing_boundary` | **核心谓词**：映射不可还原 ⇔ 追踪边界（混币器/不透明桥=True） |
| `resolution_method` | 解析方法（layerzero_api / across_api / cctp_iris_api / …） |
| `inferred` | True=指纹推断（未登记部署），False=地址精确命中 |

判别两级：① 地址精确查（零误判）→ ② 协议指纹（认出未登记部署）。`None` = 无判断。

---

## 4. 跨链桥溯源案例 `run_*_bridge_trace_case.py`

### 输入
- 一笔**源链交易哈希**（CLI 参数），例如一笔 Stargate/Across/CCTP 出 Ethereum 的稳定币交易。

### 输出（`artifacts/bridge_trace_case/*.json` + `.md`）
| 字段 | 含义 |
|---|---|
| `classification` | protocol-assisted traceable / registry-only / … |
| `source_transaction` / `source_explorer` | 源 tx + 浏览器链接 |
| `source_contract_matched` | 命中的桥/协议合约 |
| `destination_resolution` | 目标解析：resolved / status / dst_chain / destination_tx |
| `destination_transaction` / `destination_explorer` | 目标 tx + 链接 |
| `destination_receipt_observed` | 是否回锚到目标链 receipt（trustless 验证） |
| `evidence_strength` | 三段式：source(trustless) → bridge(trusted) → destination(trustless) |

批量版 `run_across_batch_resolution.py`：**输入**=区块窗口；**输出**=N 笔候选的解析成功率统计表。

---

## 一句话闭环

```
输入:  一个地址  →  travis-analyze  →  风险分(0-100) + 可拆解证据 + 边界标注
       一个地址  →  travis-trace    →  资金溯源树 + 中转/跨链/边界节点
       一笔交易  →  run_*_trace_case →  三段式跨链证据链
       一个合约  →  classify()      →  机制分类 + 是否追踪边界
```
每个输出都满足两条不变量：**① 每个风险分数可拆回具体链上交易；② 追踪在不可观测处诚实终止并标注。**
