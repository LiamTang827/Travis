# Travis
### TRAceable Verification Intelligence System

链上 AML 风险分析引擎。给定一个地址，Travis 扫描它的交易历史，判断它是否通过资金流动与已知风险实体（黑名单、混币器、不透明桥、高风险交易所）产生关联，并给出一个 0–100 的可解释风险分数。

---

## 设计出发点

最简单的做法：命中黑名单加 X 分，命中混币器加 Y 分，加法叠加。

问题在于这忽略了两件事：**金额大小**和**距离远近**。收过 1 美元黑钱和收过 100 万美元黑钱，风险完全不同；直接交互和隔了一个中间人，可信度也不同。

Travis 的做法是把风险建模成**污染比例**，参考 FATF 合规实践中的 Haircut Model：

```
污染比例 = Σ(风险交易额 × 类别权重 × 跳数衰减) / 该方向总流量
```

每一条风险证据都有 tx hash，可以独立核实。

---

## 图结构

把地址看成图的节点，USDT 转账看成有向边。

```
风险实体 A ──$30,000──▶ 被分析地址（总流入 $100,000）
风险实体 B ──$10,000──▶ 被分析地址
普通地址   ──$60,000──▶ 被分析地址
```

Travis 做的事：遍历被分析地址的所有交易，找出哪些边连向了风险节点，按边的金额占总流量的比例计算污染度。

---

## 1-hop 分析

**场景**：被分析地址直接和风险实体发生了 USDT 转账。

```
黑名单地址 ──$30,000 USDT──▶ 被分析地址
              这条"边"就是风险证据
```

- 风险主体 = 这个黑名单地址（直接对手方）
- 暴露金额 = 这笔交易实际的 USDT（$30,000）
- 贡献到污染率 = $30,000 × 1.0（黑名单权重）× 1.0（1-hop 衰减）÷ $100,000（总流入）= **30%**

1-hop 里，"边"就是证据——发生交易的金额直接就是暴露量。

---

## 2-hop 分析

**场景**：被分析地址的直接对手方 cp 本身不在任何黑名单，但 cp 的交易历史里出现过风险实体。

```
黑名单地址 ──$50,000──▶ cp ──$1,000──▶ 被分析地址
```

这里有两条边。关键问题是：**该用哪条边的金额？**

用 $50,000 是错的——那笔钱未必流到过被分析地址。被分析地址最多受到 $1,000 这条边的影响。

**Travis 的做法**：
1. 对 cp 打一个**节点分**（node_score）：扫描 cp 的交易，找到它接触的最高风险类别，取对应权重。上例中 cp 接触了黑名单，node_score = 1.0
2. 暴露金额 = 被分析地址与 cp 之间实际往来的 USDT（$1,000）
3. 贡献到污染率 = $1,000 × 1.0（cp 节点分）× 0.3（2-hop 衰减）÷ $100,000 = **0.3%**

2-hop 里，**节点**（cp 是否受污染）提供风险信号，**边**（被分析地址↔cp 的实际往来）提供暴露金额。两者分开，各司其职。

> `_score_cp_node()` 是未来扩展的钩子。现在它只看 cp 接触了什么类型的风险实体。后续可以在这里加入洗钱手法识别（peel chain、structuring、快速中转等），让节点分更精确。

---

## 风险类别与权重

| 类别 | 权重 | 说明 |
|------|------|------|
| USDT 黑名单 | 1.0 | Tether 官方冻结地址 |
| OFAC 制裁 / 勒索软件 / 黑客盗款 / 暗网 | 1.0 | 最高级别 |
| 混币器 | 0.5 | Tornado Cash 等，资金来源混淆 |
| 不透明桥 | 0.5 | 协议不可追踪，等效混币 |
| 高风险交易所 | 0.5 | KYC 执行不严 |
| 透明桥（对端有黑名单） | 0.5 | 可追踪但终点有问题 |
| 透明桥 | 0.3 | 协议透明，弱信号 |

---

## 跳数衰减

| 跳数 | 衰减 | 含义 |
|------|------|------|
| 1-hop | × 1.0 | 直接交互，全额计入 |
| 2-hop | × 0.3 | 隔一个中间节点，证据强度显著下降 |

衰减的理由：距离越远，被分析地址对这笔资金的"知情程度"和"参与程度"越低。犯罪分子多加一跳就是为了稀释这种关联，× 0.3 在数学上对应这种稀释。

---

## 评分计算（4步）

**Step 1 — 基础污染率**
```
received_taint = Σ(IN方向  amount × weight × decay) / total_inflow
sent_taint     = Σ(OUT方向 amount × weight × decay) / total_outflow
base_score     = max(received_taint, sent_taint) × 100
```

**Step 2 — 双向加成**
```
bilateral_bonus = min(received_taint, sent_taint) × 0.4
```
同时大额流入和流出可疑资金，是洗钱中转的典型特征，额外加罚。

**Step 3 — 类别最低分（Floor）**

| 条件 | 最低分 |
|------|--------|
| 1-hop 直接命中黑名单 | ≥ 55 |
| 1-hop 直接使用混币器 | ≥ 50 |
| 1-hop 使用不透明桥 | ≥ 35 |
| 1-hop 高风险交易所 | ≥ 20 |
| 2-hop cp 接触黑名单/混币器 | ≥ 20 |

保证行为本身的风险不被小金额稀释成 0 分。

**Step 4 — 多类别加分**
```
multi_cat_bonus = max(0, 1-hop 不同类别数 - 1) × 5
```
同时出现混币器 + 黑名单 + 不透明桥，说明资金路径刻意设计，额外加分。

### 风险等级

| 分数 | 等级 |
|------|------|
| ≥ 80 | CRITICAL |
| 45–79 | HIGH |
| 20–44 | MEDIUM |
| < 20 | LOW |
| 地址本身在黑名单 | 直接 CRITICAL 100 |

---

## 跨链桥的处理

Travis 按**协议设计**区分透明桥和不透明桥，与是否已实现 API 追踪无关：

**透明桥**：资金路径在链上有迹可查，理论上可以还原进出对应关系。

| 状态 | 代表协议 | Travis 的处理 |
|------|---------|--------------|
| API 已实现 | Stargate / LayerZero | 调用 API，追踪到目标链地址，继续分析 |
| API 待实现 | Hop / Celer / Across / Wormhole / deBridge / Connext / Squid 等 | 记录为 `transparent_bridge`，权重 0.3，暂不继续追踪 |

**不透明桥**：使用流动性池或 Maker 模式，资金进出没有链上可验证的一一对应关系，无法还原路径。

| 协议 | 原因 |
|------|------|
| Multichain | 流动性池，无法确定对应关系 |
| Orbiter / Owlto | Maker 模式，做市商作为中间人，来源不可追 |
| Synapse | 流动性池 |

不透明桥记录为 `opaque_bridge`，权重 0.5，追踪在此中断。

---

## 数据来源

| 来源 | 内容 |
|------|------|
| `usdt_blacklist.csv` | Tether 官方冻结地址，约 8,500 条（ETH + Tron） |
| `threat_intel/mixers.json` | 混币器合约地址（Tornado Cash 系列等） |
| `threat_intel/bridges.json` | 跨链桥合约地址，含透明/不透明分类 |
| `threat_intel/exchanges.json` | 高风险交易所热钱包 + 充值检测参数 |
| Etherscan / Blockscout API | 链上交易记录（普通交易 + Token 转账 + USDT 事件日志） |
| LayerZero Scan API | 跨链追踪（已实现） |

---

## 文件结构

```
Travis/
├── aml_analyzer.py          # 主引擎：多链分析 + 1/2-hop 扫描 + 评分 + 报告
├── cross_chain_tracer.py    # 透明桥追踪：tx hash → 目标链地址
├── trace_graph.py           # BFS 树状追踪（深度调查模式）
├── backend/                 # FastAPI Web 后端
├── frontend/                # React + React Flow 可视化前端
├── threat_intel/
│   ├── mixers.json
│   ├── bridges.json
│   └── exchanges.json
└── usdt_blacklist.csv
```

---

## 快速开始

```bash
pip install requests python-dotenv
cp .env.example .env   # 填入 API Key
```

```env
ETHERSCAN_API_KEY=your_key   # etherscan.io（免费，5 req/s）
BSCSCAN_API_KEY=your_key
POLYGONSCAN_API_KEY=your_key
ARBISCAN_API_KEY=your_key
# 不填则走 Blockscout 公开端点，速率较低
```

```bash
# 分析单个地址（Ethereum）
python3 aml_analyzer.py 0xYourAddress --chain ethereum

# 多链同时分析
python3 aml_analyzer.py 0xYourAddress --chains ethereum,bsc,polygon

# 只看最近 90 天
python3 aml_analyzer.py 0xYourAddress --chain ethereum --days 90

# 导出 JSON
python3 aml_analyzer.py 0xYourAddress --chain ethereum --json report.json

# 批量
python3 aml_analyzer.py --batch addresses.txt --chain ethereum

# 禁用 2-hop（加快速度）
python3 aml_analyzer.py 0xYourAddress --chain ethereum --no-hop2
```

### 参数

| 参数 | 说明 |
|------|------|
| `--chain` | ethereum / bsc / polygon / arbitrum / optimism / avalanche / base / tron |
| `--chains` | 多链逗号分隔 |
| `--no-hop2` | 禁用 2-hop |
| `--no-trace` | 禁用跨链追踪 |
| `--days N` | 只分析最近 N 天 |
| `--json FILE` | 导出 JSON |
| `--batch FILE` | 批量模式 |

---

## 扩展情报库

在对应 JSON 文件里加一行，重启生效，不需要改 Python 代码：

```json
// mixers.json
"0x合约地址": "名称"

// bridges.json
"0x合约地址": {
  "name": "协议名称",
  "traceable": true,
  "method": "layerzero_api",
  "dst_chains": ["arbitrum"]
}
```

---

## 已知局限

| 问题 | 说明 |
|------|------|
| 黑名单覆盖有限 | 仅含 Tether 冻结地址，不含 OFAC SDN / Lazarus Group 等 |
| 混币器仅 ETH | Tornado Cash 为 ETH 链，BSC 链（Cyclone Protocol 等）待补充 |
| 大部分桥追踪待实现 | Hop / Celer / Across 等 API 待接入，目前记为弱信号 |
| 只追踪 USDT | USDC / WBTC 等大额转账未纳入污染计算 |
| 2-hop cp 抽样 | 每条链最多取 5 个普通对手方做 2-hop，高频交易地址可能遗漏 |

---

## 参考文献

- Möser et al. (2014) *Towards Risk Scoring of Bitcoin Transactions*
- Liao et al. (2025) *Transaction Proximity* — Circle Research
- Mazorra et al. (2023) *Tracing Cross-chain Transactions between EVM-based Blockchains*
- Sun et al. (2025) *Track and Trace: Automatically Uncovering Cross-chain Transactions*
- FATF (2021) *Updated Guidance for a Risk-Based Approach to Virtual Assets*

---

> 本工具仅供学术研究与合规分析用途。黑名单数据来源于 Tether 官方公开冻结记录。
