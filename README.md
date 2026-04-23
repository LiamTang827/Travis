# Travis
### TRAceable Verification Intelligence System

链上 AML 风险分析引擎。以任意地址为起点，扫描其交易图，量化与黑名单、混币器、不透明桥的关联程度，输出可审计的风险评分与完整资金路径。

---

## 核心设计理念

**传统做法**：命中黑名单 → +50 分，命中混币器 → +30 分，固定加法累积。  
**问题**：金额不同、距离不同，贡献却一样，评分不可解释，无法跨地址比较。

**Travis 的做法**：比例污染传播（Proportional Taint / Haircut Model），参考 FATF 合规实践：

```
污染比例 = Σ(风险金额 × 类别权重 × 跳数衰减) / 总流量
```

- 收了 $10 黑钱 + $90 白钱 → 污染 10%，不是"命中即高危"
- 通过中间人的间接关联自动衰减（2-hop × 0.3）
- 每条风险证据都有对应 tx hash，可独立核实

---

## 分析框架

### 1-hop：直接命中

扫描被分析地址的所有交易，检查每个直接对手方是否属于已知风险实体。  
命中时，**以该笔交易的实际 USDT 金额**计入污染。

```
黑名单地址 ──$30,000 USDT──▶ 被分析地址（总流入 $100,000）

贡献 = 30,000 × 1.0(黑名单权重) × 1.0(1-hop衰减) / 100,000 = 30%
```

### 2-hop：中间节点评分

对每个普通对手方（中间节点 cp），拉取其交易记录，检查 cp 是否接触过风险实体。  
cp 被当作**一个独立节点**，按其接触的最高风险类别得到一个 node_score。  
**金额用被分析地址与 cp 之间的实际往来**，不用 cp 与风险实体之间的金额。

```
黑名单 ──$50,000──▶ cp ──$1,000──▶ 被分析地址（总流入 $100,000）

cp.node_score = 1.0（接触了黑名单）
贡献 = 1,000 × 1.0(cp节点评分) × 0.3(2-hop衰减) / 100,000 = 0.3%
```

这样做的理由：cp 的那笔 $50,000 可能根本没流到被分析地址。  
被分析地址最多受到 $1,000 这条边的污染，其危险程度由 cp 的节点评分决定。

> `_score_cp_node()` 是未来扩展的钩子，后续可加入 peel chain、structuring、快速中转等洗钱手法识别，使 cp 的节点评分更精确。

---

## 评分模型

### 类别权重

| 风险类别 | 权重 | 说明 |
|---------|------|------|
| OFAC 制裁 / 勒索软件 / 黑客盗款 / 暗网 | 1.0 | 最高级别 |
| USDT 黑名单 | 1.0 | Tether 官方冻结地址 |
| 混币器 | 0.5 | Tornado Cash 等 |
| 不透明桥 | 0.5 | 协议本身不可追踪 |
| 高风险交易所 | 0.5 | KYC 执行不严 |
| 透明桥（有黑名单关联） | 0.5 | 可追踪但对端有黑名单 |
| 透明桥 | 0.3 | 协议透明，仅弱信号 |

### 跳数衰减

| 跳数 | 衰减系数 | 含义 |
|------|---------|------|
| 1-hop | × 1.0 | 直接交互，全额计入 |
| 2-hop | × 0.3 | 中间节点的间接关联，证据强度显著下降 |

### 评分计算（4步）

**Step 1 — 基础污染率（Haircut）**
```
received_taint = Σ(IN方向  amount × weight × decay) / total_inflow
sent_taint     = Σ(OUT方向 amount × weight × decay) / total_outflow
base_score     = max(received_taint, sent_taint) × 100
```

**Step 2 — 双向洗钱加成**
```
bilateral_bonus = min(received_taint, sent_taint) × 0.4
```
同时大额流入流出可疑资金，是典型洗钱中转特征，额外加罚。

**Step 3 — 类别最低分保障（Floor）**

| 条件 | Floor |
|------|-------|
| 1-hop 直接命中黑名单 | ≥ 55 |
| 1-hop 直接使用混币器 | ≥ 50 |
| 1-hop 使用不透明桥 | ≥ 35 |
| 1-hop 高风险交易所 | ≥ 20 |
| 2-hop 间接关联黑名单/混币器 | ≥ 20 |

行为本身是风险信号，不论金额大小，保证不被稀释成 0 分。

**Step 4 — 多类别奖励**
```
multi_cat_bonus = max(0, 1-hop 不同类别数 - 1) × 5
```
同时命中混币器 + 黑名单 + 不透明桥，说明资金路径刻意设计，额外加分。

### 风险等级

| 最终分数 | 等级 |
|---------|------|
| ≥ 80 | CRITICAL |
| 45 ~ 79 | HIGH |
| 20 ~ 44 | MEDIUM |
| < 20 | LOW |
| 地址本身在黑名单 | 直接 CRITICAL 100 分 |

---

## 跨链桥分类

Travis 区分两类桥，判断标准是**协议设计是否透明**，与是否已实现 API 追踪无关：

| 类型 | 代表协议 | 处理方式 |
|------|---------|----------|
| **透明桥（API 已实现）** | Stargate / LayerZero | 调用 API 追踪目标链地址，继续分析 |
| **透明桥（API 待实现）** | Hop / Celer / Across / Wormhole / deBridge / Connext / Squid 等 | 记为 `transparent_bridge`，权重 0.3 |
| **不透明桥** | Multichain / Orbiter / Synapse / Owlto | 记为 `opaque_bridge`，权重 0.5，追踪中断 |

不透明桥使用流动性池或 Maker 模式，进出资金之间没有链上可验证的对应关系，无论有没有 API 都无法还原资金路径。

---

## 文件结构

```
Travis/
├── aml_analyzer.py          # 主引擎：多链分析 + 评分 + 报告输出
├── cross_chain_tracer.py    # 透明桥追踪：从 tx hash 解析目标链地址
├── trace_graph.py           # BFS 树状追踪（深度调查模式）
├── backend/                 # FastAPI Web 后端
├── frontend/                # React + React Flow 可视化前端
├── threat_intel/            # 威胁情报库（JSON，无需改 Python 代码）
│   ├── mixers.json          #   混币器合约（Tornado Cash 等）
│   ├── bridges.json         #   跨链桥合约（含透明/不透明分类）
│   └── exchanges.json       #   高风险交易所 + 充值地址检测参数
└── usdt_blacklist.csv       # Tether 官方冻结地址（约 8,500 条）
```

---

## 快速开始

### 安装依赖

```bash
pip install requests python-dotenv
```

### 配置 API Key

```bash
cp .env.example .env
```

```env
ETHERSCAN_API_KEY=your_key   # etherscan.io/myapikey（免费，5 req/s）
BSCSCAN_API_KEY=your_key     # bscscan.com/myapikey
POLYGONSCAN_API_KEY=your_key
ARBISCAN_API_KEY=your_key
# 其余链不填则走 Blockscout 公开端点（无需 key，速率较低）
```

### 分析地址

```bash
# 单链分析
python3 aml_analyzer.py 0xYourAddress --chain ethereum

# 多链分析
python3 aml_analyzer.py 0xYourAddress --chains ethereum,bsc,polygon

# 只看最近 90 天
python3 aml_analyzer.py 0xYourAddress --chain ethereum --days 90

# 导出 JSON
python3 aml_analyzer.py 0xYourAddress --chain ethereum --json report.json

# 批量分析
python3 aml_analyzer.py --batch addresses.txt --chain ethereum

# 禁用 2-hop（加快速度）
python3 aml_analyzer.py 0xYourAddress --chain ethereum --no-hop2
```

### 参数说明

| 参数 | 说明 |
|------|------|
| `--chain` | 指定单链（ethereum / bsc / polygon / arbitrum / optimism / avalanche / base / tron） |
| `--chains` | 指定多链，逗号分隔 |
| `--no-hop2` | 禁用 2-hop 分析 |
| `--no-trace` | 禁用跨链桥追踪 |
| `--days N` | 只分析最近 N 天 |
| `--json FILE` | 导出 JSON 报告 |
| `--batch FILE` | 批量模式，逐行读取地址 |

---

## 扩展情报库

新增混币器地址，编辑 `threat_intel/mixers.json`：

```json
"0x新合约地址": "名称"
```

新增跨链桥，编辑 `threat_intel/bridges.json`：

```json
"0x合约地址": {
  "name": "协议名称",
  "traceable": true,
  "method": "layerzero_api",
  "dst_chains": ["arbitrum", "optimism"]
}
```

重启程序生效，无需改动 Python 代码。

---

## 新增支持链

在 `aml_analyzer.py` 的 `EVM_CHAIN_REGISTRY` 加一条记录：

```python
"linea": ChainConfig(
    name="Linea", native_token="ETH",
    api_url="https://api.lineascan.build/api",
    api_key=os.getenv("LINEASCAN_API_KEY", ""),
    backup_url="https://explorer.linea.build/api",
    usdt_contract="0xa219439258ca9da29e9cc4ce5596924745e12b93",
    explorer_url="https://lineascan.build",
)
```

其余所有业务逻辑自动适配。

---

## 已知局限

| 问题 | 说明 |
|------|------|
| 黑名单覆盖有限 | 目前仅含 Tether 冻结地址，未包含 OFAC SDN、Lazarus Group 等 |
| 混币器仅覆盖 ETH | Tornado Cash 为 ETH 链，BSC 链混币器（Cyclone Protocol 等）待补充 |
| 桥追踪部分待实现 | Hop / Celer / Across 等桥的 API 追踪待开发，当前记为透明桥弱信号 |
| API 速率限制 | 免费 Key 5 req/s，深度分析需等待，建议申请付费 Key |
| 仅追踪 USDT | USDC / DAI / WBTC 等大额转账未纳入污染计算 |

---

## 参考文献

- Möser et al. (2014) *Towards Risk Scoring of Bitcoin Transactions*
- Liao et al. (2025) *Transaction Proximity* — Circle Research
- Mazorra et al. (2023) *Tracing Cross-chain Transactions between EVM-based Blockchains*
- Sun et al. (2025) *Track and Trace: Automatically Uncovering Cross-chain Transactions*
- FATF (2021) *Updated Guidance for a Risk-Based Approach to Virtual Assets*

---

> 本工具仅供学术研究与合规分析用途。黑名单数据来源于 Tether 官方公开冻结记录。
