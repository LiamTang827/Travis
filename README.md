# Travis
### TRAceable Verification Intelligence System

链上 AML 风险分析引擎。给定一个地址，扫描它的交易历史，输出一个 0–100 的风险分数和完整的证据链。

---

## 核心模型

### 把链上交易看成一张图

- **节点** = 地址
- **边** = USDT 转账，有方向和金额

```
地址A ──$30,000──▶ 被分析地址
地址B ──$10,000──▶ 被分析地址
地址C ──$60,000──▶ 被分析地址
总流入 = $100,000
```

### 统一公式

对被分析地址的**每一个直接对手方 X**，计算它对污染率的贡献：

```
贡献 = 与X的往来金额 × X的风险指数 / 总流量
```

所有贡献加总，得到污染率，换算成 0–100 分。

### X的风险指数怎么确定

**情况一：X 在我们的数据库里**（黑名单、混币器、不透明桥、高风险交易所）

直接查表，风险指数 = 对应类别的权重。

```
黑名单地址A ──$30,000──▶ 被分析地址

贡献 = 30,000 × 1.0（黑名单权重）/ 100,000 = 30%
```

**情况二：X 是普通地址，数据库里没有**

需要去链上拉 X 的交易，看 X 自己有没有和风险实体交互，计算 X 自身的污染比例作为它的风险指数：

```
X的风险指数 = Σ(X与风险实体往来的USDT × 风险类别权重) / X的USDT总流量
```

举例：

```
黑名单 ──$50,000──▶ X（总流入$100,000）──$1,000──▶ 被分析地址

X的风险指数 = 50,000 × 1.0 / 100,000 = 0.5

被分析地址的贡献 = 1,000 × 0.5 / 100,000 = 0.5%
```

X 的污染比例（0.5）本身就反映了"X 有一半资金来自黑名单"这个事实，不需要额外打折。用的金额是被分析地址和 X 之间实际往来的 $1,000，不是黑名单和 X 之间的 $50,000。

---

## 数据库里有什么

### 风险类别和权重

| 类别 | 权重 | 说明 |
|------|------|------|
| USDT 黑名单 | 1.0 | Tether 官方冻结地址（约 8,500 条） |
| OFAC 制裁 / 勒索软件 / 黑客盗款 / 暗网 | 1.0 | 最高级别 |
| 混币器 | 0.5 | Tornado Cash 等，资金来源故意混淆 |
| 不透明桥 | 0.5 | 协议无法追踪资金去向，等效混币 |
| 高风险交易所 | 0.5 | KYC 执行不严 |
| 透明桥（对端有黑名单） | 0.5 | 可追踪但目标地址有问题 |
| 透明桥 | 0.3 | 协议透明，弱信号 |

### 跨链桥的分类

Travis 按**协议本身是否透明**分类，与是否已经实现 API 追踪无关：

**透明桥**：资金进出在链上有可验证的对应关系，原则上可以还原路径。

| 状态 | 协议 | 处理 |
|------|------|------|
| API 已实现 | Stargate、LayerZero | 追踪到目标链地址，继续分析 |
| API 待实现 | Hop、Celer、Across、Wormhole、deBridge、Connext、Squid 等 | 记为透明桥（权重 0.3），暂不追踪 |

**不透明桥**：使用流动性池或做市商模式，进出资金没有链上一一对应关系，路径无法还原。

| 协议 | 原因 |
|------|------|
| Multichain | 流动性池，无法确认对应关系 |
| Orbiter、Owlto | 做市商模式，资金来源不可追 |
| Synapse | 流动性池 |

不透明桥记录为 opaque_bridge（权重 0.5），追踪在此中断。

---

## 评分计算

### 第一步：计算污染率

```
received_taint = Σ(每笔流入 × 对手方风险指数) / 总流入
sent_taint     = Σ(每笔流出 × 对手方风险指数) / 总流出
```

### 第二步：双向加成

```
taint_ratio = max(received_taint, sent_taint)
            + min(received_taint, sent_taint) × 0.4
```

同时大额流入和流出可疑资金，是洗钱中转的特征，额外加罚。

### 第三步：行为最低分（Floor）

当 USDT 金额很小时，污染率会被稀释接近 0，但行为本身已经是信号。Floor 保证不会因为金额小而漏判：

| 条件 | 最低分 |
|------|--------|
| 直接和黑名单地址有 USDT 往来 | ≥ 55 |
| 直接和混币器有 USDT 往来 | ≥ 50 |
| 直接使用不透明桥 | ≥ 35 |
| 直接和高风险交易所有往来 | ≥ 20 |
| 普通对手方的风险指数来自黑名单/混币器 | ≥ 20 |

### 第四步：多类别加分

```
multi_cat_bonus = (不同风险类别数 - 1) × 5
```

同时出现黑名单 + 混币器 + 不透明桥，说明资金路径刻意设计。

### 风险等级

| 分数 | 等级 |
|------|------|
| ≥ 80 | CRITICAL |
| 45–79 | HIGH |
| 20–44 | MEDIUM |
| < 20 | LOW |
| 地址本身在黑名单 | 直接 CRITICAL 100 |

---

## 数据来源

| 来源 | 内容 |
|------|------|
| `usdt_blacklist.csv` | Tether 官方冻结地址，约 8,500 条（ETH + Tron） |
| `threat_intel/mixers.json` | 混币器合约地址 |
| `threat_intel/bridges.json` | 跨链桥合约，含透明/不透明分类和追踪方法 |
| `threat_intel/exchanges.json` | 高风险交易所热钱包 |
| Etherscan / Blockscout API | 普通交易、ERC-20 转账、USDT 事件日志 |
| LayerZero Scan API | 跨链追踪（已接入） |

支持链：Ethereum、BSC、Polygon、Arbitrum、Optimism、Avalanche、Base、Tron。无 API Key 时自动回落到 Blockscout 公开端点。

---

## 文件结构

```
Travis/
├── aml_analyzer.py          # 主引擎：多链扫描、风险计算、报告输出
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
cp .env.example .env
```

`.env` 填入 API Key（不填则走公开端点，速率较低）：

```env
ETHERSCAN_API_KEY=your_key
BSCSCAN_API_KEY=your_key
POLYGONSCAN_API_KEY=your_key
ARBISCAN_API_KEY=your_key
```

```bash
# 单链分析
python3 aml_analyzer.py 0xYourAddress --chain ethereum

# 多链
python3 aml_analyzer.py 0xYourAddress --chains ethereum,bsc,polygon

# 只看最近 90 天
python3 aml_analyzer.py 0xYourAddress --chain ethereum --days 90

# 导出 JSON
python3 aml_analyzer.py 0xYourAddress --chain ethereum --json report.json

# 批量
python3 aml_analyzer.py --batch addresses.txt --chain ethereum

# 禁用普通对手方的二次查询（更快，但漏掉间接关联）
python3 aml_analyzer.py 0xYourAddress --chain ethereum --no-hop2
```

### 参数说明

| 参数 | 说明 |
|------|------|
| `--chain` | ethereum / bsc / polygon / arbitrum / optimism / avalanche / base / tron |
| `--chains` | 多链，逗号分隔 |
| `--no-hop2` | 跳过对普通对手方的二次链上查询 |
| `--no-trace` | 跳过跨链桥追踪 |
| `--days N` | 只分析最近 N 天 |
| `--json FILE` | 导出 JSON 报告 |
| `--batch FILE` | 批量模式 |

---

## 扩展数据库

在对应 JSON 文件里加一条，重启生效：

```jsonc
// threat_intel/mixers.json
"0x合约地址": "协议名称"

// threat_intel/bridges.json
"0x合约地址": {
  "name": "协议名称",
  "traceable": true,        // 协议是否透明
  "method": "layerzero_api", // 追踪方法（null = 待实现）
  "dst_chains": ["arbitrum"]
}
```

新增支持链，在 `aml_analyzer.py` 的 `EVM_CHAIN_REGISTRY` 加一条 `ChainConfig`，其余逻辑自动适配。

---

## 已知局限

| 问题 | 说明 |
|------|------|
| 黑名单覆盖有限 | 仅含 Tether 冻结地址，不含 OFAC SDN、Lazarus Group 等 |
| 混币器仅 ETH 链 | BSC 链混币器（Cyclone Protocol 等）待补充 |
| 大部分桥追踪待实现 | Hop / Celer / Across 等 API 待接入 |
| 仅追踪 USDT | USDC、WBTC 等未纳入污染计算 |
| 普通对手方抽样 | 每条链最多取 5 个普通对手方做二次查询，高频交易地址可能遗漏 |

---

## 参考文献

- Möser et al. (2014) *Towards Risk Scoring of Bitcoin Transactions*
- Liao et al. (2025) *Transaction Proximity* — Circle Research
- Mazorra et al. (2023) *Tracing Cross-chain Transactions between EVM-based Blockchains*
- Sun et al. (2025) *Track and Trace: Automatically Uncovering Cross-chain Transactions*
- FATF (2021) *Updated Guidance for a Risk-Based Approach to Virtual Assets*

---

> 本工具仅供学术研究与合规分析用途。黑名单数据来源于 Tether 官方公开冻结记录。
