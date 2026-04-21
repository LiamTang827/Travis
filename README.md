# Travis
### TRAceable Verification Intelligence System

链上 AML 风险分析引擎。以任意地址为起点，沿交易图向外扩展，量化其与黑名单、混币器、不透明桥的关联程度，输出可审计的风险评分与完整资金路径。

---

## 核心设计理念

**传统做法**：命中黑名单 → +50 分，命中混币器 → +30 分，加法累积。  
**问题**：金额不同、距离不同，贡献却一样，评分不可解释，无法跨地址比较。

**Travis 的做法**：比例污染传播（Haircut Model），来自 FATF 合规实践：

```
污染比例 = Σ(风险金额 × 类别权重 × 跳数衰减) / 总流量
```

- 收了 10 USDT 黑钱 + 90 USDT 白钱 → 污染比例 10%，不是"命中即高危"
- 经过中间人的间接关联自动衰减（2-hop × 0.3）
- 每条风险证据都有对应 tx hash，可独立核实

---

## 功能

- **多链覆盖**：Ethereum / BSC / Polygon / Arbitrum / Optimism / Avalanche / Base / Tron
- **1-hop + 2-hop 图遍历**：直接对手方全量扫描，二跳抽样检测间接关联
- **透明桥追踪**：LayerZero / Stargate / Hop / Celer / Across / Rollup 官方桥可追踪对端地址
- **不透明桥识别**：Multichain / Orbiter / Synapse 等无法对应进出，等同混币器处理
- **路径可视化**：每条风险证据展示完整资金路径，支持 1-hop 和 2-hop 两种跳数
- **分页拉取**：自动翻页获取完整历史，遇时间窗口或无数据早停
- **可扩展情报库**：混币器 / 桥 / 交易所地址统一维护在 `threat_intel/` JSON 文件中

---

## 评分模型

| 风险类别 | 权重 | 说明 |
|---------|------|------|
| OFAC 制裁 | 1.0 | 最高级别 |
| 勒索软件 / 黑客 | 0.9 | |
| 暗网 / USDT 黑名单 | 0.8 | Tether 冻结地址 |
| 混币器 | 0.7 | Tornado Cash 等 |
| 不透明桥 | 0.6 | 资金来源不可追溯 |
| 高风险交易所 | 0.4 | KYC 执行不严 |
| 透明桥（有黑名单关联） | 0.3 | |
| 透明桥（无黑名单） | 0.1 | 参考信号 |

| 跳数 | 衰减系数 | 说明 |
|------|---------|------|
| 1-hop | 1.0 | 直接交互，全额计入 |
| 2-hop | 0.3 | 通过中间节点的间接关联 |

| 风险分数 | 等级 | 含义 |
|---------|------|------|
| 100 | CRITICAL | 地址本身在黑名单 |
| 60–99 | HIGH | 高比例直接关联 |
| 30–59 | MEDIUM | 中等污染或间接关联 |
| 0–29 | LOW | 低风险 |

---

## 文件结构

```
Travis/
├── aml_analyzer.py          # 主引擎：多链分析 + 评分 + 报告输出
├── cross_chain_tracer.py    # 桥追踪：解析单笔桥 tx 的目标链和目标地址
├── trace_graph.py           # BFS 树状图追踪
├── threat_intel/            # 威胁情报数据库（JSON，无需改 Python 代码即可扩展）
│   ├── mixers.json          #   混币器合约地址
│   ├── bridges.json         #   跨链桥合约地址（含透明/不透明分类）
│   └── exchanges.json       #   交易所热钱包 + 高风险所 + 充值地址检测参数
├── usdt_blacklist.csv       # USDT 黑名单（Tether 官方冻结地址，~8500 条）
├── .env.example             # API Key 配置模板
└── TRACE_LOGIC.md           # 追踪逻辑详细文档
```

---

## 快速开始

### 1. 安装依赖

```bash
pip install requests python-dotenv
```

### 2. 配置 API Key

```bash
cp .env.example .env
```

编辑 `.env`：

```env
ETHERSCAN_API_KEY=your_key   # etherscan.io/myapikey（免费，5 req/s）
BSCSCAN_API_KEY=your_key     # bscscan.com/myapikey
POLYGONSCAN_API_KEY=your_key
ARBISCAN_API_KEY=your_key
# 其余链不填则走 Blockscout 公开端点（无需 key，速率较低）
```

### 3. 分析地址

```bash
# 单链分析（快，适合日常查询）
python3 aml_analyzer.py 0xYourAddress --chain ethereum

# 多链分析（查指定几条链）
python3 aml_analyzer.py 0xYourAddress --chains ethereum,bsc,polygon

# 启用 2-hop（更深，较慢）
python3 aml_analyzer.py 0xYourAddress --chain ethereum

# 只看最近 90 天
python3 aml_analyzer.py 0xYourAddress --chain ethereum --days 90

# 导出 JSON
python3 aml_analyzer.py 0xYourAddress --chain ethereum --json report.json

# 批量分析
python3 aml_analyzer.py --batch addresses.txt --chain ethereum
```

### 完整参数

| 参数 | 说明 |
|------|------|
| `--chain` | 指定单链（ethereum / bsc / polygon / arbitrum / optimism / avalanche / base / tron） |
| `--chains` | 指定多链，逗号分隔（如 `ethereum,bsc`） |
| `--no-hop2` | 禁用 2-hop 分析（加快速度） |
| `--no-trace` | 禁用透明桥跨链追踪 |
| `--days N` | 只分析最近 N 天的交易 |
| `--json FILE` | 导出 JSON 报告 |
| `--no-color` | 禁用彩色输出 |
| `--batch FILE` | 批量模式，从文件逐行读取地址 |

---

## 输出示例

```
============================================================
  AML 风险分析报告
============================================================
  地址:     0x2aa1ca10bddd558fdfce9572d97f8cb28cd67154
  链:       ethereum
  USDT 流入:    65,778.05  |  流出:   288,929.06

  ──────────────────────────────────────────────────────
  风险等级:   CRITICAL
  风险分数:   100/100  (污染比例 100.00%)
  ──────────────────────────────────────────────────────

  1-Hop 风险证据（直接交互，衰减系数 1.0）
  ──────────────────────────────────────────────────────
    [ethereum] [blacklist]     33,889.02 USDT  污染贡献 41.22%
      路径: 0xee31...03a6 --33,889 USDT--> 0x2aa1...7154
      完整地址: 0xee31de335135f4c1aac55724554b8404967303a6
      证据tx:   0x4d42b30428b8fdc21d... 等3笔

  2-Hop 风险证据（间接关联，衰减系数 0.3）
  ──────────────────────────────────────────────────────
    [ethereum] [blacklist]     63,360.00 USDT  污染贡献 23.12%（×0.3衰减）
      路径: 0xee31...03a6 --> 0x9f8d...1cf9 --> 0x2aa1...7154
      中间节点: 0x9f8d9b44162b97480a7bf61da1ee89d0089c1cf9
      风险终点: 0xee31de335135f4c1aac55724554b8404967303a6
```

---

## 扩展情报库

新增一个混币器地址，打开 `threat_intel/mixers.json`，加一行：

```json
"0x新合约地址": "名称"
```

重启程序生效，无需改动任何 Python 代码。桥和交易所同理，分别对应 `bridges.json` 和 `exchanges.json`。

---

## 新增支持链

在 `aml_analyzer.py` 的 `EVM_CHAIN_REGISTRY` 中加一条记录：

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

其余所有业务逻辑自动适配，无需修改。

---

## 相关文献

- Möser et al. (2014) *Towards Risk Scoring of Bitcoin Transactions*
- Liao et al. (2025) *Transaction Proximity* — Circle Research
- Mazorra et al. (2023) *Tracing Cross-chain Transactions between EVM-based Blockchains*
- Sun et al. (2025) *Track and Trace: Automatically Uncovering Cross-chain Transactions*
- FATF (2021) *Updated Guidance for a Risk-Based Approach to Virtual Assets*

---

> 本工具仅供学术研究与合规分析用途。黑名单数据来源于 Tether 官方公开冻结记录。
