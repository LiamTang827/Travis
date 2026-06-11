# 资金溯源系统 — 追踪逻辑文档

> 文件对应代码：`src/cripto_analyst/aml_analyzer.py` + `src/cripto_analyst/trace_graph.py`
> 最后更新：2026-03-17

---

## 目录

1. [系统概述](#1-系统概述)
2. [数据来源](#2-数据来源)
3. [地址分类体系](#3-地址分类体系)
4. [单地址分析流程](#4-单地址分析流程)
5. [树状追踪算法](#5-树状追踪算法)
6. [子节点生成规则](#6-子节点生成规则)
7. [自适应深度机制](#7-自适应深度机制)
8. [时间窗口过滤](#8-时间窗口过滤)
9. [风险传播与评分](#9-风险传播与评分)
10. [二次标记：中转地址识别](#10-二次标记中转地址识别)
11. [跨链追踪](#11-跨链追踪)
12. [剪枝规则](#12-剪枝规则)
13. [输出格式](#13-输出格式)
14. [CLI 参数速查](#14-cli-参数速查)
15. [已知局限与改进方向](#15-已知局限与改进方向)

---

## 1. 系统概述

本系统的目标是：**给定一个区块链地址，判断它是否与已知犯罪地址存在资金关联，并量化这种关联的风险程度。**

核心思路是把地址之间的资金流动关系构建成一棵树：

```
目标地址（根节点）
├── 对手方 A（第1跳）
│   ├── 对手方 A1（第2跳）
│   └── Tornado Cash（终止：混币器）
├── Stargate Bridge ──→ 目标链地址 B（跨链，继续追踪）
│   └── 黑名单地址 C（终止：确认风险）
└── 对手方 D（第1跳）
    └── ...
```

树的每个节点代表一个地址，边代表资金往来关系。系统对每个节点逐一分析，根据分析结果决定是否继续展开该节点。

---

## 2. 数据来源

### 2.1 黑名单

- **来源**：`data/blacklists/usdt_blacklist.csv`（Tether 官方冻结地址列表）
- **格式**：`address, time, chain`
- **规模**：约 8,500+ 条，覆盖 Ethereum 和 Tron
- **局限**：仅包含 Tether 冻结地址，不包含 OFAC 制裁名单（如 Lazarus Group 的 Harmony 攻击地址）

### 2.2 交易记录

每分析一个地址，系统会依次调用以下接口：

| 接口 | 内容 | 备注 |
|------|------|------|
| Etherscan `txlist` | 普通 ETH 交易 | 最多 100 笔 |
| Etherscan `tokentx` | ERC-20 Token 转账 | 最多 100 笔 |
| Etherscan `getLogs` | USDT Transfer 事件日志 | 仅当前两项为空时补充查询 |
| Etherscan `balance` | 账户余额及基础信息 | |
| Blockscout API | Etherscan 无数据时的备选 | 自动 fallback |
| TronScan API | Tron 链交易查询 | 地址为 Tron 时使用 |

请求间隔固定为 `0.25` 秒，防止触发 API 限速。

### 2.3 跨链追踪（透明桥）

当地址使用了透明跨链桥时，调用 `BridgeTracer.resolve()` 获取对端地址：

| 桥类型 | 追踪方法 |
|--------|----------|
| LayerZero (Stargate/OFT) | `api.layerzeroscan.com/tx/{txHash}` |
| Rollup 官方桥 (Arbitrum/Optimism/Polygon) | 目标地址 = 源地址（同一用户） |
| Hop/Celer/Across/Wormhole | 各协议官方 API（已注册，部分待实现） |

---

## 3. 地址分类体系

每个被分析的地址最终会被归入以下 7 类之一：

### 终止节点（不继续展开，追踪到此为止）

| 类型 | 标志 | 含义 | 风险权重 |
|------|------|------|----------|
| `blacklisted` | 🔴 | 直接命中 USDT 黑名单，Tether 已冻结该地址 | 100 |
| `suspect` | ⚠ | 使用过混币器或不透明跨链桥，资金流向不可追踪，追踪在此中断 | 35 |
| `mixer` | 🔴 | 混币器合约本身（Tornado Cash 等），作为子节点展示 | 80 |
| `opaque_bridge` | 🟠 | 不透明跨链桥合约本身（Multichain 等），作为子节点展示 | 60 |

> **为什么 `suspect` 是终止节点？**
> 使用混币器或不透明桥意味着资金进入了一个"黑盒"：你知道钱进去了，但不知道从哪里出来、出来多少、出来时用的是什么地址。继续追踪毫无意义，只会在混币器后面追到完全无关的其他用户。

### 继续展开节点

| 类型 | 标志 | 含义 | 风险权重 |
|------|------|------|----------|
| `bridge_dst` | 🔵 | 透明跨链桥的对端地址（已切换到目标链，继续追踪） | 20 |
| `clean` | ○ | 普通对手方，目前无已知风险，需进一步分析 | 0 |
| `high_risk` | 🟡 | 综合评分高风险（1跳内多个黑名单关联，或评分 ≥60） | 50 |

> `high_risk` 节点会继续展开，因为其本身不是终止性的，需要追踪确认。

---

## 4. 单地址分析流程

每个节点进入 BFS 队列后，执行 `_analyze_node()`，流程如下：

```
┌─────────────────────────────────────────────┐
│ 1. 查询黑名单                                │
│    地址是否在 data/blacklists/usdt_blacklist.csv 中？         │
│    是 → is_blacklisted = True               │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│ 2. 拉取交易记录                              │
│    txlist + tokentx（最多各 100 笔）          │
│    如果都为空 → 补充查 USDT getLogs           │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│ 3. 时间窗口过滤（如启用）                    │
│    丢弃 N 天以前的交易                       │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│ 4. 提取对手方列表                            │
│    遍历全部交易，取出所有不是自己的地址       │
│    计算每个对手方的交互次数（用于排序）        │
└──────────────────┬──────────────────────────┘
                   │
       ┌───────────┼──────────────────────┐
       ▼           ▼                      ▼
┌──────────┐ ┌──────────────┐     ┌──────────────┐
│ 黑名单检测│ │ 桥/混币器识别│     │ 风险评分计算  │
│ 对手方里  │ │ 对手方里有   │     │ 综合多因素   │
│ 有黑名单? │ │ 桥/混币器?  │     │ 得出 0-100分 │
└──────────┘ └──────────────┘     └──────────────┘
       │           │                      │
       └───────────▼──────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│ 5. 节点分类                                  │
│    按优先级选择节点类型（见第3节）            │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│ 6. 透明桥跨链追踪（如启用）                  │
│    有 OUT 方向的透明桥交易?                  │
│    是 → 调用 BridgeTracer 获取对端地址       │
└─────────────────────────────────────────────┘
```

### 节点分类优先级

```python
if is_blacklisted:
    → blacklisted（最高优先级）
elif mixer_interactions OR opaque_bridge_interactions:
    → suspect（资金流向断裂）
elif hop1_blacklisted >= 3 OR risk_score >= 60:
    → high_risk
elif via_bridge (经由透明桥到达此节点):
    → bridge_dst
else:
    → clean
```

### 风险评分构成（0-100 分）

| 风险因素 | 加分 |
|----------|------|
| 直接命中黑名单 | +60 |
| 每个 1跳黑名单关联 | +20 |
| 混币器交互（每次） | +25 |
| 不透明跨链桥使用 | +25 |
| 跨链后目标地址是黑名单 | +35 |
| 跨链后目标地址的1跳黑名单 | +15 |
| 高风险交易所使用 | +10 |

---

## 5. 树状追踪算法

系统使用 **广度优先搜索（BFS）** 构建地址关联树。

### 整体流程

```
初始化：
  root = TraceNode(target_address)
  queue = [root]
  visited = {}

BFS 主循环：
  while queue 不为空:
    node = queue.popleft()

    if node 已访问过 → 跳过（防循环）
    if 已分析节点数 >= max_nodes → 停止

    visited.add(node)
    分析此节点（_analyze_node）

    if 节点是终止类型 → 不展开，继续下一个
    if node.depth >= node.local_max_depth → 到达深度上限，不展开

    children = 生成子节点（_get_children）
    取前 max_children 个加入队列

BFS 结束后：
  _propagate_risk(root)       ← 向上传播风险评分
  _reclassify_suspects(root)  ← 标记中转地址
```

### 为什么用 BFS 而不是 DFS？

BFS 按层展开，优先分析浅层节点。这意味着：
- 如果节点上限（`max_nodes`）触发，砍掉的是最深层的节点，不会砍掉重要的浅层发现
- 报告中深度数据更均匀，不会出现某一条链特别深而其他分支完全未分析的情况

---

## 6. 子节点生成规则

当一个节点被判定为"可继续展开"时，`_get_children()` 按以下优先级生成候选子节点：

### 优先级顺序

```
优先级 1（最高）：透明桥跨链追踪结果
  ← BridgeTracer 已解析好对端地址，直接作为 bridge_dst 子节点加入

优先级 2：1跳黑名单地址
  ← 这些地址已确认是黑名单，直接标记为 blacklisted 加入（不再分析，节省 API 调用）

优先级 3：不透明桥/混币器合约地址
  ← 这些合约作为终止节点展示（说明资金流向了哪个黑盒）

优先级 4（最低）：普通对手方
  ← 按交互频率降序排列，取频率最高的 N 个
  ← 排除：USDT/USDC 合约、桥合约、混币器合约、黑名单地址
```

> **为什么按交互频率排序？**
> 频率高说明资金往来密切，更可能是真实的业务关系。频率低（如只有1笔）的地址可能是偶然出现，更容易产生噪音。

### 去重机制

- 高优先级已加入的地址不会再被低优先级重复添加
- 全局 `visited` 集合防止同一地址在不同路径下被重复分析

---

## 7. 自适应深度机制

**问题**：固定深度有两种失败模式：
- 太浅（如深度=2）：犯罪分子多跑几跳就能规避
- 太深（如深度=5）：分析大量无关地址，误伤正常用户，且 API 调用成本极高

**解决方案**：普通分支用标准深度，可疑分支额外多追 `depth_bonus` 跳。

### 触发条件

当一个节点满足以下任一条件时，其子节点获得额外深度预算：

```
is_suspicious = (
    hop1_blacklisted 不为空        ← 直接接触过黑名单地址
    OR mixer_interactions 不为空   ← 使用过混币器
    OR opaque_bridge_interactions 不为空  ← 使用过不透明桥
)
```

### 深度计算

```
普通节点的子节点:  child.local_max_depth = parent.local_max_depth
可疑节点的子节点:  child.local_max_depth = min(
                     parent.local_max_depth + depth_bonus,
                     max_depth + depth_bonus   ← 绝对上限，防止无限延伸
                   )
```

### 示例（max_depth=3, depth_bonus=1）

```
目标地址（深度0）→ 普通 → 上限=3
  └── 对手方A（深度1，无异常）→ 上限=3
        └── 对手方A1（深度2，无异常）→ 上限=3
              └── 对手方A11（深度3）→ 到达上限，不展开

目标地址（深度0）→ 普通 → 上限=3
  └── 对手方B（深度1，发现混币器交互）→ is_suspicious=True
        └── 子节点B1（深度2）→ 上限=4（获得+1）
              └── 子节点B11（深度3）→ 上限=4，继续
                    └── 子节点B111（深度4）→ 到达上限(3+1)，不展开
```

---

## 8. 时间窗口过滤

**问题**：区块链上的地址可能有数年历史，早期的交易可能和当前持有人完全无关（地址被转卖、私钥泄露、合约重用等）。把2018年的交易关联到2024年的调查对象会产生大量误报。

**解决方案**：通过 `--time-window DAYS` 参数只分析最近 N 天的交易。

```
交易过滤规则：
  每笔交易的 timeStamp（Etherscan 返回的 Unix 时间戳）
  如果 timeStamp < (当前时间 - time_window_days × 86400) → 丢弃

对象：普通交易（txlist）、Token 转账（tokentx）、USDT 事件日志（getLogs）
```

### 推荐设置

| 场景 | 建议值 | 说明 |
|------|--------|------|
| 快速筛查 | `--time-window 365` | 只看近1年，速度快，适合初步判断 |
| 标准调查 | `--time-window 730` | 近2年，兼顾覆盖率和精度 |
| 深度调查 | `--time-window 1095` | 近3年，用于大案件 |
| 不限制 | `--time-window 0` | 默认值，看全部历史记录 |

---

## 9. 风险传播与评分

### 9.1 节点自身风险（risk_score）

由 `_calculate_risk()` 在单地址分析阶段计算，满分 100，反映该地址**直接**的可疑程度（见第4节风险评分构成）。

### 9.2 子树传播风险（subtree_max_risk）

BFS 完成后，通过**后序遍历**把子节点风险向上传播，使父节点能反映整个子树的最高风险。

```
叶节点:
  subtree_max_risk = risk_score
  subtree_blacklist_count = (1 if blacklisted else 0)

非叶节点（后序）:
  for each child:
    decayed = child.subtree_max_risk × 0.6   ← 每跳衰减40%
    child_max = max(child_max, decayed)
    bl_count += child.subtree_blacklist_count

  contamination_score = child_max             ← 纯来自子树，不含自身
  subtree_max_risk = max(risk_score, child_max)
  subtree_blacklist_count = (self_bl) + bl_count
```

### 9.3 深度衰减标准

| 来自深度 | 衰减系数 | 传播到根时的有效风险（原始100分） | 评级参考 |
|----------|----------|----------------------------------|----------|
| 深度 1   | × 1.0    | 60 分                            | CRITICAL / HIGH |
| 深度 2   | × 0.6    | 36 分                            | HIGH / MEDIUM |
| 深度 3   | × 0.36   | 21.6 分                          | MEDIUM |
| 深度 4   | × 0.216  | 13 分                            | LOW |
| 深度 5+  | × ≤ 0.13 | < 8 分                           | 参考意义为主 |

> **设计意图**：不是说深度4的关联完全无意义，而是说它的**确定性**大幅下降。犯罪分子故意多加几跳就是为了稀释这种关联性，衰减系数在数学上对应这种稀释效果。

---

## 10. 二次标记：中转地址识别

**背景**：洗钱中常用"中转账户"（Money Mule）——这种账户本身不在黑名单，看起来"干净"，但它的功能是在黑名单地址和干净地址之间搭桥，隔断直接关联。

**检测方法**：BFS 展开完成、风险传播完成后，`_reclassify_suspects()` 对全树做一次扫描：

```python
for each node in tree:
    if node.node_type in (clean, bridge_dst):
        if node.subtree_blacklist_count > 0:
            node.node_type = suspect  ← 升级为疑似中转
```

**结果**：这种 `suspect` 节点和"使用混币器的 suspect"的区别是：
- 它**有子节点**（因为在 BFS 阶段被当作 clean 展开了）
- 子树里有 `blacklisted` 节点（这就是污染来源）
- `contamination_score` 显示来自子树的风险量

**报告中展示**：
```
⚠ 疑似中转地址（1 个）
  地址: 0x5d84a...  深度=0  子树黑名单=1  污染评分=60
  路径: 0x5d84a... → 0x098b7...（Ronin 攻击者）
```

---

## 11. 跨链追踪

### 11.1 问题

犯罪资金常用的路径：
```
以太坊地址 A → [Stargate Bridge] → Arbitrum 地址 B → 黑名单地址 C
```
如果不跨链追踪，系统只能看到"A 用了 Stargate"，不知道 B 是什么，也看不到 B 连接到了 C。

### 11.2 透明桥追踪流程

```
1. 发现地址有 OUT 方向的透明桥交易（bridge_interactions）
2. 取该笔交易的 tx_hash
3. 调用 BridgeTracer.resolve(tx_hash, method)
   ├── LayerZero 方法: GET api.layerzeroscan.com/tx/{txHash}
   │   解析 dstTxHash → 在目标链上找代币接收方
   └── Rollup 方法: src_address == dst_address（同一用户）
4. 获得目标链和目标地址
5. 创建 bridge_dst 类型子节点，切换到目标链继续分析
```

### 11.3 不透明桥的处理

对于 Multichain、Orbiter Finance、Synapse 等桥，无法从链上数据确定接收方：
- 用户地址标记为 `suspect`（终止）
- 混币器合约作为子节点展示，注明"追踪断开"
- 报告中单独列出"不透明桥节点"一栏

### 11.4 已支持的桥

| 桥名称 | 类型 | 追踪方法 |
|--------|------|----------|
| Stargate Finance | 透明 | LayerZero Scan API |
| Hop Protocol | 透明 | Hop API (transferId) |
| Celer cBridge v1/v2 | 透明 | cBridge API |
| Across Protocol v2/v3 | 透明 | Across API |
| Wormhole | 透明 | Wormhole API |
| deBridge | 透明 | deBridge API |
| LayerZero Endpoint v1/v2 | 透明 | LayerZero Scan API |
| Polygon PoS Bridge | 透明 | 事件日志（Rollup） |
| Arbitrum Bridge/Inbox | 透明 | 事件日志（Rollup） |
| Optimism Gateway/Messenger | 透明 | 事件日志（Rollup） |
| Connext | 透明 | Connext API |
| SquidRouter (Axelar) | 透明 | Axelarscan API |
| Symbiosis | 透明 | Symbiosis API |
| Multichain/Anyswap | **不透明** | ❌ 无法追踪 |
| Orbiter Finance | **不透明** | ❌ Maker 模式，无法关联 |
| Synapse | **不透明** | ❌ 流动性池模式 |
| Owlto Finance | **不透明** | ❌ Maker 模式 |

---

## 12. 剪枝规则

防止地址树无限爆炸的四重限制：

| 规则 | 参数 | 默认值 | 说明 |
|------|------|--------|------|
| 最大深度 | `--depth` | 3 | 从根节点往下最多追 N 跳 |
| 可疑分支加成 | `--depth-bonus` | 1 | 发现风险时该分支额外追 N 跳 |
| 每节点子节点上限 | `--children` | 5 | 每个地址最多展开 N 个子节点 |
| 全局节点上限 | `--nodes` | 50 | 整棵树最多分析 N 个节点 |
| 访问去重 | 内部 visited 集合 | — | 防止同一地址被循环分析 |

**四个规则的交互关系**：
- `max_nodes` 是硬限制，触发后立即停止，优先级最高
- `local_max_depth` 是软限制，可疑分支会突破 `max_depth` 但不超过 `max_depth + depth_bonus`
- `max_children` 是每节点的子节点数量上限，多余的候选子节点被丢弃（按优先级排列，重要的先保留）

---

## 13. 输出格式

### 13.1 终端树状图

```
└─ ⚠ ethereum:0x5d84a732b355ada31a...  [suspect]  风险:60 子树黑名单:1 污染:60
   ├─ 🔴 ethereum:0x098b716b8aaf2151...  [blacklisted]  风险:100 子树黑名单:1
   └─ ○ ethereum:0x036587e77eabe6a7...  [clean]  风险:20
```

颜色含义：
- 紫色/深红：CRITICAL（风险 ≥80）
- 红色：HIGH（风险 ≥60）
- 黄色：MEDIUM（风险 ≥30）
- 绿色：LOW（风险 <30）

### 13.2 汇总报告

BFS 结束后打印各类节点汇总，包含：
- 黑名单命中节点（地址 + 深度 + 路径）
- 混币器节点
- 不透明桥节点
- 跨链追踪节点
- 综合高风险节点
- 疑似中转地址（含污染评分）
- 深度-风险评估标准说明

### 13.3 JSON 导出（`--json FILE`）

完整树结构的 JSON，包含每个节点的全部分析字段，可用于进一步程序化处理。

### 13.4 Mermaid 图导出（`--mermaid FILE`）

输出 `.md` 文件，包含 `flowchart TD` 格式的 Mermaid 图，可在 GitHub / Obsidian / mermaid.live 直接渲染。

节点形状对应：
- 六边形 `{{}}` → 黑名单 / 混币器（终止高风险）
- 旗帜 `>]` → 疑似中转地址
- 圆角 `([])` → 透明桥目标
- 平行四边形 `[//]` → 不透明桥
- 矩形 `[]` → 普通 / 高风险

---

## 14. CLI 参数速查

```bash
python3 src/cripto_analyst/trace_graph.py <地址> [参数]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--chain` | `ethereum` | 链类型：`ethereum` 或 `tron` |
| `--depth` | `3` | 最大追踪深度 |
| `--children` | `5` | 每节点最大子节点数 |
| `--nodes` | `50` | 全局节点上限 |
| `--depth-bonus` | `1` | 可疑分支额外深度 |
| `--time-window` | `0` | 只分析最近 N 天的交易（0=不限） |
| `--blacklist` | `data/blacklists/usdt_blacklist.csv` | 黑名单 CSV 路径 |
| `--json FILE` | — | 导出 JSON 结构 |
| `--mermaid FILE` | — | 导出 Mermaid 图（.md） |
| `--no-trace` | — | 禁用跨链追踪（加快速度） |
| `--no-hop2` | — | 禁用2跳分析（加快速度） |
| `--no-color` | — | 禁用彩色输出 |

### 常用命令示例

```bash
# 快速筛查（关闭耗时功能，约30秒）
python3 src/cripto_analyst/trace_graph.py 0xABCD... --depth 2 --children 3 --nodes 10 --no-trace --no-hop2

# 标准调查（近2年交易，约2-5分钟）
python3 src/cripto_analyst/trace_graph.py 0xABCD... --depth 3 --children 5 --nodes 30 --time-window 730

# 深度调查 + 导出 Mermaid 图
python3 src/cripto_analyst/trace_graph.py 0xABCD... --depth 4 --children 5 --nodes 60 \
  --time-window 730 --depth-bonus 2 --mermaid report.md --json report.json
```

---

## 15. 已知局限与改进方向

### 15.1 黑名单覆盖不足

当前黑名单仅为 Tether 冻结地址（~8,500条）。Harmony/Euler 等黑客地址因未被 Tether 冻结而无法检测。

**改进**：叠加以下数据源：
- OFAC SDN 制裁名单（官方 CSV）
- HAPI Protocol 开源黑名单（覆盖 Lazarus Group 等）
- Chainalysis KYT / TRM Labs（商业 API）

### 15.2 交易数量限制

每次查询最多返回 100 笔交易（Etherscan 限制）。对于高频交易地址，可能遗漏重要的早期交易。

**改进**：分页查询 + 按时间段分批拉取。

### 15.3 Tron 链覆盖

目前 Tron 链的跨链追踪和混币器识别尚不完整，Tron 链的主要风险路径（USDT TRC-20 转账）已覆盖，但细粒度分析较弱。

### 15.4 仅追踪 USDT/ETH

系统主要基于 USDT 转账记录和 ETH 普通交易。其他 ERC-20 Token（USDC、DAI、WBTC 等）的大额转账可能未被纳入对手方分析。

### 15.5 API 速率限制

免费 Etherscan API Key 每秒限 5 次请求。分析深度较大的树时，等待时间较长（每个节点约需 4 次请求，默认间隔 0.25s）。

**改进**：申请 Etherscan 付费 API Key（每秒 10-30 次），或使用 Infura/Alchemy 直接读取节点。
