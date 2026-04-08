# 基于跨链追踪的加密货币反洗钱风险识别系统
## 第一次中期报告（1st Interim Report）

---

## 一、Introduction（引言）

### 1.1 加密货币洗钱问题的规模与演变

区块链的去中心化、假名性（pseudonymity）和全球可达性使其在带来金融创新的同时，也成为非法资金流动的重要渠道。Chainalysis 发布的 *2024 Crypto Money Laundering Report* 显示，2023 年非法加密货币地址共接收约 **409 亿美元**资金，而这一数字在 2025 年已增长至超过 **1,540 亿美元**，年增幅高达 162%。尤为值得关注的是，稳定币（Stablecoin）在非法交易中的占比已从早期的少数上升至 **63%**（2025 年更达 84%），犯罪分子正加速从比特币转向以 USDT 为代表的稳定币——原因正是其流动性强、跨链转移便捷，而监管盲区相对更大。

从犯罪类型来看，洗钱手段已呈现出系统性的"专业化"趋势。以 Huione Group 为例，该平台自 2021 年至今经手的加密货币交易额超过 **700 亿美元**，逐渐演化为一个服务于诈骗、洗钱全流程的地下金融基础设施。这一趋势表明，加密货币犯罪不再是分散的个人行为，而是具备组织结构和技术门槛的有组织犯罪。

### 1.2 跨链桥的崛起与监管盲区

近年来，跨链桥（Cross-chain Bridge）的规模急剧扩张。以 Stargate Finance 为例，其月均跨链交易量超过 **23 亿美元**，整个 DeFi 生态中每月跨链资产规模逾 **80 亿美元**。跨链桥的核心功能是允许用户在不同区块链之间转移资产，其本身是合法且重要的基础设施——但这一特性同样被犯罪分子系统性地利用于切断资金追踪链条。

Elliptic 于 2023 年的报告指出，**70 亿美元**的非法资产已通过跨链服务完成洗钱，且这一数字自 2022 年起持续快速增长。在可识别的洗钱方案中，**58% 使用了跨链桥**作为关键一环（2024 年数据）。Chainalysis 也在其 2024 年报告中指出，来自被盗资金关联地址的跨链桥使用量在 2023 年出现了大幅跃升。

以北韩黑客组织 Lazarus Group 的操作为例：
- **Ronin Bridge 攻击（2022 年 3 月）**：盗取约 6.25 亿美元，随后通过 Tornado Cash 混币、Avalanche 跨链桥切链到比特币网络，再经 Sinbad 混币器二次清洗，整个洗钱流程横跨超过 12,000 个地址、涉及多条链。
- **Harmony Horizon Bridge 攻击（2022 年 6 月）**：盗取约 1 亿美元，**98% 的被盗资产经由 Tornado Cash 混币**，之后在 Ethereum、BNB Chain、BitTorrent Chain 之间反复跳转，直至 2023 年部分资金再次出现在 Avalanche 和 TRON 链上。

这类攻击展示了当代洗钱的典型模式：**混币 + 跨链 + 多跳中转**，其目的正是通过增加追踪难度来消耗执法和合规资源。执法机构最终从 Ronin 攻击中追回了约 **3,000 万美元**——仅占被盗总额的约 4.8%——揭示了当前追踪能力的上限。

### 1.3 现有工具的局限性

国际刑警组织与相关执法机构的调查显示，**74% 的机构报告称现有区块链调查工具在跨链活动追踪方面存在明显局限**。主流工具（如 Chainalysis Reactor、TRM Labs）虽已具备一定的跨链能力，但其核心算法并未被学术界公开验证，且主要面向商业客户。

从学术研究现状来看，现有文献的主要局限集中在以下几点：

1. **单链为主**：绝大多数 AML 研究以 Bitcoin 或 Ethereum 为单一研究对象，缺乏跨链场景下的分析框架。当资金从 Ethereum 通过桥转移到 Arbitrum 或 Tron 时，现有学术工具就会失去追踪能力。
2. **黑名单覆盖不足**：现有研究多依赖 OFAC 制裁名单，忽视了稳定币发行方（如 Tether）自行维护的实际冻结名单——后者包含 8,500+ 个冻结地址、资产超过 42 亿美元，比 OFAC 更贴近真实洗钱检测的第一现场。
3. **可追溯性未分类讨论**：现有研究鲜少区分"透明桥"与"不透明桥"，而这一分类对于判断是否能继续追踪资金流向至关重要。
4. **图分析缺乏深度控制机制**：现有图分析方法通常设定固定深度，未考虑不同分支的可疑程度差异，导致要么追踪太浅（可规避）、要么开销太大（误伤正常用户）。

### 1.4 普通用户的合规困境：被动污染问题

现有的 AML 工具（Chainalysis、TRM Labs、Elliptic）均以机构用户为主要服务对象。然而，链上的**普通用户**面临的合规风险往往是被动的，且完全缺乏应对工具。

**典型场景如下：**

```
场景一：收款污染
黑名单地址 A ──转账──→ 普通用户 B ──转账──→ 中心化交易所

结果：交易所的 AML 系统检测到 B 的入金来自高风险地址 A，
     B 的账户被冻结或标记为高风险，尽管 B 对此毫不知情。
```

```
场景二：跨链污染扩散
黑名单地址 A → 混币器 → 跨链桥 → 中转地址 C → 普通用户 B

结果：B 在接收来自 C 的转账时，并不知道资金链条的上游存在黑名单地址。
     交易所的 2-hop 或 3-hop 扫描可能同样触发风险警报。
```

这一现象在业界被称为 **"被动污染"（Passive Taint）** 或 **"无辜第三方误伤"**。其核心矛盾在于：

- 区块链是公开透明的，任何人理论上都能查验对方地址的历史——但**分析能力被商业公司垄断**，个人用户无法在发起交易前进行等价的风险自查。
- 交易所的合规政策**不透明且各不相同**：部分交易所追溯 2 跳，部分追溯 5 跳，用户完全不知道自己的入金会被追溯多深。
- 洗钱方有意识地将资金**分散至大量普通地址**（即 Money Mule），令这些地址在无意中成为洗钱链条的一环。

BlockSec 的分析发现，**54% 的黑名单地址在被冻结前已完成资产转移** [12]——这意味着大量已转出的"污染资金"已经在正常用户地址之间流通，而这些用户本人对此毫不知情。

### 1.5 研究目标

综合以上背景，本研究回答以下核心问题：

> **给定一个待查区块链地址，如何系统地识别它与已知黑名单地址之间是否存在资金关联，以及这种关联的风险程度和可信度如何——特别是在资金路径跨越多条区块链、经过混币器或多层中转的场景下？**

具体而言，本研究需解决四个子问题：

- **子问题 1（分类问题）**：如何区分"真正无法追踪的隐匿行为"（混币器、不透明桥）与"可以穿透追踪的跨链行为"（透明桥）？
- **子问题 2（深度问题）**：在多跳追踪中，如何在"追踪深度不足（可规避）"和"追踪开销过大（误伤正常用户）"之间找到合理的平衡点？
- **子问题 3（评分问题）**：如何将多跳、多链的追踪结果量化成可解释的风险评分，使得不同地址之间可以横向比较？
- **子问题 4（比例问题）**：当一个地址同时持有合法资金和污染资金时，如何区分"黑钱"与"白钱"的比例，避免对整个地址一刀切地判定为高风险？

### 1.6 预期成果

预期交付物为一个**原型软件系统**，包含四个组件：

1. **单地址风险分析引擎**：支持 Ethereum 和 Tron 链，集成黑名单检测（8,500+ USDT 冻结地址）、跨链桥注册表（20+ 合约，区分透明/不透明）、混币器识别（10 个 Tornado Cash 合约）
2. **递归溯源图引擎**：基于 BFS 的多跳资金关联树，通过 LayerZero Scan API 实现跨链桥解析，支持自适应深度控制和汇聚路径追踪
3. **机器学习模块**：基于 61 个领域特征和树集成模型的行为钱包分类
4. **可视化输出**：JSON 格式（程序消费）和 Mermaid 图格式（人工审阅）

系统面向**普通链上用户**（非机构），填补目前不存在的开源、自助式地址风险评估工具的空白。

---

## 二、Related Work（相关文献综述）

### 2.1 区块链交易图与 AML 检测

将区块链交易建模为图（Graph）是当前 AML 研究的主流范式。在这一方向上，最具影响力的基础工作来自 Weber 等人（2019 年），他们发布了 **Elliptic Dataset**——一个包含 203,769 个节点和 234,355 条有向边的比特币交易图，其中约 4,500 个节点带有"非法"标注，并在 KDD 2019 的异常检测研讨会上首次提出将图卷积网络（GCN）应用于 AML 分类任务 [1]。该数据集至今仍是学术界最广泛使用的 AML 基准（Benchmark）。2024 年，同一团队发布了第二代数据集 **Elliptic2**，提供社区级标注，支持对整个洗钱子图（而非单笔交易）进行形态分析 [2]。

然而，上述研究有一个共同局限：**均基于单链（主要是 Bitcoin 或 Ethereum），没有讨论资金跨链后如何继续追踪。** 此外，地址聚类（Address Clustering）是商业工具（Chainalysis、Elliptic）的核心能力之一，旨在将同一实体控制的多个地址归并识别，但相关算法细节并未公开，学术界的开源实现也主要依赖启发式方法，在 Ethereum 账户模型下覆盖率有限。本研究不直接实现地址聚类，但在子节点生成阶段采用交互频率作为代理指标，优先追踪高频交互地址，部分补偿了缺乏聚类能力的不足。

### 2.2 跨链交易的追踪与可追溯性

这一方向是本研究最直接的学术背景，也是近年来增长最快的研究领域之一。

#### 2.2.1 透明桥的追踪方法

**Mazorra 等人（2023/2024）** 在论文 *Tracing Cross-chain Transactions between EVM-based Blockchains: An Analysis of Ethereum-Polygon Bridges*（发表于 Ledger 期刊）中，提出了一套针对 EVM 兼容链之间跨链交易的匹配启发式算法 [3]。其核心思想是：**EVM 兼容链之间，用户地址在不同链上保持一致**（例如同一个 `0xABCD...` 地址在 Ethereum 和 Polygon 上是同一密钥控制的），因此可以通过"时间窗口 + 金额 + 代币类型"的组合匹配算法，将源链上的 Lock 事件与目标链上的 Mint/Release 事件关联起来。该研究在覆盖 2020 年 8 月至 2023 年 8 月的超过 200 万笔跨链交易上实现了高达 **99.65%** 的存款匹配率和 **92.78%** 的取款匹配率。

**Sun 等人（2025）** 在论文 *Track and Trace: Automatically Uncovering Cross-chain Transactions in the Multi-blockchain Ecosystems*（arXiv 2504.01822）中，系统分析了 **12 个主流跨链桥**（包括 Stargate、Celer cBridge、Wormhole、Synapse 等），覆盖 2021 年 4 月至 2024 年 3 月的以太坊源链数据，提出了自动化识别跨链交易的通用框架 [4]。该工作的重要发现之一是：不同桥的"透明程度"差异极大——基于消息传递协议（如 LayerZero）的桥可以通过 API 直接获取对端交易哈希，而基于流动性池的桥（如 Synapse）则几乎不可能在链上数据中找到明确的输入-输出对应关系。

**A Survey of Transaction Tracing Techniques for Blockchain Systems**（arXiv 2510.09624）则从更宏观的视角梳理了区块链交易追踪技术的发展脉络，将现有方法分为：链上事件关联、API 辅助追踪、统计推断和机器学习四大类，并指出跨链追踪是当前最欠缺系统性研究的方向 [5]。

#### 2.2.2 透明桥 vs. 不透明桥：可追溯性分类的重要性

本研究认为，区分**透明桥（traceable bridge）**和**不透明桥（opaque bridge）**是进行有效资金追踪的前提，但这一分类在现有学术文献中尚未得到充分讨论。以下对比说明了两者的本质差异（表格综合自 [3], [4], [5]）：

| 维度 | 透明桥 | 不透明桥 |
|------|--------|----------|
| **工作机制** | 消息传递协议（LayerZero、Wormhole）或 Rollup 官方桥 | 流动性池（Synapse）、做市商模式（Orbiter、Owlto） |
| **链上对应关系** | 存在唯一 transferId 或共同 txHash，可关联两端 | 用户资金先进入共享池，再由做市商在目标链独立转出，无法关联 |
| **类比** | 银行电汇（有汇款参考号） | 现金存入 ATM 后由不同人取出（无法关联） |
| **洗钱风险** | 低（资金流向可被追踪和追溯） | 高（等同于混币器，资金流向不可追踪） |
| **典型代表** | Stargate, Hop Protocol, Arbitrum/Optimism 官方桥 | Multichain（已崩溃）、Orbiter Finance、Synapse |

Multichain（曾是最大跨链桥之一）于 2023 年因内部问题崩溃，导致约 **1.27 亿美元**资产丢失——这一事件本身也暴露了不透明桥在透明度和可审计性方面的根本性缺陷。

### 2.3 多跳风险评分与树状追踪

本节梳理与本研究技术方案最直接相关的三项工作。

#### 2.3.1 奠基工作：Bitcoin 交易风险评分（2014）

**Möser, Böhme & Breuker（2014）** 在 *Towards Risk Scoring of Bitcoin Transactions*（Financial Cryptography 2014）中首次将"从已知违规地址出发、沿交易图传播风险"形式化为一个研究问题 [6]。该工作提出了两种传播策略：

- **Poison（全污染）**：只要资金来源中含有任何违规输入，输出视为完全污染
- **Haircut（按比例）**：污染比例等于违规来源资金占总输入的比例，随混合逐步稀释

这是学术界最早讨论"多跳风险"的工作，被后续几乎所有 Taint Analysis 研究引用。其局限在于发表于 2014 年，研究场景仅限于 Bitcoin 单链，未涉及跨链桥或混币器的特殊处理逻辑。

#### 2.3.2 TaintRank：PageRank 风格的污染传播（2019）

**Hercog & Povšea（2019）** 在 *Taint analysis of the Bitcoin network*（arXiv:1907.01538）中提出 **TaintRank** 算法 [7]，将污染传播类比为 PageRank：

- 构造以地址为节点、交易为有向边的有权图
- 每个节点的污染值由其所有上游节点的加权污染值累加而来
- 污染随传播距离增大自然衰减，最终分布呈幂律形态

TaintRank 以**批量、全局**的方式对整个 Bitcoin 网络进行评分，可为每个地址产生 0-1 的污染指数。与本研究不同的是，它是离线批处理算法，不支持以单个地址为根节点的实时树状查询，亦不支持跨链场景。

#### 2.3.3 Transaction Proximity：Circle 对 Ethereum 全图的 BFS 实践（2025）

**Liao, Zeng, Belenkiy & Hirshman（2025）** 来自 USDC 发行方 Circle，在 *Transaction Proximity: A Graph-Based Approach to Blockchain Fraud Prevention*（arXiv:2505.24284）中，将 BFS 思路应用于整个 Ethereum 历史图 [8]：

- 数据规模：**2.06 亿节点，4.42 亿条边**，覆盖 Ethereum 从创世到 2024 年 5 月的全部交易
- BFS 深度上限：**5 跳**（覆盖 98.2% 的 USDC 活跃持有者）
- 核心指标：**Transaction Proximity**（与受监管交易所的最短跳数）和 **EAI（Easily Attainable Identities）**（直接连接到交易所的地址）
- 关键发现：83% 的已知攻击者地址不是 EAI，21% 距离任何受监管交易所超过 5 跳——说明犯罪地址在图结构上确实倾向于远离"正常流通节点"

值得注意的是，该论文的风险视角与本研究**方向相反但互补**：Transaction Proximity 衡量"距离合法锚点的远近"（越近越合法），本研究衡量"距离违规锚点的远近"（越近越危险）。两种方法理论上可以融合使用，为同一地址从两个方向提供置信度。

#### 2.3.4 与本研究的系统对比

以下表格综合比较了本研究与现有方法（表格编译自 [6], [7], [8]）：

| 特性 | Möser 2014 | TaintRank 2019 | Tx Proximity 2025 | Chainalysis（行业） | **本研究** |
|------|:---:|:---:|:---:|:---:|:---:|
| 跨链追踪 | ❌ | ❌ | ❌ | 部分（未公开） | ✅ |
| 透明桥 vs 不透明桥分类 | ❌ | ❌ | ❌ | ❌ | ✅ |
| 自适应深度（可疑分支加深） | ❌ | ❌ | ❌（固定 5 跳） | ❌ | ✅ |
| 实时单地址查询 | ❌（论文） | ❌（批处理） | ❌（离线分析） | ✅（商业） | ✅ |
| 面向普通用户（非机构） | — | — | — | ❌ | ✅ |
| 黑名单锚点：USDT 冻结名单 | ❌ | ❌ | ❌ | 部分 | ✅ |
| 跳数衰减系数（显式） | ✅ | 隐式 | ❌ | 未公开 | ✅（×0.6） |
| 混币器终止逻辑 | ❌ | ❌ | ❌ | ✅ | ✅ |
| 开源可复现 | — | 部分 | 部分 | ❌ | ✅ |

### 2.4 稳定币 AML 的机器学习方法

**Juvinski & Li（2026）** 在 **StableAML** 论文 [24] 中进行了迄今最全面的稳定币 AML 机器学习研究。他们在 16,433 个标注地址上用 68 个行为特征训练树集成模型，CatBoost 达到 Macro-F1 = 0.9775，显著优于图神经网络（GraphSAGE, F1=0.8048）。其最重要的发现是：**领域特定的特征工程比复杂的图算法更重要** — 原因是稳定币交易图极度稀疏（density < 0.01），GNN 的 message passing 无法有效传播信息。而树集成模型可以直接利用编码了洗钱模式领域知识的手工特征，不依赖图连接性。

这一发现对本研究有直接指导意义：与其投入计算昂贵的 GNN 架构，不如采用**特征工程 + 树集成模型**的路线。

### 2.5 监管框架与现实需求

**FATF（金融行动特别工作组）** 于 2019 年将虚拟资产（VA）和虚拟资产服务提供商（VASP）纳入其反洗钱和反恐融资标准框架（Recommendation 15），并在 2023 年的定向更新报告中指出：在 151 个成员国中，**超过一半尚未实施"旅行规则"（Travel Rule）**，75% 的成员国对 R.15 处于部分合规或不合规状态 [9]。FATF 2023 报告同时特别强调了稳定币被 DPRK 行为者、恐怖主义融资和毒品贩运者使用的显著增长趋势。

**欧盟《人工智能法案》（EU AI Act, Regulation 2024/1689）** 于 2024 年正式生效，将用于 AML/CFT 合规的 AI 系统归类为 **"高风险 AI 系统"（Annex III）** [18]。该法案要求此类系统满足三个条件：（1）决策逻辑的充分透明性，（2）人类监督机制，（3）可向监管机构和终端用户提供完整的决策解释。违规者最高面临 **3,500 万欧元或全球营业额 7%** 的罚款。这产生了一个核心矛盾：**检测效果最好的模型（GNN、深度学习）恰恰是最不可解释的；而最可解释的方法（规则引擎）检测能力有限。** 这一矛盾直接推动了本研究采用的混合方法。

### 2.6 可解释性与隐私保护合规

AML 检测系统的可解释性是监管的硬性要求。FATF Recommendation 20 要求 STR 报告包含"为什么认为该交易可疑"的文字说明。美国《银行保密法》同样要求 SAR 以自然语言描述可疑行为模式。EU AI Act 进一步将解释义务扩展到 AI 系统本身 [18]。

Watson, Richards & Schiff（2025）提出了一个代表性的三层架构（架构来自 [14]）：第一层 GNN 检测（GCN-GRU 混合模型，准确率 0.9470，AUC-ROC 0.9807）；第二层 GraphLIME 归因；第三层 LLM 解释。Nicholls 等人（2024）展示了 LLM 可以独立生成"有用的、可操作的解释" [15]。Sun 等人（2024）发表了第一篇 LLM 在区块链安全领域的系统综述 [16]。

在隐私方面，Buterin 等人（2023）提出 **Privacy Pools** [19]，证明了隐私与合规可以共存——用户可通过零知识证明证明资金来源的合法性而不暴露交易细节。Privacy Pools v1 已于 2024 年在 Ethereum 主网上线。Constantinides & Cartlidge（2025）指出 Proof of Innocence 依赖黑名单的完整性和实时性 [20]。Tornado Cash 制裁事件（2022 年 OFAC 制裁、2024 年第五巡回法院推翻、2025 年财政部解除 [21]）进一步说明单纯制裁隐私工具不是长久之计。

本研究的规则引擎（BFS 追踪 + 风险评分）在可解释性方面具有天然优势：每一步决策都有完整的因果链条，不存在"黑盒"问题，使得未来引入 LLM 解释层变得直接可行。

### 2.7 现有方案优缺点总结

**商业工具**（Chainalysis, TRM Labs, Elliptic）：覆盖广但闭源、昂贵、仅面向机构、算法未经学术验证。其"黑盒"性质与 EU AI Act 的透明性要求日益冲突。

**学术方法**（Elliptic/GNN, TaintRank, Transaction Proximity）：可复现、理论基础扎实，但局限于单链、批处理/离线、面向研究而非普通用户。

**本研究**结合了四个先前工作中缺失的要素：(1) 带有桥可追溯性分类的跨链追踪；(2) 数据驱动的自适应深度 BFS；(3) 规则引擎 + ML 混合评分；(4) 开源、面向普通用户的定位。

---

## 三、System Modeling and Structure（系统建模与架构）

### 3.1 架构概述

系统由三个核心模块组成：

1. **单地址分析引擎**（`aml_analyzer.py`）——通过 Etherscan/TronScan API 获取链上数据，对比黑名单、桥注册表和混币器合约，执行 ML 增强的风险评分
2. **递归溯源图引擎**（`trace_graph.py`）——基于 BFS 的多跳资金关联树，支持跨链桥解析、自适应深度和汇聚路径追踪
3. **ML 风险评分器**（`ml/` 流水线）——从 Transfer 事件中提取行为特征，树集成分类，作为混合评分组件集成

### 3.2 设计决策与理由

**决策 1：桥的可追溯性分类作为一等公民。** 与现有研究不同，本系统将每个桥分类为透明或不透明。透明桥通过协议 API 解析对端地址继续追踪；不透明桥视同混币器，标记为高风险"追踪断裂"终止节点。这直接回应了 Sun 等人 [4] 发现的可追溯性差异问题。

**决策 2：自适应深度 BFS。** 普通分支使用标准最大深度（默认 3 跳）；发现可疑指标的分支获得 `depth_bonus` 额外跳数（默认 +1）。这在追踪充分性和计算成本之间提供了数据驱动的平衡。

**决策 3：双向实体检测。** 代码审查发现仅检查 `to` 字段会遗漏从混币器**提取**资金的情况（`from=mixer`）。系统现在对 `from` 和 `to` 双向检查所有实体注册表，并记录方向（IN/OUT）。

**决策 4：汇聚路径追踪。** 原始 BFS 的 `visited` 集合静默丢弃汇聚路径，使分散→汇聚洗钱模式不可见。重设计的系统保留汇聚元数据（`converge_from`、`in_degree`），不展开但记录，捕获多路径汇聚——这是关键的洗钱特征。

**决策 5：规则 + ML 混合评分。** 公式为 `新风险评分 = 规则引擎 × 0.4 + ML predict_proba × 0.6`。规则引擎保留 40% 确保已知高风险信号不被低估；ML 贡献 60% 捕获规则无法覆盖的行为模式。模型文件缺失时自动降级为纯规则引擎。

### 3.3 解决现有局限

| 现有局限 | 本系统的解决方案 |
|---------|---------------|
| 仅支持单链 | 通过桥注册表 + LayerZero Scan API 实现多链追踪 |
| 无桥分类 | 显式的透明/不透明分类驱动追踪逻辑 |
| 固定深度 | 可疑触发的自适应深度加成 |
| 仅面向机构 | 开源，面向普通用户的自助评估 |
| 黑盒模型 | 规则引擎完整因果链；ML 可输出特征重要性 |
| 仅 OFAC 黑名单 | USDT 冻结名单（8,500+ 地址）为主要锚点 |

---

## 四、Methodology and Algorithms（方法论与算法）

### 4.1 风险评分算法

采用**每跳 0.6 倍**的风险衰减系数：

| 关联距离 | 衰减后有效风险（原始 100 分） | 风险等级 |
|----------|-------------------------------|----------|
| 直接接触（1 跳） | 60 分 | HIGH |
| 二跳 | 36 分 | MEDIUM |
| 三跳 | 21.6 分 | LOW |
| 四跳及以上 | ≤ 13 分 | 参考 |

BFS 展开后，二次扫描识别**疑似中转地址**（Money Mule）：若一个看似干净的地址的子树中存在黑名单命中，则标记为 suspect 并计算子树污染评分。

### 4.2 采样偏差修正

代码审查发现五个系统性问题，分为两大类：

**采样扭曲（P1, P2, P5）：**

| 编号 | 问题 | 影响 | 修复方案 |
|:---:|------|------|---------|
| P1 | `MAX_TX_FETCH=100`，仅获取最新 100 笔交易 | 活跃地址的历史脏交易被截断 | 提高至 500，并加截断提示 |
| P2 | `txlist + tokentx` 直接拼接导致重复计数 | 对手方交互频率虚高 | 按 `(hash, from, to)` 三元组去重 |
| P5 | 对手方排名纯按交互频率 | DEX Router 占满名额 | 引入金额加权复合评分，排除已知 DEX 地址 |

**图结构失真（P3, P4）：**

| 编号 | 问题 | 影响 | 修复方案 |
|:---:|------|------|---------|
| P3 | 桥/混币器检测只查 `to` 字段 | 从混币器提取资金完全检测不到 | 双向检测，记录方向 |
| P4 | `visited` 集合静默丢弃汇聚路径 | 分散→汇聚洗钱模式不可见 | 保留汇聚信息 |

核心洞察：**这五个问题的共同效果是，洗钱者的对抗策略恰好命中系统的盲区。**

### 4.3 机器学习流水线

参考 StableAML 的发现 [24]，ML 流水线包含四个阶段：

**阶段 1：数据收集。** Blocklisted（100 个，来自 USDT 黑名单）、Normal（50 个，链上随机采样）、Sanctioned（10 个，来自 OFAC SDN）。对每个地址使用 Etherscan getLogs API 双向获取 USDT/USDC Transfer 事件。

**阶段 2：特征工程。** 参考 StableAML 的四类特征框架（特征框架改编自 [24]），提取 **61 个行为特征**：

| 类别 | 数量 | 代表性特征 | 数据来源 |
|------|:---:|-----------|---------|
| Interaction Features | 18 | `sent_to_mixer`, `received_from_mixer`, `has_flagged_interaction` | 与项目已有地址标签库匹配 |
| Transfer Features | 19 | `transfers_over_10k`, `drain_ratio`, `repeated_amount_ratio` | 纯金额/数量统计 |
| Network Features | 10 | `in_degree`, `out_degree`, `counterparty_flagged_ratio` | from/to 集合计算 |
| Temporal Features | 8 | `has_daily_burst`, `rapid_tx_ratio`, `hour_concentration` | timestamp 排序后计算 |

**阶段 3：模型训练。** 使用 5-Fold Stratified Cross Validation 对比四个树集成模型，通过 balanced class weights 处理类不平衡。

**阶段 4：模型集成。** 最优模型通过 `MLRiskScorer` 类加载，从 `RiskReport` 中提取特征，调用 `predict_proba` 返回 0-100 风险分，与规则引擎混合评分。

---

## 五、Preliminary Performance Analysis（初步实验分析）

### 5.1 模型评估

| 模型 | Macro-F1 | PR-AUC | 准确率 |
|------|:--------:|:------:|:-----:|
| **RandomForest** | **0.919** | **0.949** | **0.927** |
| XGBoost | 0.886 | 0.917 | 0.900 |
| CatBoost | 0.872 | 0.937 | 0.887 |
| LightGBM | 0.865 | 0.932 | 0.880 |

最优模型 RandomForest 的混淆矩阵：

|  | 预测 blocklisted | 预测 normal |
|--|:-:|:-:|
| 实际 blocklisted | 93 | 7 |
| 实际 normal | 4 | 46 |

模型对 blocklisted 检测达到 95.9% 精确率和 93.0% 召回率，仅 4 个误报。考虑到训练集仅 150 个样本（vs StableAML 的 16,433 个），这一结果令人鼓舞。

### 5.2 特征重要性分析

跨模型共识的 Top 5 重要特征：

1. **`drain_ratio`**（余额清空率）— blocklisted 均值 0.21 vs normal 1.37（被冻结地址资金转不走）
2. **`total_sent_amount`**（总转出金额）— 大额资金流动是核心信号
3. **`counterparty_flagged_ratio`**（对手方标记比例）— KYC/标签数据的价值体现
4. **`out_degree`**（出度）— 黑名单地址出度远低于正常地址
5. **`in_out_ratio`**（流入/流出比）— 资金流向对称性

### 5.3 系统模块状态

| 模块 | 状态 | 描述 |
|------|------|------|
| `aml_analyzer.py` | 已实现 | Etherscan + TronScan API，黑名单（8,500+），桥注册表（20+），混币器（10），混合评分 |
| `trace_graph.py` | 已实现 | BFS 树，跨链解析，自适应深度，汇聚追踪，Mermaid 导出 |
| `ml/` 流水线 | 已实现 | 数据收集，61 特征，4 模型训练，最优模型集成 |
| 缺陷修复（P1-P5） | 已实现 | 采样偏差和图结构失真修正 |

### 5.4 已知局限

1. **数据量有限**：150 个样本 vs StableAML 的 16,433 个。扩大数据集是提升泛化能力的最直接手段。
2. **Normal 类未经人工验证**：从链上随机采样的"正常"地址可能包含未被标记的洗钱地址（label noise）。
3. **仅覆盖 USDT/USDC Transfer 事件**：洗钱者 swap 成 ETH 或其他 token 后跳出分析视野。
4. **特征提取的实时性**：部分时序特征需要完整的 Transfer 事件数据才能精确计算。
5. **二分类限制**：当前仅区分 blocklisted/normal，未加入 sanctioned、cybercrime 等细分类别。

---

## 六、Milestones and Overall Schedule（里程碑与时间表）

| 阶段 | 时间 | 里程碑 | 交付物 |
|------|------|--------|--------|
| 阶段 1 | 第 1-3 周（已完成） | 核心系统实现 | `aml_analyzer.py`, `trace_graph.py`, 注册表 |
| 阶段 2 | 第 4-5 周（已完成） | ML 流水线开发 | 数据收集，特征工程，模型训练，系统集成 |
| 阶段 3 | 第 5-6 周（已完成） | 缺陷修复与系统改进 | P1-P5 修复，混合评分，汇聚追踪 |
| 阶段 4 | 第 7-9 周 | 端到端验证与数据扩展 | 已知洗钱案例测试；数据集扩充至 1,000+ 地址 |
| 阶段 5 | 第 10-12 周 | Taint 比例分析 | 实现 FIFO/Haircut/Poison 方法 |
| 阶段 6 | 第 13-15 周 | 额外桥支持与评估 | Hop Protocol, Across Protocol 解析；综合性能基准 |
| 阶段 7 | 第 16-18 周 | 终期报告 | LLM 解释层（探索性）；终期报告撰写 |

---

## 七、Work to Be Completed for the Next Report（下阶段工作）

1. **数据集扩展**：从 150 扩展到 1,000+ 标注地址，对 Normal 类进行人工验证。
2. **端到端验证**：在已知洗钱案例（Ronin Bridge, Harmony Bridge）上运行完整系统，验证追踪树能否还原实际洗钱路径。
3. **OFAC SDN 集成**：补充 Tether 冻结名单未覆盖的制裁地址。
4. **额外桥支持**：实现 Hop Protocol 和 Across Protocol 的对端地址解析。
5. **时间窗口过滤**：引入可配置时间窗口，排除远古交易导致的误报。
6. **Taint 比例分析**：开始实现 FIFO 和 Haircut 方法，将二元风险判断升级为比例置信度评分。
7. **LLM 解释层**（探索性）：原型验证将 JSON 追踪结果输入 LLM 生成满足 SAR/STR 要求的自然语言风险报告，参考 [14] 和 [15] 的验证结果。

---

## 参考文献

### AML 图分析基础

[1] Weber, M., Domeniconi, G., Chen, J., Weidele, D. K. I., Bellei, C., Robinson, T., & Leiserson, C. E. (2019). **Anti-Money Laundering in Bitcoin: Experimenting with Graph Convolutional Networks for Financial Forensics.** *KDD Workshop on Anomaly Detection in Finance.* arXiv:1908.02591.

[2] Bellei, C. et al. (2024). **The Shape of Money Laundering: Subgraph Representation Learning on the Blockchain with the Elliptic2 Dataset.** arXiv:2404.19109.

### 跨链追踪

[3] Mazorra, B. et al. (2023). **Tracing Cross-Chain Transactions Between EVM-Based Blockchains: An Analysis of Ethereum-Polygon Bridges.** *Ledger Journal.* arXiv:2504.15449.

[4] Sun, X. et al. (2025). **Track and Trace: Automatically Uncovering Cross-chain Transactions in the Multi-blockchain Ecosystems.** arXiv:2504.01822.

[5] Ren, J. et al. (2025). **A Survey of Transaction Tracing Techniques for Blockchain Systems.** arXiv:2510.09624.

### 多跳风险评分

[6] Möser, M., Böhme, R., & Breuker, D. (2014). **Towards Risk Scoring of Bitcoin Transactions.** *Financial Cryptography and Data Security Workshops (FC 2014).* Springer. https://maltemoeser.de/paper/risk-scoring.pdf

[7] Hercog, U., & Povšea, A. (2019). **Taint Analysis of the Bitcoin Network.** arXiv:1907.01538.

[8] Liao, G., Zeng, Z., Belenkiy, M., & Hirshman, J. (2025). **Transaction Proximity: A Graph-Based Approach to Blockchain Fraud Prevention.** Circle Research. arXiv:2505.24284.

### 行业报告与数据源

[9] FATF (2023). **Targeted Update on Implementation of the FATF Standards on Virtual Assets and Virtual Asset Service Providers.** Financial Action Task Force. June 2023.

[10] Chainalysis (2024). **2024 Crypto Money Laundering Report.** Chainalysis Inc.

[11] Elliptic (2023). **$7 Billion in Crypto Laundered Through Cross-Chain Services.** Elliptic Enterprise Ltd.

[12] BlockSec (2023). **Following the Frozen: An On-Chain Analysis of USDT Blacklisting and Its Links to Terrorist Financing.** BlockSec Blog.

[13] Weber, M. & Bellei, C. (2019). **Elliptic Data Set.** Kaggle / Elliptic. https://www.kaggle.com/datasets/ellipticco/elliptic-data-set

### LLM 解释层与可解释 AML

[14] Watson, A., Richards, G., & Schiff, D. (2025). **Explain First, Trust Later: LLM-Augmented Explanations for Graph-Based Crypto Anomaly Detection.** arXiv:2506.14933.

[15] Nicholls, J. et al. (2024). **Large Language Model XAI Approach for Illicit Activity Investigation in Bitcoin.** *Neural Computing and Applications.* Springer. https://link.springer.com/article/10.1007/s00521-024-10510-w

[16] Sun, H. et al. (2024). **Large Language Models for Blockchain Security: A Systematic Literature Review.** arXiv:2403.14280.

[17] Kute, D. et al. (2026). **Explainable and Fair Anti-Money Laundering Models Using a Reproducible SHAP Framework for Financial Institutions.** *Discover Artificial Intelligence.* Springer. https://link.springer.com/article/10.1007/s44163-026-00944-7

### 监管框架

[18] European Union (2024). **Regulation (EU) 2024/1689 — AI Act, Annex III: High-Risk AI Systems.** https://artificialintelligenceact.eu/annex/3/

### ZKP 合规证明与隐私保护 AML

[19] Buterin, V., Illum, J., Nadler, M., Schär, F., & Soleimani, A. (2023). **Blockchain Privacy and Regulatory Compliance: Towards a Practical Equilibrium.** *Blockchain: Research and Applications, 5*(1), 100176. https://papers.ssrn.com/sol3/papers.cfm?abstract_id=4563364

[20] Constantinides, T. & Cartlidge, J. (2025). **zkMixer: A Configurable Zero-Knowledge Mixer with Anti-Money Laundering Consensus Protocols.** arXiv:2503.14729. Accepted at IEEE DAPPS 2025.

[21] Brownworth, A., Durfee, J., Lee, M., & Martin, A. (2024). **Regulating Decentralized Systems: Evidence from Sanctions on Tornado Cash.** Federal Reserve Bank of New York Staff Reports, No. 1112. https://www.newyorkfed.org/research/staff_reports/sr1112.html

[22] Chaudhary, A. (2023). **zkFi: Privacy-Preserving and Regulation Compliant Transactions using Zero Knowledge Proofs.** arXiv:2307.00521.

[23] Effendi, F. & Chattopadhyay, A. (2024). **Privacy-Preserving Graph-Based Machine Learning with Fully Homomorphic Encryption for Collaborative Anti-Money Laundering.** *SPACE 2024.* arXiv:2411.02926.

[24] Juvinski, L. & Li, Z. (2026). **StableAML: Machine Learning for Behavioral Wallet Detection in Stablecoin Anti-Money Laundering on Ethereum.** arXiv:2602.17842.
