# 基于跨链追踪的加密货币反洗钱风险识别系统
## 中期报告

---

## 一、研究背景

### 1.1 加密货币洗钱问题的规模与演变

区块链的去中心化、假名性（pseudonymity）和全球可达性使其在带来金融创新的同时，也成为非法资金流动的重要渠道。Chainalysis 发布的 *2024 Crypto Money Laundering Report* 显示，2023 年非法加密货币地址共接收约 **409 亿美元**资金，而这一数字在 2025 年已增长至超过 **1,540 亿美元**，年增幅高达 162%。尤为值得关注的是，稳定币（Stablecoin）在非法交易中的占比已从早期的少数上升至 **63%**（2025 年更达 84%），犯罪分子正加速从比特币转向以 USDT 为代表的稳定币——原因正是其流动性强、跨链转移便捷，而监管盲区相对更大。

从犯罪类型来看，洗钱手段已呈现出系统性的"专业化"趋势。以 Huione Group 为例，该平台自 2021 年至今经手的加密货币交易额超过 **700 亿美元**，逐渐演化为一个服务于诈骗、洗钱全流程的地下金融基础设施。这一趋势表明，加密货币犯罪不再是分散的个人行为，而是具备组织结构和技术门槛的有组织犯罪。

### 1.2 跨链桥的崛起与监管盲区

近年来，跨链桥（Cross-chain Bridge）的规模急剧扩张。以 Stargate Finance 为例，其月均跨链交易量超过 **23 亿美元**，整个 DeFi 生态中每月跨链资产规模逾 **80 亿美元**。跨链桥的核心功能是允许用户在不同区块链之间转移资产，其本身是合法且重要的基础设施——但这一特性同样被犯罪分子系统性地利用于切断资金追踪链条。

Elliptic 于 2023 年的报告指出，**70 亿美元**的非法资产已通过跨链服务完成洗钱，且这一数字自 2022 年起持续快速增长。在可识别的洗钱方案中，**58% 使用了跨链桥**作为关键一环（2024 年数据）。Chainalysis 也在其 2024 年报告中指出，来自被盗资金关联地址的跨链桥使用量在 2023 年出现了大幅跃升。

以北韩黑客组织 Lazarus Group 的操作为例：
- **Ronin Bridge 攻击（2022 年 3 月）**：盗取约 6.25 亿美元，随后通过 Tornado Cash 混币、Avalanche 跨链桥切链到比特币网络，再经 Sinbad 混币器二次清洗，整个洗钱流程横跨超过 12,000 个地址、涉及多条链。
- **Harmony Horizon Bridge 攻击（2022 年 6 月）**：盗取约 1 亿美元，**98% 的被盗资产经由 Tornado Cash 混币**，之后在 Ethereum、BNB Chain、BitTorrent Chain 之间反复跳转，直至 2023 年部分资金再次出现在 Avalanche 和 TRON 链上。

这类攻击展示了当代洗钱的典型模式：**混币 + 跨链 + 多跳中转**，其目的正是通过增加追踪难度来消耗执法和合规资源。

### 1.3 现有工具的局限性

国际刑警组织与相关执法机构的调查显示，**74% 的机构报告称现有区块链调查工具在跨链活动追踪方面存在明显局限**。主流工具（如 Chainalysis Reactor、TRM Labs）虽已具备一定的跨链能力，但其核心算法并未被学术界公开验证，且主要面向商业客户。

从学术研究现状来看，现有文献的主要局限集中在以下几点：

1. **单链为主**：绝大多数 AML 研究以 Bitcoin 或 Ethereum 为单一研究对象，缺乏跨链场景下的分析框架。
2. **黑名单覆盖不足**：现有研究多依赖 OFAC 制裁名单，忽视了稳定币发行方（如 Tether）自行维护的实际冻结名单——后者更贴近真实洗钱被发现的第一现场。
3. **可追溯性未分类讨论**：现有研究鲜少区分"透明桥"与"不透明桥"，而这一分类对于判断是否能继续追踪资金流向至关重要。
4. **图分析缺乏深度控制机制**：现有图分析方法通常设定固定深度，未考虑不同分支的可疑程度差异，导致要么追踪太浅（可规避）、要么开销太大（误伤正常用户）。

---

## 二、研究动机

### 2.1 为什么要做这个工作

本研究的核心动机来自一个现实矛盾：**区块链上的每一笔交易都是公开可查的，但资金流向依然可以被有效隐藏。**

区块链的透明性（transparency）是其与传统银行系统最大的不同——所有交易记录永久保存在公开账本上，任何人都可以查阅。然而，犯罪分子通过三类工具抵消了这种透明性：

1. **混币器（Mixer）**：将多个用户的资金混合后输出，切断输入与输出之间的对应关系。Tornado Cash 在被 OFAC 制裁前累计匿名化了超过 **70 亿美元**的资金流。
2. **不透明跨链桥**：通过流动性池（如 Synapse、Multichain）或做市商模式（如 Orbiter Finance）完成资产转移，但在链上数据中无法找到"这笔钱到底转给了谁"的记录。
3. **干净地址中转**（Money Mule）：通过一连串外观"干净"的中间地址来拉开源地址与目标地址的图谱距离，稀释关联性。

因此，单纯依靠"这个地址是否在黑名单上"的一跳式检查是不够的。现实中的洗钱路径往往需要追踪多跳，才能发现隐藏在中间层的高风险关联。

### 2.2 稳定币黑名单的价值与不足

Tether（USDT 发行方）是目前加密世界中最具执行力的"第一响应人"之一。其维护的黑名单（USDT Blacklist）截止 2025 年 3 月已冻结超过 **8,500 个地址**、涉及资产超过 **42 亿美元**，其中包括与制裁实体、诈骗网络和恐怖主义融资相关的地址。

BlockSec 在 *Following the Frozen: An On-Chain Analysis of USDT Blacklisting* 中分析了 USDT 黑名单的链上行为，发现 **54% 的被冻结地址在冻结发生时，资产已被提前转出**，说明冻结行动常常滞后于实际的资金转移。这也意味着：**真正有价值的是冻结事件发生之前的资金流向追踪，而不仅仅是冻结之后的快照分析。**

本研究正是从这一观察出发：以 USDT 黑名单为"锚点"，向上追踪与黑名单地址有过资金往来的上游地址，并通过跨链追踪延伸到其他链，构建一个多跳、多链的风险评估体系。

### 2.3 普通用户的合规困境：被动污染问题

现有的 AML 工具（Chainalysis、TRM Labs、Elliptic）均以机构用户为主要服务对象，其产品定位是帮助**交易所和监管机构**识别可疑账户。然而，链上的**普通用户**面临的合规风险往往是被动的，且完全缺乏应对工具。

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
- 洗钱方有意识地将资金**分散至大量普通地址**（即前文所述的 Money Mule），令这些地址在无意中成为洗钱链条的一环，再由其转入交易所，以此绕过直接黑名单检测。

BlockSec 的分析发现，**54% 的黑名单地址在被冻结前已完成资产转移**——这意味着大量已转出的"污染资金"已经在正常用户地址之间流通，而这些用户本人对此毫不知情。

本研究的目标正是填补这一工具空白：为**普通链上用户**提供一个可自行查验的地址风险评估工具，使其能在发起交易或接受转账前，判断对方地址是否与已知违规行为存在资金关联，从而主动规避被动污染风险。

### 2.4 研究问题的明确定义

综合以上背景，本研究回答以下核心问题：

> **给定一个待查区块链地址，如何系统地识别它与已知黑名单地址之间是否存在资金关联，以及这种关联的风险程度和可信度如何——特别是在资金路径跨越多条区块链、经过混币器或多层中转的场景下？**

具体而言，本研究需解决四个子问题：

- **子问题 1（分类问题）**：如何区分"真正无法追踪的隐匿行为"（混币器、不透明桥）与"可以穿透追踪的跨链行为"（透明桥）？
- **子问题 2（深度问题）**：在多跳追踪中，如何在"追踪深度不足（可规避）"和"追踪开销过大（误伤正常用户）"之间找到合理的平衡点？
- **子问题 3（评分问题）**：如何将多跳、多链的追踪结果量化成可解释的风险评分，使得不同地址之间可以横向比较？
- **子问题 4（比例问题）**：当一个地址同时持有合法资金和污染资金时，如何区分"黑钱"与"白钱"的比例，避免对整个地址一刀切地判定为高风险？

---

## 三、相关文献综述

### 3.1 区块链交易图与 AML 检测

将区块链交易建模为图（Graph）是当前 AML 研究的主流范式。在这一方向上，最具影响力的基础工作来自 Weber 等人（2019 年），他们发布了 **Elliptic Dataset**——一个包含 203,769 个节点和 234,355 条有向边的比特币交易图，其中约 4,500 个节点带有"非法"标注，并在 KDD 2019 的异常检测研讨会上首次提出将图卷积网络（GCN）应用于 AML 分类任务 [1]。该数据集至今仍是学术界最广泛使用的 AML 基准（Benchmark）。2024 年，同一团队发布了第二代数据集 **Elliptic2**，提供社区级标注，支持对整个洗钱子图（而非单笔交易）进行形态分析 [2]。

然而，上述研究有一个共同局限：**均基于单链（主要是 Bitcoin 或 Ethereum），没有讨论资金跨链后如何继续追踪。** 此外，地址聚类（Address Clustering）是商业工具（Chainalysis、Elliptic）的核心能力之一，旨在将同一实体控制的多个地址归并识别，但相关算法细节并未公开，学术界的开源实现也主要依赖启发式方法，在 Ethereum 账户模型下覆盖率有限。本研究不直接实现地址聚类，但在子节点生成阶段采用交互频率作为代理指标，优先追踪高频交互地址，部分补偿了缺乏聚类能力的不足。

### 3.2 跨链交易的追踪与可追溯性

这一方向是本研究最直接的学术背景，也是近年来增长最快的研究领域之一。

#### 3.2.1 透明桥的追踪方法

**Mazorra 等人（2023/2024）** 在论文 *Tracing Cross-chain Transactions between EVM-based Blockchains: An Analysis of Ethereum-Polygon Bridges*（发表于 Ledger 期刊）中，提出了一套针对 EVM 兼容链之间跨链交易的匹配启发式算法 [3]。其核心思想是：**EVM 兼容链之间，用户地址在不同链上保持一致**（例如同一个 `0xABCD...` 地址在 Ethereum 和 Polygon 上是同一密钥控制的），因此可以通过"时间窗口 + 金额 + 代币类型"的组合匹配算法，将源链上的 Lock 事件与目标链上的 Mint/Release 事件关联起来。该研究在覆盖 2020 年 8 月至 2023 年 8 月的超过 200 万笔跨链交易上实现了高达 **99.65%** 的存款匹配率和 **92.78%** 的取款匹配率。

**Sun 等人（2025）** 在论文 *Track and Trace: Automatically Uncovering Cross-chain Transactions in the Multi-blockchain Ecosystems*（arXiv 2504.01822）中，系统分析了 **12 个主流跨链桥**（包括 Stargate、Celer cBridge、Wormhole、Synapse 等），覆盖 2021 年 4 月至 2024 年 3 月的以太坊源链数据，提出了自动化识别跨链交易的通用框架 [4]。该工作的重要发现之一是：不同桥的"透明程度"差异极大——基于消息传递协议（如 LayerZero）的桥可以通过 API 直接获取对端交易哈希，而基于流动性池的桥（如 Synapse）则几乎不可能在链上数据中找到明确的输入-输出对应关系。

**A Survey of Transaction Tracing Techniques for Blockchain Systems**（arXiv 2510.09624）则从更宏观的视角梳理了区块链交易追踪技术的发展脉络，将现有方法分为：链上事件关联、API 辅助追踪、统计推断和机器学习四大类，并指出跨链追踪是当前最欠缺系统性研究的方向 [5]。

#### 3.2.2 透明桥 vs. 不透明桥：可追溯性分类的重要性

本研究认为，区分**透明桥（traceable bridge）**和**不透明桥（opaque bridge）**是进行有效资金追踪的前提，但这一分类在现有学术文献中尚未得到充分讨论。以下对比说明了两者的本质差异：

| 维度 | 透明桥 | 不透明桥 |
|------|--------|----------|
| **工作机制** | 消息传递协议（LayerZero、Wormhole）或 Rollup 官方桥 | 流动性池（Synapse）、做市商模式（Orbiter、Owlto） |
| **链上对应关系** | 存在唯一 transferId 或共同 txHash，可关联两端 | 用户资金先进入共享池，再由做市商在目标链独立转出，无法关联 |
| **类比** | 银行电汇（有汇款参考号） | 现金存入 ATM 后由不同人取出（无法关联） |
| **洗钱风险** | 低（资金流向可被追踪和追溯） | 高（等同于混币器，资金流向不可追踪） |
| **典型代表** | Stargate, Hop Protocol, Arbitrum/Optimism 官方桥 | Multichain（已崩溃）、Orbiter Finance、Synapse |

Multichain（曾是最大跨链桥之一）于 2023 年因内部问题崩溃，导致约 **1.27 亿美元**资产丢失——这一事件本身也暴露了不透明桥在透明度和可审计性方面的根本性缺陷。

#### 3.2.3 犯罪案例中的跨链洗钱路径

Lazarus Group 在 Ronin Bridge 和 Harmony Bridge 攻击中的洗钱路径（详见第 1.2 节）是迄今为止最被研究的跨链洗钱案例。Chainalysis 的链上追踪显示，在多层桥接和混币操作之后，大部分资金最终流向了 OTC 场外交易商或高风险交易所；执法机构最终追回了约 **3,000 万美元**——仅占 Ronin 被盗总额的约 4.8%。

这一数字揭示了当前追踪能力的上限：即便是资源最充足的商业工具，在面对混币器 + 多链跳转的组合时，追回率也极低。这正是提升自动化追踪工具学术研究价值的根本原因。

### 3.3 多跳风险评分与树状追踪：与本研究最直接相关的先行工作

本节梳理与本研究技术方案最直接相关的三项工作，并在节末给出详细对比表。

#### 3.3.1 奠基工作：Bitcoin 交易风险评分（2014）

**Möser, Böhme & Breuker（2014）** 在 *Towards Risk Scoring of Bitcoin Transactions*（Financial Cryptography 2014）中首次将"从已知违规地址出发、沿交易图传播风险"形式化为一个研究问题 [6]。该工作提出了两种传播策略：

- **Poison（全污染）**：只要资金来源中含有任何违规输入，输出视为完全污染
- **Haircut（按比例）**：污染比例等于违规来源资金占总输入的比例，随混合逐步稀释

这是学术界最早讨论"多跳风险"的工作，被后续几乎所有 Taint Analysis 研究引用。其局限在于发表于 2014 年，研究场景仅限于 Bitcoin 单链，未涉及跨链桥或混币器的特殊处理逻辑。

#### 3.3.2 TaintRank：PageRank 风格的污染传播（2019）

**Hercog & Povšea（2019）** 在 *Taint analysis of the Bitcoin network*（arXiv:1907.01538）中提出 **TaintRank** 算法 [7]，将污染传播类比为 PageRank：

- 构造以地址为节点、交易为有向边的有权图
- 每个节点的污染值由其所有上游节点的加权污染值累加而来
- 污染随传播距离增大自然衰减，最终分布呈幂律形态

TaintRank 以**批量、全局**的方式对整个 Bitcoin 网络进行评分，可为每个地址产生 0-1 的污染指数。与本研究不同的是，它是离线批处理算法，不支持以单个地址为根节点的实时树状查询，亦不支持跨链场景。

#### 3.3.3 Transaction Proximity：Circle 对 Ethereum 全图的 BFS 实践（2025）

**Liao, Zeng, Belenkiy & Hirshman（2025）** 来自 USDC 发行方 Circle，在 *Transaction Proximity: A Graph-Based Approach to Blockchain Fraud Prevention*（arXiv:2505.24284）中，将 BFS 思路应用于整个 Ethereum 历史图 [8]：

- 数据规模：**2.06 亿节点，4.42 亿条边**，覆盖 Ethereum 从创世到 2024 年 5 月的全部交易
- BFS 深度上限：**5 跳**（覆盖 98.2% 的 USDC 活跃持有者）
- 核心指标：**Transaction Proximity**（与受监管交易所的最短跳数）和 **EAI（Easily Attainable Identities）**（直接连接到交易所的地址）
- 关键发现：83% 的已知攻击者地址不是 EAI，21% 距离任何受监管交易所超过 5 跳——说明犯罪地址在图结构上确实倾向于远离"正常流通节点"

值得注意的是，该论文的风险视角与本研究**方向相反但互补**：Transaction Proximity 衡量"距离合法锚点的远近"（越近越合法），本研究衡量"距离违规锚点的远近"（越近越危险）。两种方法理论上可以融合使用，为同一地址从两个方向提供置信度。

#### 3.3.4 与本研究的系统对比

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
| 树状可视化 + Mermaid 导出 | ❌ | ❌ | ❌ | ✅（商业） | ✅ |
| 开源可复现 | — | 部分 | 部分 | ❌ | ✅ |

从对比可以看出：本研究的核心增量在于**跨链追踪框架**（含桥的可追溯性分类）和**自适应深度**机制，这两点在现有学术文献中均无直接先例。Transaction Proximity（2025）是方法论最接近的工作，但它的跨链能力和面向普通用户的定位均未覆盖。

### 3.4 监管框架与现实需求

**FATF（金融行动特别工作组）** 于 2019 年将虚拟资产（VA）和虚拟资产服务提供商（VASP）纳入其反洗钱和反恐融资标准框架（Recommendation 15），并在 2023 年的定向更新报告中指出：在 151 个成员国中，**超过一半尚未实施"旅行规则"（Travel Rule）**，75% 的成员国对 R.15 处于部分合规或不合规状态 [9]。FATF 2023 报告同时特别强调了稳定币被 DPRK 行为者、恐怖主义融资和毒品贩运者使用的显著增长趋势。

上述背景说明：当前合规体系依然存在巨大缺口，自动化、可解释的链上追踪工具具有明确的现实需求，而不仅仅是学术上的研究兴趣。

与 FATF 框架相呼应的是，**欧盟《人工智能法案》（EU AI Act, Regulation 2024/1689）** 于 2024 年正式生效，将用于 AML/CFT 合规的 AI 系统归类为 **"高风险 AI 系统"（Annex III）** [18]。该法案要求此类系统必须满足以下条件：（1）决策逻辑的充分透明性（transparency），（2）人类监督机制（human oversight），（3）可向监管机构和终端用户提供完整的决策解释（explainability）。违规者最高面临 **3,500 万欧元或全球营业额 7%** 的罚款。这意味着"黑盒"模型（如纯 GNN 分类器）在不具备解释层的情况下，将越来越难以满足欧洲市场的合规要求——这为可解释的 AML 系统提供了明确的制度驱动力。

### 3.5 AML 系统的可解释性与 LLM 解释层

#### 3.5.1 可解释性的监管刚需

AML 检测系统的可解释性并非"锦上添花"，而是监管的硬性要求。FATF Recommendation 20 要求金融机构在提交可疑交易报告（Suspicious Transaction Report, STR）时必须包含"为什么认为该交易可疑"的文字说明。美国《银行保密法》（Bank Secrecy Act）同样要求可疑活动报告（SAR）以自然语言描述可疑行为的具体模式。上述 EU AI Act 则进一步将这种解释义务扩展到了 AI 系统本身 [18]。

这产生了一个核心矛盾：**检测效果最好的模型（GNN、深度学习）恰恰是最不可解释的；而最可解释的方法（规则引擎）检测能力有限。**

#### 3.5.2 XAI（可解释 AI）在 AML 中的应用

近年来，将可解释性工具（SHAP、LIME 等）引入 AML 模型的研究迅速增长。Kute 等人（2026）提出了一个端到端的可复现 SHAP 框架，用于解释 AML 模型的决策过程，强调公平性与监管合规的结合 [17]。该工作系统地展示了如何将特征重要性归因转化为合规部门可理解的报告。

在区块链场景下，Watson, Richards & Schiff（2025）提出了一个具有代表性的三层架构 [14]：

```
Layer 1: GNN 检测层（GCN-GRU 混合模型，准确率 0.9470，AUC-ROC 0.9807）
Layer 2: GraphLIME 归因层（识别哪些特征驱动了分类结果）
Layer 3: LLM 解释层（将归因结果转化为自然语言叙述）
```

该架构在 Elliptic++ 数据集上验证，论文题为 *Explain First, Trust Later: LLM-Augmented Explanations for Graph-Based Crypto Anomaly Detection*，代表了 GNN + XAI + LLM 三层融合的最新范式。

#### 3.5.3 LLM 在链上交易解释中的独立应用

除了作为 GNN 的解释层，LLM 也被直接应用于链上交易数据的分析和解释。Nicholls 等人（2024）在 *Large Language Model XAI Approach for Illicit Activity Investigation in Bitcoin*（发表于 Springer *Neural Computing and Applications*，IF 4.7）中 [15]，展示了一种不依赖传统 ML 检测器的方法：直接将 Bitcoin 交易数据输入 LLM 生成自然语言叙述，再提取叙述的嵌入向量计算相似度，从而发现其他非法交易。该方法的意义在于证明了 LLM 对链上交易数据能产生"有用的、可操作的解释"，且这些解释本身可以作为一种特征用于下游检测。

Sun 等人（2024）发表了第一篇系统综述 LLM 在区块链安全领域应用的论文 *Large Language Models for Blockchain Security: A Systematic Literature Review* [16]，覆盖异常检测、智能合约审计、交易分析等方向，为该领域的研究全景提供了结构化梳理。

#### 3.5.4 与本研究的关系

本研究的规则引擎（BFS 追踪 + 风险评分）在可解释性方面具有天然优势：每一步决策（为什么该节点被标为 suspect、风险路径是什么、衰减是怎么算的）都有完整的因果链条，不存在"黑盒"问题。这使得引入 LLM 作为解释层的路径更为直接——不需要 SHAP/LIME 等 post-hoc 归因工具来"反向推测"模型决策，而是直接将已有的结构化追踪结果（JSON）转化为自然语言风险报告，天然满足 SAR/STR 的叙述性要求。

### 3.6 隐私保护合规：零知识证明与 Privacy Pools

#### 3.6.1 隐私与合规的核心矛盾

区块链 AML 领域存在一个根本性张力：**隐私保护（Privacy）与合规审查（Compliance）长期被视为不可兼得的两极。** 用户有合法的隐私需求（不暴露资产状况和交易细节），但合规框架要求资金来源的可追溯性。

2022 年 8 月，美国 OFAC 首次制裁了 Tornado Cash 智能合约——这是历史上首次对一个**开源、不可变的代码**而非人或组织实施制裁，引发了学术界和法律界的广泛讨论。Brownworth, Durfee, Lee & Martin（2024）在纽约联储的工作论文中对此进行了系统的实证分析 [21]：制裁公告后 Tornado Cash 的交易量和用户多样性立即下降，但净流入量在数月后恢复甚至超过制裁前水平；处理 Tornado Cash 交易的区块验证者数量持续萎缩，表明**审查抵抗能力是脆弱的（fragile）**。2024 年 11 月，美国第五巡回上诉法院裁定 OFAC 制裁不可变智能合约超越了其法定权力；2025 年 3 月，美国财政部正式解除了对 Tornado Cash 的制裁。

这一系列事件表明：**单纯制裁隐私工具不是长久之计**，需要从技术层面寻找隐私与合规的平衡点。

#### 3.6.2 Privacy Pools：隐私与合规的实用均衡

**Buterin, Illum, Nadler, Schär & Soleimani（2023）** 在论文 *Blockchain Privacy and Regulatory Compliance: Towards a Practical Equilibrium*（发表于 *Blockchain: Research and Applications*）中 [19]，提出了 **Privacy Pools** 协议和 **Association Sets（关联集合）** 的核心概念：

- **存款阶段**：用户将资金存入隐私池（与 Tornado Cash 类似）
- **取款阶段**：用户选择一个 Association Set，并用零知识证明（ZKP）证明"我的存款属于这个集合"，但不暴露具体是哪一笔
- **Association Set 的语义**：
  - **包含集合（Inclusion）**："我的存款属于{已知合法来源的存款集合}"
  - **排除集合（Exclusion）**："我的存款不属于{OFAC 制裁地址的存款集合}"

该协议首次在学术上证明了**"隐私"与"合规"不必是非此即彼的**——用户可以在保护交易细节的同时，向验证方证明资金来源的合法性。Privacy Pools v1 已于 2024 年在 Ethereum 主网上线。

#### 3.6.3 Proof of Innocence 的实践与局限

Privacy Pools 的核心思想催生了 **Proof of Innocence（无辜证明）** 的工程实践。Railgun 协议率先部署了 **Private Proofs of Innocence（PPOI）** 系统：在用户存入代币（shield）时，钱包自动生成一个 ZK 证明，证明该代币"不属于预设的非法交易/地址列表"。该证明由去中心化的 POI 节点验证，整个过程端到端加密，不暴露用户的 0zk 地址、余额或交易历史。

然而，Constantinides & Cartlidge（2025）在 *zkMixer: A Configurable Zero-Knowledge Mixer with Anti-Money Laundering Consensus Protocols*（已被 IEEE DAPPS 2025 接收）中 [20]，指出了 Proof of Innocence 在实践中的根本缺陷：**PoI 依赖于黑名单的完整性和实时性**——如果一笔存款在通过 PoI 检查之后才被标记为非法，则该存款已经进入隐私池且不可撤销。该论文提出了替代方案：通过共识机制在存款进入混币池**之前**由参与者集体验证，若未通过验证，则可冻结或退回存款。

#### 3.6.4 隐私保护 AML 的密码学技术路线

在 ZKP 之外，其他密码学方法也被探索用于隐私保护 AML：

- **全同态加密（FHE）**：Effendi & Chattopadhyay（2024）在 *Privacy-Preserving Graph-Based Machine Learning with Fully Homomorphic Encryption for Collaborative Anti-Money Laundering*（SPACE 2024 会议）中 [23]，展示了使用 FHE 在加密数据上直接执行图机器学习（XGBoost 达到 99%+ 准确率），使得多个金融机构可以在不共享原始数据的前提下协作完成 AML 检测。
- **ZKP 中间件**：Chaudhary（2023）提出的 zkFi 框架 [22] 将零知识证明封装为 DeFi 协议的即插即用合规插件，降低了 ZKP 的集成门槛。

#### 3.6.5 与本研究的关系

本研究目前基于公开链上数据进行风险追踪，追踪结果（完整的 BFS 路径树）暴露了用户的交易关联信息。从隐私保护的角度，一个自然的演进方向是：**用户在本地运行追踪，生成一个 ZK 证明——"该地址在 N 跳内没有黑名单关联"——但不暴露具体路径。** 验证方（交易所或交易对手）只看到证明有效与否，看不到追踪过程中涉及的任何中间地址。

这一方向面临的主要挑战包括：（1）黑名单的实时更新问题——证明的有效性依赖于黑名单的某个快照版本；（2）计算开销——对 BFS 追踪树生成 ZK 证明的电路复杂度较高；（3）Association Set 的构建者信任问题——谁来决定哪些地址属于"合法"集合。这些是当前学术界的开放问题，超出本研究的当前范围，但作为长期研究方向具有明确的价值。

---

## 四、研究方案概述

基于以上背景和文献，本研究提出一个**以地址为根节点的多链风险溯源图（Multi-Chain Risk Trace Graph）**，核心设计决策如下：

### 4.1 桥的可追溯性分类作为追踪框架的基础

与现有研究不同，本研究将跨链桥的可追溯性（traceability）作为分析框架的一等公民，将其分为：
- **透明桥**：通过协议 API（LayerZero Scan、Hop、Wormhole 等）或事件日志（Rollup 桥）获取对端地址，继续在目标链上展开分析
- **不透明桥**：视同混币器，标记为"追踪断裂"的高风险终止节点

这一分类直接回应了 Sun 等人（2025）在多桥研究中提出的可追溯性差异问题，并在工程实现层面给出了一套可操作的处理方案。

### 4.2 树状追踪与自适应深度

本研究使用 BFS（广度优先搜索）构建资金关联树，并引入**自适应深度（Adaptive Depth）**机制：
- 普通分支使用标准最大深度（默认 3 跳）
- 发现可疑指标（接触黑名单 / 使用混币器 / 使用不透明桥）的分支获得 `depth_bonus` 额外跳数（默认 +1）

这一设计在"追踪不足"和"追踪过度"之间提供了一个数据驱动的平衡点，而不是人为的固定阈值。

### 4.3 风险评分的跳数衰减

参考 AML 实践中"直接关联风险高于间接关联"的共识，本研究引入每跳 **0.6 倍**的风险衰减系数：

| 关联距离 | 衰减后有效风险（原始 100 分） | 风险等级 |
|----------|-------------------------------|----------|
| 直接接触（1 跳） | 60 分 | HIGH |
| 二跳 | 36 分 | MEDIUM |
| 三跳 | 21.6 分 | LOW |
| 四跳及以上 | ≤ 13 分 | 参考 |

### 4.4 中转地址识别

针对"干净地址中转"（Money Mule）这一常见洗钱手段，系统在完成 BFS 展开后对全树进行二次扫描：若一个看似干净的地址的子树中存在黑名单命中，则将其标记为"疑似中转地址（suspect）"，并计算该地址的子树污染评分（contamination score）。

---

## 五、当前进展

### 5.1 已完成工作

本研究目前已完成以下核心模块的实现：

**`aml_analyzer.py` — 单地址分析引擎**
- 接入 Etherscan API 和 TronScan API，完整支持 Ethereum 和 Tron 链
- 实现 USDT 黑名单检测（8,500+ 地址，覆盖 Ethereum 和 Tron）
- 实现跨链桥注册表（`BRIDGE_REGISTRY`），包含 20+ 个桥合约，区分透明/不透明
- 实现混币器识别（Tornado Cash 等 10 个合约）
- 实现 `BridgeTracer`：通过 LayerZero Scan API 获取跨链对端地址
- 实现风险评分（0-100 分）

**`trace_graph.py` — 递归溯源图引擎**
- 基于 BFS 构建多跳资金关联树
- 实现透明桥 → 切链继续追踪
- 实现自适应深度（`depth_bonus`）
- 实现子树风险传播（每跳 0.6 衰减）
- 实现"疑似中转地址"二次标记
- 支持 JSON 导出和 Mermaid 可视化图导出

### 5.2 测试数据选取

系统已具备可测试能力。以下为计划测试的代表性地址：

| 地址 | 类型 | 预期结果 |
|------|------|----------|
| `0x098b716b8aaf21512996dc57eb0615e2383e2f96` | Ronin Bridge 攻击者（Lazarus Group），已在 USDT 黑名单 | 直接黑名单命中，树第一层即终止 |
| `0x7f367cc41522ce07553e823bf3be79a889debe1b` | Lazarus Group 关联地址，已在 USDT 黑名单 | 黑名单命中 |
| 与上述地址有直接交互的上游地址 | 一跳关联（通过 Etherscan 查询） | 风险分 ≈ 60，标记为疑似中转 |
| 使用 Stargate Finance 跨链的测试地址 | 透明桥使用者 | 切链到目标链继续分析 |

### 5.3 后续计划

**近期工程完善（短期）：**
1. 补充 OFAC SDN 名单（覆盖 Harmony 攻击等未被 Tether 冻结的地址）
2. 实现 Hop Protocol、Across Protocol 的对端地址解析
3. 对已知洗钱案例（Ronin/Harmony）进行端到端追踪测试，验证树状结构是否能还原实际洗钱路径
4. 引入时间窗口过滤，避免远古交易引入误报

**中期研究方向：Taint 比例分析**

当前系统对"使用了混币器的地址"或"接收了黑名单转账的地址"采用整体性的风险标记，未能区分该地址中被污染资金与合法资金的比例。这在实践中会导致误伤：一个地址收到了 1 USDT 的黑名单转账，但同时持有 10,000 USDT 的完全合法资金，不应与直接洗钱地址等同对待。

**Taint Analysis（污染比例分析）**是区块链取证领域已有研究的方向，其核心问题是：给定一个地址，其资产中有多大比例可以被溯源到已知违规来源？典型方法包括：
- **FIFO 法**：先入先出，假设地址中最早收到的资金最先被花出
- **按比例法（Haircut）**：污染比例随每次混合按比例稀释
- **Poison 法**：只要有任何污染来源，整个输出均视为污染（最保守）

将 Taint Analysis 引入本系统，可将当前的二元判断（风险/非风险）升级为**比例置信度评分**，更贴近实际合规需求，也更符合 meeting 中提出的"区分黑钱和白钱"目标。

**远期研究方向：LLM 解释层与合规隐私**

1. **LLM 风险解释层**：将现有系统的 JSON 追踪结果输入 LLM，自动生成满足 SAR/STR 监管要求的自然语言风险报告（详见第 3.5 节文献分析）。该方向已被 Watson 等人 [14] 和 Nicholls 等人 [15] 在 Elliptic++ 和 Bitcoin 数据集上验证可行性。

2. **ZKP 合规证明**：用户在本地运行追踪后，生成零知识证明——"该地址在 N 跳内没有黑名单关联"——但不暴露具体路径。该方向的理论基础来自 Buterin 等人的 Privacy Pools [19]，工程实践中的局限性和替代方案已由 Constantinides & Cartlidge [20] 系统分析。

这两个方向分别对应 EU AI Act 的可解释性要求 [18] 和隐私保护合规的长期需求，超出当前中期阶段的实现范围，但作为研究议题值得在报告中提出。

---

## 四、系统改进：从规则引擎到机器学习

### 4.1 现有规则引擎的系统性缺陷

在对 `aml_analyzer.py` 和 `trace_graph.py` 进行代码审查后，发现了五个影响分析准确性的系统性问题，分为两大类：

**第一类：采样扭曲（Sampling Bias）**

| 编号 | 问题 | 影响 | 修复方案 |
|:---:|------|------|---------|
| P1 | `MAX_TX_FETCH=100`，仅获取最新 100 笔交易 | 活跃地址的历史脏交易被截断；洗钱者可通过"稀释攻击"制造垃圾交易将脏交易推出窗口 | 提高至 500，并加截断提示 |
| P2 | `txlist + tokentx` 直接拼接导致同一笔交易被计数两次 | 对手方交互频率虚高，排名被扭曲 | 按 `(hash, from, to)` 三元组去重 |
| P5 | 对手方排名纯按交互频率 | DEX Router、交易所热钱包占满名额，低频但大额的可疑地址被淹没 | 引入金额加权复合评分，排除已知 DEX 地址 |

**第二类：图结构失真（Graph Distortion）**

| 编号 | 问题 | 影响 | 修复方案 |
|:---:|------|------|---------|
| P3 | 桥/混币器检测只查 `to` 字段 | 从 Tornado Cash **提取**资金（`from=mixer`）完全检测不到 | `from` 和 `to` 双向检测，记录方向（IN/OUT） |
| P4 | `visited` 集合静默丢弃汇聚路径 | 多条路径指向同一节点（分散→汇聚洗钱模式）不可见 | 保留汇聚信息（`converge_from`、`in_degree`），不展开但记录 |

核心洞察：**这五个问题的共同效果是，洗钱者的对抗策略（制造噪音、使用混币器提取、分散后汇聚）恰好命中系统的盲区。** 采样策略和洗钱者的对抗策略方向相反——洗钱者制造噪音稀释信号，系统却优先看噪音、过滤掉信号。

### 4.2 机器学习工作流

#### 4.2.1 动机与方法选择

参考 Juvinski & Li（2026）的 **StableAML** 论文 [24]，该研究在 16,433 个标注地址上用 68 个行为特征训练树集成模型，CatBoost 达到 Macro-F1 = 0.9775。其关键发现是：**领域特定的特征工程比复杂的图算法更重要** — 树集成模型（CatBoost, F1=0.9775）显著优于图神经网络（GraphSAGE, F1=0.8048），原因是稳定币交易图极度稀疏（density < 0.01），GNN 的 message passing 无法有效传播信息。

基于这一发现，本研究采用**特征工程 + 树集成模型**的路线，而非 GNN。

#### 4.2.2 数据收集

数据来源于两个渠道：

- **Blocklisted 类**（100 个）：从项目维护的 `usdt_blacklist.csv`（Tether 官方冻结名单，约 8,500 条）中取以太坊地址
- **Normal 类**（50 个）：从以太坊最近区块的 USDT Transfer 事件中随机采样活跃地址，排除已知合约（桥、混币器、交易所、零地址）和黑名单地址
- **Sanctioned 类**（10 个）：自动下载 OFAC SDN 制裁名单，提取以太坊地址

对每个地址，使用 Etherscan getLogs API 获取全量 USDT/USDC **Transfer 事件**（ERC-20 标准事件），分 `sent`（topic[1]=地址）和 `received`（topic[2]=地址）双向查询。选择 getLogs 而非 txlist 的原因：（1）避免 txlist/tokentx 交叉重复（P2）；（2）Transfer 事件是 token 移动的唯一权威记录；（3）天然支持双向查询（解决 P3）。

#### 4.2.3 特征工程

参考 StableAML 的四类特征框架，从原始 Transfer 事件中提取 **61 个行为特征**：

| 类别 | 数量 | 代表性特征 | 数据来源 |
|------|:---:|-----------|---------|
| Interaction Features | 18 | `sent_to_mixer`, `received_from_mixer`, `has_flagged_interaction` | 与项目已有地址标签库（BRIDGE_REGISTRY, MIXER_CONTRACTS 等）匹配 |
| Transfer Features | 19 | `transfers_over_10k`, `drain_ratio`, `repeated_amount_ratio` | 纯金额/数量统计 |
| Network Features | 10 | `in_degree`, `out_degree`, `counterparty_flagged_ratio`, `has_proxy_behavior` | from/to 集合计算 |
| Temporal Features | 8 | `has_daily_burst`, `rapid_tx_ratio`, `hour_concentration` | timestamp 排序后计算 |

其中 `has_proxy_behavior` 检测"收到后 24 小时内转出相同金额（±5%）"的模式（peeling chain 中继特征），`repeated_amount_ratio` 检测重复金额转账（peeling chain 信号）。

#### 4.2.4 模型训练与评估

使用 5-Fold Stratified Cross Validation，对比四个树集成模型：

| 模型 | Macro-F1 | PR-AUC |
|------|:--------:|:------:|
| **RandomForest** | **0.919** | **0.949** |
| XGBoost | 0.886 | 0.917 |
| CatBoost | 0.872 | 0.937 |
| LightGBM | 0.865 | 0.932 |

最优模型 RandomForest 的混淆矩阵：

|  | 预测 blocklisted | 预测 normal |
|--|:-:|:-:|
| 实际 blocklisted | 93 | 7 |
| 实际 normal | 4 | 46 |

跨模型共识的 Top 5 重要特征：

1. **`drain_ratio`**（余额清空率）— blocklisted 均值 0.21 vs normal 1.37（被冻结地址资金转不走）
2. **`total_sent_amount`**（总转出金额）— 大额资金流动是核心信号
3. **`counterparty_flagged_ratio`**（对手方标记比例）— KYC/标签数据的价值体现
4. **`out_degree`**（出度）— 黑名单地址出度远低于正常地址
5. **`in_out_ratio`**（流入/流出比）— 资金流向对称性

#### 4.2.5 模型集成

训练好的模型通过 `MLRiskScorer` 类集成到现有系统：

```
原风险评分 = 纯规则引擎（硬编码权重）
新风险评分 = 规则引擎 × 0.4 + ML 模型 predict_proba × 0.6
```

混合策略的设计理由：
- 规则引擎保留 40% 权重：确保已知高风险信号（混币器、黑名单直接关联）不被 ML 模型低估
- ML 模型占 60% 权重：对规则引擎未覆盖的行为模式（时间异常、金额分布、网络拓扑）提供补充信号
- 降级兼容：模型文件不存在时自动回退到纯规则引擎

### 4.3 局限性

1. **数据量有限**：150 个样本 vs StableAML 的 16,433 个。扩大数据集是提升模型泛化能力的最直接手段。
2. **Normal 类未经人工验证**：从链上随机采样的"正常"地址可能包含未被标记的洗钱地址（label noise）。
3. **仅覆盖 USDT/USDC Transfer 事件**：洗钱者 swap 成 ETH 或其他 token 后跳出分析视野。
4. **特征提取的实时性**：当前 ML 评分器从 `RiskReport` 中提取的特征是 report 中已有信息的子集，部分特征（如 temporal features）需要完整的 Transfer 事件数据才能精确计算。
5. **二分类限制**：当前仅区分 blocklisted/normal，未加入 sanctioned、cybercrime 等细分类别。

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
