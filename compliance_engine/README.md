# ChainSentinel — 区块链 AML 合规引擎

> 面向香港稳定币发行的链上反洗钱检测系统

---

## 快速开始

```bash
# 1. 安装依赖
pip install requests flask flask-cors

# 2. 分析单个地址
cd compliance_engine
python analyze.py 0x098B716B8Aaf21512996dC57EB0615e2383E2f96 2

# 3. 启动前端 API
python db.py
# → http://localhost:5001

# 4. 打开前端
open ../dashboard_v2.html
```

---

## 文件结构

```
stbc/
├── dashboard_v2.html          前端界面
├── run.py                     交互式运行菜单
└── compliance_engine/
    ├── analyze.py             主入口
    ├── collector.py           Etherscan V2 数据采集
    ├── graph.py               图结构 + Haircut污染率
    ├── scorer.py              风险评分引擎
    ├── db.py                  SQLite数据库 + Flask API
    ├── config.py              黑名单 + 配置参数
    └── detectors/
        ├── d_blacklist.py     OFAC/Lazarus黑名单
        ├── d_peel_chain.py    C2 Peel Chain
        ├── d_smurfing.py      C1/C2 拆单结构化
        ├── d_fanout.py        C3 蜘蛛网
        ├── d_bipartite.py     C4 二分图
        ├── d_mixer.py         C5/C8 混币器
        ├── d_defi.py          E1-E4 DeFi滥用
        ├── d_nft.py           E5 NFT洗钱
        ├── d_dusting.py       G1 尘埃攻击
        ├── d_pig_butchering.py B4 猪杀盘
        ├── d_reverse_taint.py G2 反向污染
        ├── d_pagerank.py      No.25 PageRank
        └── d_lof.py           No.26 LOF异常
```

---

## 评分规则

| 条件 | 得分 |
|---|---|
| 直接交互黑名单（1跳） | 100（直接标黑） |
| 二跳黑名单 | +50 |
| 三跳黑名单 | +25 |
| 混币器交互 | +30 |
| 不透明跨链桥 | +20 |
| 主动转出给黑名单 >2个 | +40 |
| 主动转出给黑名单 =1个 | +20 |
| 被动收到黑名单 >2个 | +10 |
| 被动收到黑名单 =1个 | +5 |
| OFAC制裁交易所 | +25 |
| 透明桥+黑名单关联 | +15 |
| 透明桥（无黑名单） | +5 |
| Smurfing拆单 | +12 |
| 猪杀盘三段式 | +15 |
| DeFi滥用 | +10 |
| NFT洗钱 | +8 |

**风险等级：**

| 得分 | 等级 |
|---|---|
| ≥ 100（或直接命中黑名单） | 🔴 CRITICAL |
| 60–99 | 🟠 HIGH |
| 30–59 | 🟡 MEDIUM |
| 0–29 | 🟢 LOW |

---

## 覆盖手法

参考慢雾 AML 评估框架，链上可检测手法共 27 种，本系统覆盖：

| 编号 | 手法 | 状态 |
|---|---|---|
| B5/OFAC | 制裁实体直接链上操作 | ✅ |
| C1 | Smurfing 拆单 | ✅ |
| C2 | Peel Chain 剥皮链 | ✅ |
| C3 | Fan-out 蜘蛛网 | ✅ |
| C4 | Bipartite 二分图 | ✅ |
| C5 | ZK Mixer 混币器 | ✅ |
| C8 | Mixer-first Gas资助 | ✅ |
| E1 | DEX 多次闪兑 | ✅ |
| E2 | 流动性池快速存取 | ✅ |
| E3 | Flash Loan | ✅ |
| E4 | Yield Farming | ✅ |
| E5 | NFT Wash Trading | ✅ |
| G1 | Dusting Attack | ✅ |
| G2 | 反向污染攻击 | ✅ |
| B4 | 猪杀盘三段式 | ✅ |
| No.25 | PageRank 风险传播 | ✅ |
| No.26 | LOF 异常检测 | ✅ |
| A1-A8 | 链下手法 | ❌ 需链下数据 |
| D1-D3 | 跨链桥追踪 | 🚧 开发中 |
| H1-H5 | 出金手法 | ❌ 需CEX数据 |

---

## API 接口

启动：`python compliance_engine/db.py`

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/analyze` | POST | 分析地址 `{address, hops}` |
| `/api/db/list` | GET | 列出所有历史记录 |
| `/api/db/get/<address>` | GET | 获取单个地址报告 |
| `/api/db/stats` | GET | 数据库统计 |
| `/api/blacklist` | GET | 黑名单列表 |
| `/api/watchlist` | GET | 监控名单 |

---

## 测试

```bash
# 高风险地址（Lazarus Ronin Bridge）
python analyze.py 0x098B716B8Aaf21512996dC57EB0615e2383E2f96 2

# 灰度地址（Stake.com 赌博平台）
python analyze.py 0x974CaA59029e46ec2393e2c454e6cc0d51e24d40 1

# 安全地址（Binance 热钱包）
python analyze.py 0x28c6c06298d514db089934071355e5743bf21d60 1
```

---

## 技术架构

```
数据采集层    Etherscan V2 API（ETH主网）
              Blockstream API（BTC，开发中）

图分析层      NetworkX 图结构
              BFS 跳数计算
              Haircut 污染率传播

检测层        13个独立检测器
              每个检测器独立文件，可单独调试

评分层        跳数分 + 叠加分
              直接命中黑名单 = 100分 = CRITICAL

输出层        JSON报告 + SQLite缓存
              Flask API + HTML前端
```

---

## 参考资料

- [Vitalik Privacy Pool 论文 2023](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=4563364)
- [慢雾 AML 供应商评估 Checklist](https://github.com/slowmist/Cryptocurrency-AML-Checklist)
- [tayvano Lazarus 研究库](https://github.com/tayvano/lazarus-bluenoroff-research)
- [BIS Bulletin No.111 2025](https://www.bis.org/publ/bisbull111.htm)
- FATF Recommendation 16 Travel Rule
- Hong Kong AMLO Cap.615 / VASP 制度
