# ============================================================
# graph.py
# 把原始交易数据建成图结构
# 节点 = 地址，边 = 转账关系
# ============================================================

from collections import defaultdict
from config import BLACKLIST, KNOWN_MIXERS, KNOWN_GAMBLING, KNOWN_BRIDGES

# ── DEX / 交易所 地址标注 ────────────────────────────────────
KNOWN_DEX = {
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap V3 Router2",
    "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b": "Uniswap Universal Router",
    "0x3fc91a3afd70395cd496c647d5a79192c3d612b3": "Uniswap Universal Router2",
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router",
    "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch V4",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5",
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange",
    "0xdef171fe48cf0115b1d80b88dc8eab59176fee57": "Paraswap V5",
    "0xa2a3cae63476891ab2d640d9a5a800755ee79d6e": "Paraswap",
    "0x10ed43c718714eb63d5aa57b78b54704e256024e": "PancakeSwap V2",
    "0x13f4ea83d0bd40e75c8222255bc855a974568dd4": "PancakeSwap V3",
    "0x8a42d311d282bfcaa5133b2de0a8bcdbecea3073": "DODO",
    "0xd702dd976fb76fffc2d3963d037dfdae5b04e593": "DODO",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2",
    "0x6131b5fae19ea4f9d964eac0408e4408b66337b5": "KyberSwap",
    "0x617dee16b86534a5d792a4d7a62fb491b544111e": "KyberSwap Aggregator",
}

KNOWN_CEX = {
    "0x28c6c06298d514db089934071355e5743bf21d60": "Binance",
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549": "Binance",
    "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": "Binance",
    "0x56eddb7aa87536c09ccc2793473599fd21a8b17f": "Binance",
    "0x9696f59e4d72e237be84ffd425dcad154bf96976": "Binance",
    "0xbe0eb53f46cd790cd13851d5eff43d12404d33e8": "Binance",
    "0xf977814e90da44bfa03b6295a0616a897441acec": "Binance",
    "0xa910f92acdaf488fa6ef02174fb86208ad7722ba": "Kraken",
    "0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0": "Kraken",
    "0x0d0707963952f2fba59dd06f2b425ace40b492fe": "Gate.io",
    "0x7793cd85c11a924478d358d49b05b37b91cd5711": "Gate.io",
    "0x77134cbc06cb00b66f4c7e623d5fdbf6777635ec": "OKX",
    "0x98ec059dc3adfbdd63429454aeb0c990fba4a128": "OKX",
    "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b": "OKX",
    "0xeb2629a2734e272bcc07bda959863f316f4bd4cf": "Coinbase",
    "0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43": "Coinbase",
    "0x503828976d22510aad0201ac7ec88293211d23da": "Coinbase",
    "0x71660c4005ba85c37ccec55d0c4493e66fe775d3": "Coinbase",
    "0x3cd751e6b0078be393132286c442345e5dc49699": "Coinbase",
    "0x77696bb39917c91a0c3d2f8c0b49c9977a6b0011": "Huobi",
    "0xab5c66752a9e8167967685f1450532fb96d5d24f": "Huobi",
    "0x6748f50f686bfbca6fe8ad62b22228b87f31ff2b": "Huobi",
    "0x1062a747393198f70f71ec65a582423dba7e5ab3": "Huobi",
    "0x32598293906b35c2a6c4c5571f53f8f9543f1580": "KuCoin",
    "0x2b5634c42055806a59e9107ed44d43c426e58258": "KuCoin",
    "0x689c56aef474df92d44a1b70850f808488f9769c": "Bybit",
    "0xf89d7b9c864f589bbf53a82105107622b35eaa40": "Bybit",
}


def safe_int(x):
    if x is None: return 0
    if isinstance(x, int): return x
    s = str(x).strip().lower()
    if s in ("", "0x"): return 0
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
    except:
        return 0


# ============================================================
# 核心：建图
# ============================================================

def build_graph(eth_txs, int_txs, token_txs):
    """
    从三种交易数据建图

    节点结构：
      addr -> {
        first_seen:    int,   第一笔交易时间戳
        last_seen:     int,   最后一笔交易时间戳
        in_count:      int,   收款次数
        out_count:     int,   发款次数
        in_value:      int,   总收款金额（wei/最小单位）
        out_value:     int,   总发款金额
        tokens:        set,   交互过的币种
        is_blacklist:  bool,  是否在黑名单
        is_mixer:      bool,  是否是 Mixer 合约
        is_gambling:   bool,  是否是赌博合约
        is_bridge:     bool,  是否是跨链桥
        labels:        list,  所有标签
      }

    边结构：
      (from, to, value, timestamp, type/symbol)
      type: ETH / INT / USDT / USDC / ...
    """
    nodes = {}
    edges = []

    def upsert_node(addr, ts):
        """创建或更新节点"""
        a = addr.lower().strip()
        if not a or a == "0x":
            return None
        if a not in nodes:
            nodes[a] = {
                "first_seen":   ts,
                "last_seen":    ts,
                "in_count":     0,
                "out_count":    0,
                "in_value":     0,
                "out_value":    0,
                "tokens":       set(),
                "is_blacklist": a in BLACKLIST,
                "is_mixer":     a in KNOWN_MIXERS,
                "is_gambling":  a in KNOWN_GAMBLING,
                "is_bridge":    a in KNOWN_BRIDGES,
                "is_dex":       a in KNOWN_DEX,
                "is_cex":       a in KNOWN_CEX,
                "labels":       _get_labels(a),
            }
        else:
            nodes[a]["first_seen"] = min(nodes[a]["first_seen"], ts)
            nodes[a]["last_seen"]  = max(nodes[a]["last_seen"],  ts)
        return a

    def add_edge(frm, to, val, ts, typ):
        """添加一条边，同时更新节点统计"""
        f = upsert_node(frm, ts)
        t = upsert_node(to,  ts)
        if not f or not t:
            return
        nodes[f]["out_count"] += 1
        nodes[f]["out_value"] += val
        nodes[t]["in_count"]  += 1
        nodes[t]["in_value"]  += val
        # 记录币种（ETH和内部交易不算token）
        if typ not in ("ETH", "INT"):
            nodes[f]["tokens"].add(typ)
            nodes[t]["tokens"].add(typ)
        edges.append((f, t, val, ts, typ))

    # ETH 普通交易
    for tx in eth_txs:
        if tx.get("isError", "0") == "1":
            continue
        add_edge(
            tx.get("from", ""),
            tx.get("to",   ""),
            safe_int(tx.get("value", 0)),
            safe_int(tx.get("timeStamp", 0)),
            "ETH"
        )

    # 内部交易（合约调用产生的ETH转账）
    for tx in int_txs:
        if tx.get("isError", "0") == "1":
            continue
        add_edge(
            tx.get("from", ""),
            tx.get("to",   ""),
            safe_int(tx.get("value", 0)),
            safe_int(tx.get("timeStamp", 0)),
            "INT"
        )

    # ERC20 全币种
    for tx in token_txs:
        symbol = tx.get("tokenSymbol", "?")
        add_edge(
            tx.get("from", ""),
            tx.get("to",   ""),
            safe_int(tx.get("value", 0)),
            safe_int(tx.get("timeStamp", 0)),
            symbol
        )

    return nodes, edges


def _get_labels(addr):
    """给地址打上所有已知标签"""
    labels = []
    if addr in BLACKLIST:
        labels.append(BLACKLIST[addr])
    if addr in KNOWN_MIXERS:
        labels.append(f"Mixer: {KNOWN_MIXERS[addr]}")
    if addr in KNOWN_GAMBLING:
        labels.append(f"Gambling: {KNOWN_GAMBLING[addr]}")
    if addr in KNOWN_BRIDGES:
        labels.append(f"Bridge: {KNOWN_BRIDGES[addr]}")
    if addr in KNOWN_DEX:
        labels.append(f"DEX: {KNOWN_DEX[addr]}")
    if addr in KNOWN_CEX:
        labels.append(f"CEX: {KNOWN_CEX[addr]}")
    return labels


# ============================================================
# 合并多个图（多跳追踪时用）
# ============================================================

def merge_graphs(base_nodes, base_edges, new_nodes, new_edges):
    """
    把新图合并进基础图
    节点：累加统计数据
    边：直接追加（允许重复，之后去重）
    """
    for addr, info in new_nodes.items():
        if addr not in base_nodes:
            base_nodes[addr] = info
        else:
            base_nodes[addr]["in_count"]  += info["in_count"]
            base_nodes[addr]["out_count"] += info["out_count"]
            base_nodes[addr]["in_value"]  += info["in_value"]
            base_nodes[addr]["out_value"] += info["out_value"]
            base_nodes[addr]["tokens"]    |= info["tokens"]
            base_nodes[addr]["first_seen"] = min(
                base_nodes[addr]["first_seen"], info["first_seen"]
            )
            base_nodes[addr]["last_seen"] = max(
                base_nodes[addr]["last_seen"], info["last_seen"]
            )
            # preserve risk flags — once blacklisted always blacklisted
            base_nodes[addr]["is_blacklist"] = base_nodes[addr]["is_blacklist"] or info["is_blacklist"]
            base_nodes[addr]["is_mixer"]     = base_nodes[addr]["is_mixer"]     or info["is_mixer"]
            base_nodes[addr]["is_gambling"]  = base_nodes[addr]["is_gambling"]  or info["is_gambling"]
            base_nodes[addr]["is_bridge"]    = base_nodes[addr]["is_bridge"]    or info["is_bridge"]
            # merge labels dedup
            existing = set(base_nodes[addr]["labels"])
            base_nodes[addr]["labels"] += [l for l in info["labels"] if l not in existing]
    base_edges += new_edges
    return base_nodes, base_edges


# ============================================================
# 图分析工具函数
# ============================================================

def get_neighbors(addr, edges, direction="both"):
    """
    获取一个地址的邻居
    direction: "in"=来源, "out"=去向, "both"=全部
    """
    addr = addr.lower()
    neighbors = set()
    for (f, t, v, ts, typ) in edges:
        if direction in ("in", "both") and t == addr:
            neighbors.add(f)
        if direction in ("out", "both") and f == addr:
            neighbors.add(t)
    return neighbors


def get_subgraph(addr, edges, hops=2):
    """
    以某个地址为中心，提取 N 跳内的子图
    用于可视化和局部分析
    """
    visited = set()
    frontier = {addr.lower()}

    for _ in range(hops):
        new_frontier = set()
        for node in frontier:
            new_frontier |= get_neighbors(node, edges, "both")
        frontier = new_frontier - visited
        visited |= frontier

    visited.add(addr.lower())

    # 过滤出子图边
    sub_edges = [
        (f, t, v, ts, typ) for f, t, v, ts, typ in edges
        if f in visited and t in visited
    ]
    return visited, sub_edges


def find_linear_chains(nodes, edges):
    """
    找出所有入度=1且出度=1的线性链
    用于 C2 Peel Chain 检测
    返回：[(chain1), (chain2), ...]
    """
    # 入度=1且出度=1的候选节点
    candidates = {
        addr for addr, info in nodes.items()
        if info["in_count"] == 1 and info["out_count"] == 1
    }

    # 建 next 映射
    next_map = {}
    for (f, t, v, ts, typ) in edges:
        if f in candidates:
            next_map[f] = t

    # 找连续链
    visited = set()
    chains  = []

    for start in candidates:
        if start in visited:
            continue
        chain = [start]
        cur   = start
        while (cur in next_map
               and next_map[cur] in candidates
               and next_map[cur] not in visited):
            cur = next_map[cur]
            chain.append(cur)
            visited.add(cur)
        if len(chain) >= 3:
            chains.append(chain)

    return sorted(chains, key=len, reverse=True)


def find_hub_nodes(nodes, min_in=5, min_out=5, max_lifetime=3600):
    """
    找出高入度高出度且短生命周期的中转节点
    用于 C3 Fan-out 检测
    """
    hubs = []
    for addr, info in nodes.items():
        if (info["in_count"] >= min_in
                and info["out_count"] >= min_out):
            lifetime = info["last_seen"] - info["first_seen"]
            if lifetime <= max_lifetime:
                hubs.append({
                    "address":  addr,
                    "in":       info["in_count"],
                    "out":      info["out_count"],
                    "lifetime": lifetime,
                    "labels":   info["labels"],
                })
    return sorted(hubs, key=lambda x: x["in"] + x["out"], reverse=True)


def find_bipartite_pattern(nodes, edges):
    """
    找出二分图模式（C4）
    两组地址集合只在组间交互，不在组内交互
    两侧同时首次激活
    """
    # 找同时激活的地址组（同一时间戳首次出现）
    by_first_seen = defaultdict(list)
    for addr, info in nodes.items():
        by_first_seen[info["first_seen"]].append(addr)

    # 找同时激活超过3个地址的时间点
    suspicious_groups = {
        ts: addrs
        for ts, addrs in by_first_seen.items()
        if len(addrs) >= 3
    }

    results = []
    for ts, group in suspicious_groups.items():
        # 检查这组地址是否只和组外地址交互
        group_set = set(group)
        internal_edges = [
            (f, t) for f, t, *_ in edges
            if f in group_set and t in group_set
        ]
        external_edges = [
            (f, t) for f, t, *_ in edges
            if (f in group_set) != (t in group_set)  # XOR
        ]

        # 没有内部边，只有外部边 = 二分图特征
        if len(internal_edges) == 0 and len(external_edges) >= 3:
            results.append({
                "timestamp":      ts,
                "group":          list(group_set),
                "external_edges": len(external_edges),
                "severity":       "MEDIUM",
            })

    return results


def calculate_taint(address, nodes, edges, max_hops=5):
    """
    Haircut 污染率计算
    黑名单地址的污染率 = 1.0
    污染按转账比例向下游传播
    最多传播 max_hops 跳

    返回：目标地址的污染率（0.0 ~ 1.0）
    """
    addr = address.lower()

    # 直接命中黑名单：自身污染率=100%，无需传播
    from config import BLACKLIST as _BL, KNOWN_MIXERS as _KM
    if addr in _BL or addr in _KM:
        return 100.0

    # 初始化：黑名单地址污染率=1，其他=0
    taint = {}
    for a, info in nodes.items():
        # re-check against config in case is_blacklist was incorrectly False
        taint[a] = 1.0 if (info["is_blacklist"] or a in _BL or a in _KM) else 0.0

    # 按时间顺序传播污染
    sorted_edges = sorted(edges, key=lambda x: x[3])

    for hop in range(max_hops):
        updated = False
        for (f, t, v, ts, typ) in sorted_edges:
            if f not in taint or taint[f] <= 0:
                continue
            total_out = nodes.get(f, {}).get("out_value", 1) or 1
            new_taint = taint[f] * (v / total_out)
            old_taint = taint.get(t, 0.0)
            merged    = min(1.0, old_taint + new_taint)
            if merged > old_taint:
                taint[t] = merged
                updated  = True
        if not updated:
            break

    return round(taint.get(addr, 0.0) * 100, 2)


# ============================================================
# 图转 JSON（给前端用）
# ============================================================

def graph_to_json(nodes, edges, max_nodes=None, max_edges=None, edge_tags=None,
                  detector_results=None, law_section=None, risk_only=False):
    """
    把图结构转成前端可以直接用的 JSON 格式
    risk_only=True：只输出风险相关节点（黑名单/mixer/DEX/CEX/高风险连接），前端性能大幅提升
    risk_only=False：全量输出
    节点颜色编码：
      红色  = 黑名单
      橙色  = Mixer
      紫色  = 赌博
      蓝色  = 桥
      绿色  = DEX
      青色  = CEX
      灰色  = 普通
    """
    # 如果 edge_tags 没传，从 detector_results 动态生成
    if edge_tags is None and detector_results:
        edge_tags = tag_edges(edges, detector_results, nodes)
    def node_color(info):
        if info["is_blacklist"]: return "#ef4444"
        if info["is_mixer"]:     return "#f59e0b"
        if info["is_gambling"]:  return "#8b5cf6"
        if info["is_bridge"]:    return "#3b82f6"
        if info.get("is_dex"):   return "#10b981"   # 绿色 = DEX
        if info.get("is_cex"):   return "#06b6d4"   # 青色 = CEX
        return "#64748b"

    def node_risk_priority(item):
        _, info = item
        if info["is_blacklist"]: return 0
        if info["is_mixer"]:     return 1
        if info["is_gambling"]:  return 2
        if info["is_bridge"]:    return 3
        if info.get("is_dex"):   return 4
        if info.get("is_cex"):   return 4
        return 5

    def node_size(info):
        total = info["in_count"] + info["out_count"]
        return max(10, min(50, total))

    # risk_only: 只保留风险节点 + 与其1跳内的节点
    if risk_only:
        risk_core = {
            addr for addr, info in nodes.items()
            if (info["is_blacklist"] or info["is_mixer"] or info["is_gambling"]
                or info["is_bridge"] or info.get("is_dex") or info.get("is_cex"))
        }
        # 加上detector命中的节点
        if detector_results:
            pc = detector_results.get("peel_chain", {})
            if pc.get("detected"):
                for chain in pc.get("chains", []):
                    risk_core.update(chain)
            fo = detector_results.get("fanout", {})
            if fo.get("detected"):
                risk_core.update(
                    h["address"] if isinstance(h, dict) else h
                    for h in fo.get("hubs", [])
                )
        # 1跳内的邻居
        risk_neighbors = set()
        for f, t, v, ts, typ in edges:
            if f in risk_core: risk_neighbors.add(t)
            if t in risk_core: risk_neighbors.add(f)
        allowed = risk_core | risk_neighbors
        # 如果太少就放宽（最少保留风险边关联的所有节点）
        if len(allowed) < 5:
            allowed = set(nodes.keys())
        filter_nodes = {k: v for k, v in nodes.items() if k in allowed}
    else:
        filter_nodes = nodes

    # 风险优先排序，全量输出（不截断）
    sorted_nodes = sorted(filter_nodes.items(), key=node_risk_priority)
    if max_nodes:
        sorted_nodes = sorted_nodes[:max_nodes]

    node_set = {addr for addr, _ in sorted_nodes}

    # 高风险地址集合（用于边排序）
    high_risk_addrs = {
        addr for addr, info in nodes.items()
        if info["is_blacklist"] or info["is_mixer"]
    }

    json_nodes = [
        {
            "id":     addr,
            "name":   addr[:10] + "...",
            "color":  node_color(info),
            "size":   node_size(info),
            "labels": info["labels"],
            "stats": {
                "in_count":  info["in_count"],
                "out_count": info["out_count"],
                "tokens":    list(info["tokens"])[:5],
                "lifetime":  info["last_seen"] - info["first_seen"],
            }
        }
        for addr, info in sorted_nodes
    ]

    # 边：风险优先排序（黑名单/mixer相关的边排前面），全量输出
    def edge_risk_priority(e):
        f, t = e[0], e[1]
        if f in high_risk_addrs or t in high_risk_addrs: return 0
        return 1

    sorted_edges = sorted(
        [(f, t, v, ts, typ) for f, t, v, ts, typ in edges
         if f in node_set and t in node_set],
        key=edge_risk_priority
    )
    if max_edges:
        sorted_edges = sorted_edges[:max_edges]

    json_edges = [
        {
            "source": f,
            "target": t,
            "value":  v,
            "ts":     ts,
            "type":   typ,
            # DEX/CEX 交互标注
            "via_dex": nodes.get(t, {}).get("is_dex") or nodes.get(f, {}).get("is_dex"),
            "via_cex": nodes.get(t, {}).get("is_cex") or nodes.get(f, {}).get("is_cex"),
            "exchange_name": (
                nodes.get(t, {}).get("labels", [None])[0] if nodes.get(t, {}).get("is_dex") or nodes.get(t, {}).get("is_cex")
                else nodes.get(f, {}).get("labels", [None])[0] if nodes.get(f, {}).get("is_dex") or nodes.get(f, {}).get("is_cex")
                else None
            ),
            "topo_tags": (edge_tags or {}).get((f, t, ts), []),
        }
        for f, t, v, ts, typ in sorted_edges
    ]

    return {
        "nodes": json_nodes,
        "edges": json_edges,
        "stats": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "shown_nodes": len(json_nodes),
            "shown_edges": len(json_edges),
        }
    }


# ============================================================
# 图摘要（用于报告）
# ============================================================

def graph_summary(nodes, edges):
    """
    生成图的统计摘要
    """
    blacklist_nodes = [a for a, i in nodes.items() if i["is_blacklist"]]
    mixer_nodes     = [a for a, i in nodes.items() if i["is_mixer"]]
    all_tokens      = set()
    for _, info in nodes.items():
        all_tokens |= info["tokens"]

    return {
        "total_nodes":      len(nodes),
        "total_edges":      len(edges),
        "blacklist_nodes":  len(blacklist_nodes),
        "mixer_nodes":      len(mixer_nodes),
        "tokens_seen":      list(all_tokens)[:20],
        "blacklist_list":   blacklist_nodes[:10],
    }


# ============================================================
# 把 detector 结果反打到每条边（topo_tags）
# 供 law mapping 和前端高亮用
# ============================================================

def tag_edges(edges, detector_results, nodes=None):
    """
    给每条边打拓扑标签，返回 edge_tags dict:
      key: (from_addr, to_addr, ts) → list of tags

    tags 包括:
      peel_chain, fan_out, fan_in, smurfing,
      bipartite, to_mixer, from_blacklist,
      to_dex, to_cex, to_bridge
    """
    edge_tags = defaultdict(list)   # (f, t, ts) → [tags]

    # ── peel_chain ──────────────────────────────────────────
    peel = detector_results.get("peel_chain", {})
    if peel.get("detected"):
        for chain in peel.get("chains", []):
            for i in range(len(chain) - 1):
                f, t = chain[i], chain[i+1]
                # 找所有匹配的边
                for ef, et, ev, ets, etyp in edges:
                    if ef == f and et == t:
                        edge_tags[(ef, et, ets)].append("peel_chain")

    # ── fan_out ─────────────────────────────────────────────
    fanout = detector_results.get("fanout", {})
    if fanout.get("detected"):
        hub_addrs = {
            h["address"] if isinstance(h, dict) else h
            for h in fanout.get("hubs", [])
        }
        for ef, et, ev, ets, etyp in edges:
            if ef in hub_addrs:
                edge_tags[(ef, et, ets)].append("fan_out")
            if et in hub_addrs:
                edge_tags[(ef, et, ets)].append("fan_in")

    # ── smurfing ────────────────────────────────────────────
    smurfing = detector_results.get("smurfing", {})
    if smurfing.get("detected"):
        repeated_vals = {
            p["value"] for p in smurfing.get("patterns", [])
        }
        for ef, et, ev, ets, etyp in edges:
            if ev in repeated_vals:
                edge_tags[(ef, et, ets)].append("smurfing")

    # ── mixer 交互 ──────────────────────────────────────────
    from config import KNOWN_MIXERS as _KM
    for ef, et, ev, ets, etyp in edges:
        if et in _KM:
            edge_tags[(ef, et, ets)].append("to_mixer")
        if ef in _KM:
            edge_tags[(ef, et, ets)].append("from_mixer")

    # ── 黑名单交互 ──────────────────────────────────────────
    from config import BLACKLIST as _BL
    for ef, et, ev, ets, etyp in edges:
        if ef in _BL:
            edge_tags[(ef, et, ets)].append("from_blacklist")
        if et in _BL:
            edge_tags[(ef, et, ets)].append("to_blacklist")

    # ── DEX / CEX / Bridge ──────────────────────────────────
    if nodes:
        for ef, et, ev, ets, etyp in edges:
            if nodes.get(et, {}).get("is_dex") or nodes.get(ef, {}).get("is_dex"):
                edge_tags[(ef, et, ets)].append("dex_swap")
            if nodes.get(et, {}).get("is_cex") or nodes.get(ef, {}).get("is_cex"):
                edge_tags[(ef, et, ets)].append("cex_deposit" if nodes.get(et, {}).get("is_cex") else "cex_withdraw")
            if nodes.get(et, {}).get("is_bridge") or nodes.get(ef, {}).get("is_bridge"):
                edge_tags[(ef, et, ets)].append("bridge")

    return dict(edge_tags)


def build_graph_with_tags(eth_txs, int_txs, token_txs, detector_results=None):
    """
    建图并打标签，一步完成
    返回 nodes, edges, edge_tags
    """
    nodes, edges = build_graph(eth_txs, int_txs, token_txs)
    edge_tags = tag_edges(edges, detector_results or {}, nodes)
    return nodes, edges, edge_tags
