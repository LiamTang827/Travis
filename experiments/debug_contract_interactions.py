#!/usr/bin/env python3
"""
Offline debug script for _build_contract_interactions + print_contract_interactions.

我们用一组手造的 normal_txs / token_txs 喂给分析器，模拟三种典型场景：
  A) 正常 ERC20 transfer：normal_tx + 匹配的 token_tx，有 functionName
  B) 多签/路由：normal_tx 的 methodId 是非透明 selector，token_tx 跟在它下面（OUT）
  C) TOKEN_ONLY：token_tx 没有对应 normal_tx（地址只是 inner-call 收款方），
                 methodId 是 0xbc4a02e4（用户报告里出现过的 selector）

这是离线测试，不打 Etherscan，能跑就证明 method 解码 / from-to / TOKEN_ONLY 分支都正常。
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cripto_analyst.aml_analyzer import (
    AMLAnalyzer, BridgeTracer, EVMClient, EVM_CHAIN_REGISTRY,
    RiskReport, TronScanClient, decode_method, print_contract_interactions,
)


ADDR = "0xAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaaAAAAAAAA"
CP_ROUTER = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
CP_PEER = "0xcccccccccccccccccccccccccccccccccccccccc"
CP_SAFE = "0xdddddddddddddddddddddddddddddddddddddddd"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"

NORMAL_TXS = [
    # A) 直白 transfer：functionName 在
    {
        "hash": "0xA1",
        "from": ADDR,
        "to": USDC,
        "value": "0",
        "input": "0xa9059cbb000000000000000000000000ccccc",
        "methodId": "0xa9059cbb",
        "functionName": "transfer(address _to, uint256 _value)",
        "timeStamp": "1715000000",
        "isError": "0",
    },
    # B) 外壳是非透明 selector (multicall 模拟)，functionName 空
    {
        "hash": "0xB2",
        "from": ADDR,
        "to": CP_ROUTER,
        "value": "0",
        "input": "0x5ae401dc000000",
        "methodId": "0x5ae401dc",
        "functionName": "",
        "timeStamp": "1715001000",
        "isError": "0",
    },
]

TOKEN_TXS = [
    # A) 跟 0xA1 配对：用户主动 OUT 100 USDC 给 CP_PEER
    {
        "hash": "0xA1",
        "from": ADDR,
        "to": CP_PEER,
        "contractAddress": USDC,
        "value": str(100 * 10**6),
        "tokenSymbol": "USDC",
        "tokenDecimal": "6",
        "methodId": "0xa9059cbb",
        "functionName": "transfer(address _to, uint256 _value)",
        "timeStamp": "1715000000",
    },
    # B) 跟 0xB2 配对：multicall 内部产生 50 USDT IN 给 ADDR
    {
        "hash": "0xB2",
        "from": CP_ROUTER,
        "to": ADDR,
        "contractAddress": USDT,
        "value": str(50 * 10**6),
        "tokenSymbol": "USDT",
        "tokenDecimal": "6",
        "methodId": "0x5ae401dc",       # token tx 也复用了外层 selector（Etherscan 行为）
        "functionName": "",
        "timeStamp": "1715001000",
    },
    # C) TOKEN_ONLY：normal_txs 里找不到 0xC3，Safe 多签代付时常见
    {
        "hash": "0xC3",
        "from": CP_SAFE,
        "to": ADDR,
        "contractAddress": USDT,
        "value": str(200 * 10**6),
        "tokenSymbol": "USDT",
        "tokenDecimal": "6",
        "methodId": "0xbc4a02e4",       # 用户报告里的 selector
        "functionName": "",
        "timeStamp": "1715002000",
    },
]


def main():
    print("\n[1] decode_method 单元自测")
    cases = [
        ("0xa9059cbb", "transfer(address,uint256)", "transfer"),
        ("0xa9059cbb", "", "transfer"),
        ("0x5ae401dc", "", "multicall"),
        ("0xbc4a02e4", "", "unknown(0xbc4a02e4)"),
        ("", "", ""),
    ]
    for mid, fn, expected in cases:
        got = decode_method(mid, fn)
        mark = "✓" if got == expected else "✗"
        print(f"  {mark} decode_method({mid!r:>14}, {fn!r:<40}) = {got!r}  (expected {expected!r})")

    print("\n[2] _build_contract_interactions 离线跑")
    analyzer = AMLAnalyzer(
        blacklist={},
        evm_clients={n: EVMClient(c) for n, c in EVM_CHAIN_REGISTRY.items()},
        tronscan=TronScanClient(),
        tracer=BridgeTracer(),
    )
    report = RiskReport(address=ADDR.lower(), chain="ethereum")
    chain_cfg = EVM_CHAIN_REGISTRY["ethereum"]
    analyzer._build_contract_interactions(
        report, NORMAL_TXS, TOKEN_TXS, chain_cfg, "ethereum", ADDR
    )

    print(f"  built {len(report.contract_interactions)} interactions")
    for it in report.contract_interactions:
        print(f"  - hash={it['tx_hash']}  dir={it['direction']:<10}"
              f"  method_label={it.get('method_label','—')}"
              f"  effects={len(it['token_effects'])}")
        for eff in it["token_effects"]:
            print(f"      └─ {eff['direction']:<5} {eff['amount']:>10} {eff['sym']:<5}"
                  f" from={eff.get('from','—')[:10]}…  to={eff.get('to','—')[:10]}…"
                  f"  inner_label={eff.get('method_label','—')}")

    # 校验关键不变量
    assert any(it["tx_hash"] == "0xC3" and it["direction"] == "TOKEN_ONLY"
               for it in report.contract_interactions), "TOKEN_ONLY 行应该存在"
    only = [it for it in report.contract_interactions if it["tx_hash"] == "0xC3"][0]
    assert only["method_id"] == "0xbc4a02e4", f"method_id 必须保留原值，got={only['method_id']}"
    assert only["method_label"] == "unknown(0xbc4a02e4)", \
        f"未知 selector 必须以 unknown(0x..) 形式标注，got={only['method_label']}"
    eff = only["token_effects"][0]
    assert eff["from"] and eff["to"], "每个 effect 都必须有 from/to"
    assert eff["direction"] == "IN", "0xC3 应被识别为 IN（Safe 多签转入）"
    print("  ✓ 不变量全部满足")

    print("\n[3] print_contract_interactions 视觉效果")
    print_contract_interactions(report, limit=10)


if __name__ == "__main__":
    main()
