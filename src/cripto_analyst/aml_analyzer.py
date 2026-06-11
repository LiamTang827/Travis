#!/usr/bin/env python3
"""Travis — TRAceable Verification Intelligence System（向后兼容转发层）

原 2888 行单体已于 2026-06-11 按职责拆分：

  config.py        全局配置、风险类别权重、统一等级阈值 risk_level()
  chains.py        ChainConfig / EVM_CHAIN_REGISTRY / EVMClient / TronScanClient
  utils.py         Base58、normalize、load_blacklist、detect_chain
  bridge_tracer.py BridgeTracer（生效的跨链桥对端解析）
  models.py        RiskIndicator / RiskReport 数据模型
  analyzer.py      AMLAnalyzer 核心引擎（比例 taint 评分）
  reporting.py     终端报告输出 / JSON 导出
  cli.py           命令行入口 main()

旧 import 路径（from cripto_analyst.aml_analyzer import X）全部继续可用。
注意：BRIDGE_TRACE_ENABLED / HOP2_ENABLED 两个运行时开关请通过 analyzer
模块设置（trace_graph 已切换）；通过本 shim 设置不会生效。
"""

from .config import (                                      # noqa: F401
    PROJECT_ROOT, BLACKLIST_CSV, ETHERSCAN_API_KEY,
    REQUEST_DELAY, PAGE_SIZE, MAX_PAGES, MAX_TX_FETCH,
    CATEGORY_WEIGHTS, HOP_DECAY, STABLECOIN_SYMBOLS,
    KNOWN_METHOD_SELECTORS, decode_method,
    RISK_LEVEL_THRESHOLDS, risk_level,
)
from .chains import (                                      # noqa: F401
    ChainConfig, EVM_CHAIN_REGISTRY, EVMClient, EtherscanClient,
    TronScanClient, CHAIN_SCANNERS, LZ_CHAIN_MAP,
    KNOWN_DEX_ADDRS, TRON_BRIDGE_CONTRACTS_HEX,
)
from .utils import (                                       # noqa: F401
    normalize, hex_to_tron_base58, load_blacklist, detect_chain,
)
from .bridge_tracer import BridgeTracer                    # noqa: F401
from .models import RiskIndicator, RiskReport              # noqa: F401
from .analyzer import (                                    # noqa: F401
    AMLAnalyzer, BRIDGE_TRACE_ENABLED, HOP2_ENABLED,
)
from .reporting import (                                   # noqa: F401
    print_report, print_transactions, print_contract_interactions,
    export_json, LEVEL_COLORS,
)
from .threat_intel import (                                # noqa: F401
    MIXER_CONTRACTS, BRIDGE_REGISTRY, ALL_BRIDGE_ADDRS, OPAQUE_BRIDGE_ADDRS,
    EXCHANGE_HOT_WALLETS, HIGH_RISK_EXCHANGES, HIGH_RISK_EXCHANGES_FLAT,
    EXCHANGE_HOT_WALLETS_FLAT, ALL_EXCHANGE_ADDRS, DEPOSIT_DETECTION_PARAMS,
    OFAC_SANCTIONED, OFAC_SANCTIONED_ADDRS,
)
from .cli import main                                      # noqa: F401

if __name__ == "__main__":
    main()
