# Stablecoin Traceability Pilot Experiment

## Purpose

This lightweight pilot tests whether cached stablecoin transfer records can be converted into explainable traceability evidence. It does not attempt full-chain surveillance or large-scale AML classification.

## Input Data

- Cached address files: 150
- Seed labels: {'blocklisted': 100, 'normal': 50}
- Parsed non-protocol counterparty edges: 40807
- Unique non-protocol counterparties: 12028
- Registry entries loaded: 2911

Protocol contracts and zero-address placeholders were excluded before matching, including USDT, USDC, and `0x000...000`.

## Results

- Direct risk/boundary evidence rows: 107
- Seeds with at least one direct evidence hit: 14 / 150
- Normal-labeled seeds with direct evidence hit: 1 / 50
- Evidence categories: {'risk_anchor': 105, 'traceability_continuation': 2}
- Traceability outcomes: {'anchor': 105, 'continue': 2}

## Illustrative Cases

### Traceability continuation case

A normal-labeled seed `0x04a8f552e6d13fd00def492d243198e841a8f107` had an IN USDC transfer with `0xea749fd6ba492dbc14c24fe8a3d08769229b896c` (Traceable bridge: SquidRouter v2 (Axelar)). This is not itself a risk anchor; it is evidence that bridge classification is needed to decide whether tracing can continue across chains.

- Amount: 97.561809
- Date UTC: 2024-07-07
- Transaction: `0xfb1fef77c29914700e20e714554a9e93e755bc28bef79e4aaa5f968fea9c808d`

### Direct risk-anchor case

Seed `0x0012da9ac0dc5f5df0179e606b9759c3394f5b21` (blocklisted) had a direct OUT transfer with `0x6fbd9cd84bb87393acc20ce666702dce8a998e02` (USDT blacklist). This demonstrates a simple one-hop traceable link to a known anchor.

- Amount: 810000.0 USDT
- Date UTC: 2023-09-07
- Transaction: `0xa5f67be4ed2ee646cc8af8ec0e673806e5b9618eb60e1715d98811cee8c100d6`

### Highest-evidence seed

The seed with the most direct evidence rows was `0x02a750266ea16ad4f4d02556822503a1658cd5c4` with 52 matched counterparty transfers.

## Interpretation for Report 2

The pilot supports a modest but useful claim: stablecoin transfer logs can be used to construct bounded traceability evidence on a laptop. The experiment also shows why traceability classification matters: blacklist/OFAC entries act as anchors, and traceable bridges indicate possible cross-chain continuation. This particular cached sample did not contain direct mixer or opaque-bridge matches after protocol-address filtering, but the registry explicitly treats those mechanisms as tracing boundaries. The current data is only a pilot sample, so it should not be presented as a full evaluation.
