# Tron TRC-20 USDT Trace Case

## Claim

This case exercises the Tron data surface (account model, base58 addresses, TronGrid/TronScan APIs). It confirms TRC-20 USDT token-level evidence and, where present, a known Tron-side bridge gateway. Honest by design: it does not fabricate a destination when the BTTC bridge mapping is not publicly resolvable from the Tron transaction alone.

- Classification: token-level TRC-20 evidence (no known bridge counterparty in this tx)
- Source tx: `37e003f8caf7c751a1d1e120ca9cd0ac4ad815936c8707a0408c9b8904754646`
- Source explorer: https://tronscan.org/#/transaction/37e003f8caf7c751a1d1e120ca9cd0ac4ad815936c8707a0408c9b8904754646
- USDT TRC-20 transfers found: 1
- Bridge counterparty: None
- Destination resolved: `False`

## Note

BTTC / Tron bridge destination resolution requires the bridge indexer; no public one-to-one source-to-destination mapping was resolved from the Tron transaction alone.
