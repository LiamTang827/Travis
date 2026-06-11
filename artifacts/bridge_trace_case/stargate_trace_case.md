# Stargate / LayerZero Bridge Trace Case

## Claim

This is a message-passing bridge trace via LayerZero. The source-chain transaction interacts with a known Stargate/LayerZero contract; LayerZero Scan then maps the source message to the destination delivery transaction; the destination receipt is fetched to re-anchor that claim on-chain.

## Source

- Bridge family: Stargate (LayerZero)
- Classification: protocol-assisted traceable bridge
- Source tx: `0x5955c3c28ee325ae6570793afd7ffb6c4b8416543f4695c739db95b7455485a1`
- Source explorer: https://etherscan.io/tx/0x5955c3c28ee325ae6570793afd7ffb6c4b8416543f4695c739db95b7455485a1
- Matched known contract: `0x1a44076050125825900e736c501f859c50fe728c`

## Destination (protocol-assisted, via LayerZero Scan)

- Resolved: `True`
- LayerZero status: `DELIVERED`
- Destination chain: arbitrum
- Destination tx: `0xc47406642e25a128e66a16c61888856d332abf153e3d94273fbe21fed91cfd16`
- Destination explorer: https://arbiscan.io/tx/0xc47406642e25a128e66a16c61888856d332abf153e3d94273fbe21fed91cfd16
- Destination receipt observed: `True`

## Evidence Strength (trustless--trusted--trustless)

- Source step: trustless (Ethereum receipt + known Stargate/LayerZero contract)
- Bridge step: trusted (LayerZero Scan API maps source message to destination tx)
- Destination step: trustless (destination receipt re-anchors the API claim)

## Report Interpretation

If `resolved=true`, this is a second protocol-assisted bridge case using a different mechanism (message-passing) and a different indexer (LayerZero Scan) than the Across liquidity-fill case, supporting the generality of the evidence-first model. If `resolved=false`, this is honestly a registry-only interaction: the contract is identified but the destination is not yet linked, which is itself a valid evidence-first outcome.
