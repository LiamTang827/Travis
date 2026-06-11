# Across USDC Bridge Trace Case

## Claim

This is one completed deterministic/protocol-assisted stablecoin bridge trace instance. The source-chain event gives the destination chain, deposit ID, depositor, recipient, and amount. Across' status API then links the deposit transaction to the destination fill transaction.

## Source Event

- Bridge: Across Protocol V3
- Classification: protocol-assisted traceable bridge
- Origin chain: ethereum (1)
- Source tx: `0x024b2b3cfffddb12ef9b93da592f1ec754c457281b11be4e24324cd26359b3f5`
- Source explorer: https://etherscan.io/tx/0x024b2b3cfffddb12ef9b93da592f1ec754c457281b11be4e24324cd26359b3f5
- Event: `V3FundsDeposited`
- Deposit ID: `1502687`
- Depositor: `0xcb9055fc2a8f0f27041dc238574100a22df0c15e`
- Recipient: `0xcb9055fc2a8f0f27041dc238574100a22df0c15e`
- Destination chain: arbitrum (42161)
- Input: 40000.012359 USDC (40000012359 raw)
- Output: 39996.803276 USDC (Arbitrum) (39996803276 raw)

## Destination Fill

- Status: `filled`
- Destination tx: `0x5f81158cdd5c0ea56c50c6ddbea411e1a08ca031c56fcf057cddc60b0c1cd7ee`
- Destination explorer: https://arbiscan.io/tx/0x5f81158cdd5c0ea56c50c6ddbea411e1a08ca031c56fcf057cddc60b0c1cd7ee
- Destination receipt observed: `True`
- Destination block: `246291987`
- Destination tx sender/relayer: `0x07ae8551be970cb1cca11dd7a11f47ae82e70e67`

## Evidence Used

- source Ethereum transaction receipt
- Across V3FundsDeposited event topic
- indexed destinationChainId
- indexed depositId
- indexed depositor
- non-indexed recipient in event data
- Across `/deposit/status` API queried by both deposit transaction hash and originChainId+depositId
- Destination-chain transaction receipt fetched through Etherscan V2 multi-chain API

## Report Interpretation

This case should be described as a protocol-assisted traceable stablecoin bridge. It is stronger than a registry-only bridge interaction because the Across event exposes the destination chain and recipient, and the Across status API returns the destination fill transaction. It is not based on time-window or amount-similarity heuristics.
