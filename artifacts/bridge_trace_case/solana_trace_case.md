# Solana Cross-Chain USDC Trace Attempt

- Classification: registry-only (Solana CCTP/Wormhole program identified)
- Source signature: `ZjwXLPkiEJb5D4Z9rWFdNL8U7f35PuvPicnjqLW2sfBch5CpgbmnidnfMyyG8WqAEdXNKhRmKhuJQ5WpGuzwgkE`
- Explorer: https://solscan.io/tx/ZjwXLPkiEJb5D4Z9rWFdNL8U7f35PuvPicnjqLW2sfBch5CpgbmnidnfMyyG8WqAEdXNKhRmKhuJQ5WpGuzwgkE
- Program hits: [{'programId': 'CCTPV2Sm4AdWt5296sk4P66VBZ7bEhcARwFaaS9YPbeC', 'name': 'Circle CCTP V2 MessageTransmitter'}, {'programId': 'CCTPV2vPZJS2u2BBsUoscuikbYjnpFmbFsvVuJdgUMQe', 'name': 'Circle CCTP V2 TokenMessengerMinter'}]
- Instruction names: ['HandleReceiveUnfinalizedMessage', 'ReceiveMessage']
- USDC SPL touch: True
- Destination resolved: False

## Note

This completed Solana surface case observes a real CCTP/Wormhole-style transaction through public Solana RPC, records the invoked cross-chain program(s), instruction names, and SPL USDC token-balance touch. The counterparty chain is not inferred unless a message nonce/sequence and attestation/VAA are explicitly recovered; the unresolved hop is therefore recorded as an evidence boundary rather than a future-script placeholder.
