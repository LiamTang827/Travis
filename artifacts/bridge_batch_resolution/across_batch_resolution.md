# Across Batch Stablecoin Bridge Resolution

## Setup

- Bridge: Across Protocol V3
- Source chain: ethereum
- Block window: 20600000 to 20602000
- Raw V3FundsDeposited events: 445
- Stablecoin candidate events: 66
- Verified candidate limit: 20

## Results

- Verified candidates: 20
- Resolved with destination fill tx: 20
- Status counts: `{'filled': 20}`
- Candidate destination chains: `{'arbitrum': 28, 'polygon': 13, 'base': 12, 'linea': 3, 'optimism': 10}`
- Candidate input tokens: `{'USDC': 50, 'USDT': 16}`

## Verified Cases

- depositId `1502687`: 40000.012359 USDC to arbitrum / status `filled` / fill `0x5f81158cdd5c0ea56c50c6ddbea411e1a08ca031c56fcf057cddc60b0c1cd7ee` / tx `0x024b2b3cfffddb12ef9b93da592f1ec754c457281b11be4e24324cd26359b3f5`
- depositId `1502695`: 927.000000 USDC to arbitrum / status `filled` / fill `0x86380b3e6987b6ab115adab215bf83987dc7f046bd08c2468dc687ca6648fff4` / tx `0x41579dcf84f538df7918e3a0d7c97262df53703f17f01c903d8b6821a7d28f5a`
- depositId `1502709`: 1090.454300 USDC to polygon / status `filled` / fill `0xf077a138ff7ece7d443d01c2cf932a23863cb195303d1250ae521db3f3f16dca` / tx `0xba42b3085cd4e12d179f3e4cca9dfeffc565491856fd57e3ec6cc715112f5cde`
- depositId `1502714`: 20000.018195 USDC to base / status `filled` / fill `0x6ac570f2483a40383df0bb76620751397eae1e03a3ab86806cf2b737122ce059` / tx `0xf3e62e815fabffcb9c0669cfc3f8efd6d4f8033b8e5d58bed2838edcda325086`
- depositId `1502720`: 63.935625 USDT to linea / status `filled` / fill `0x8def6c9c810979fe6eafa86cc574f894dafacf744e29009685ec5b89991718de` / tx `0xb6844c6365ce8a81ed9537d5f1273a562f6ab7296d40aec848e5134dde3928e8`
- depositId `1502739`: 1930.432000 USDC to base / status `filled` / fill `0x5aa2169db43e4c4e7ddfcd8918674849d97e83727e7985825a18c5fd85ee79c3` / tx `0x80082c712d740857b730a7d4e77895a64954dd5a5d1ddadc0fdcb2e168ad9e5e`
- depositId `1502742`: 3078.000000 USDC to arbitrum / status `filled` / fill `0x16748638a89592febe623fca6a40fcaa4cb503f1ca868d46fee770105b4ca993` / tx `0x83e497ea66196d725b0953c34e74851bef72cc8052838e5bc4b592845aa6ef12`
- depositId `1502743`: 200.000000 USDC to optimism / status `filled` / fill `0xd8688adf1f5332ef7d2dfa4b752bd6896bc75d4a0da22343952402eead5dedec` / tx `0xfc64261099c60c99bc6c5513a9b45a8464824a1e07bd113df170eacae08adc10`
- depositId `1502745`: 3059.014969 USDC to arbitrum / status `filled` / fill `0x5a060c8a6b488aabf5ef1de1b0f41b6bb94f275d54c280d8f89bccc1aee06509` / tx `0x5ae6018844746e2689f524d68679a6adcb176be11edc2b0b4158506f45461ce0`
- depositId `1502763`: 2500.000000 USDC to base / status `filled` / fill `0xd891c472aa26f2b219e111763b3a32df1ba58fff61a22135bbda381ff166caf1` / tx `0xd478925e13a8bae59c91bc5d53d6c75306388b0b7c5a150d4ac7c591ce347a5d`
- depositId `1502769`: 34.000000 USDC to arbitrum / status `filled` / fill `0x98acbff9a69de219a41569fb7a8cf6aa03ab3235e43d6626c8468b4c6c7dd03f` / tx `0x3adde3dc2d03f73fa5d09bf54f28fe776327e06c2520b53af4897507f1e5334f`
- depositId `1502774`: 92.077828 USDC to arbitrum / status `filled` / fill `0x77ab29a4d91190877da513c47500e54a8d890725ad9542e0c79091429abb0f96` / tx `0x82a4ac58399d90ec4eecf9771294e539e89a66fb70b4e12575215dce28dbf4e0`
- depositId `1502775`: 20.989500 USDT to optimism / status `filled` / fill `0xfecef392f4317b8824b78788d2492429461cbcf72aeeb30a673dd167e70b3c3f` / tx `0x968b43b3aa013859cdbad6c227b944818d441f4f779008cfa9b9f76778c737f7`
- depositId `1502780`: 23.477771 USDC to polygon / status `filled` / fill `0x149be2253bd143c12bda39fd618e838bf79a8aecbadeaa8781e1a399bc4ce050` / tx `0x6b194d3d065ac1226eda5b79919e9cba6f24c56559084ead91ad46bb37de7a7c`
- depositId `1502788`: 167.000000 USDC to optimism / status `filled` / fill `0xcf5cafa9637189edc3eb484b94a84b018c29b340f791251ea0829bcce717402a` / tx `0xc06d7da31f58d12a859f946d46efe4b28d425e7b2eca04afd03200822d870bf4`
- depositId `1502792`: 760.574676 USDC to optimism / status `filled` / fill `0xcf10328d459fb43a30785b16fcde3709a7e283872c2a5f7049ff3fad3798dbe7` / tx `0xbc7f694b4e8995d2c703c1f09fd8399770be9bbe4b2fafdd475bd07f115ee09a`
- depositId `1502799`: 5303.374400 USDC to arbitrum / status `filled` / fill `0xed7a2efc3cdfab83deceb817d952182c5309244a53d23bf7db798a182effd496` / tx `0x4e7c658d8e6c75edacfc375f5b6635243292d397a763cb17d9e2e1795e2ecaca`
- depositId `1502807`: 22.238944 USDC to polygon / status `filled` / fill `0xe3267e71f52ec14178fd906ff0e949372aaa4e4e8d09965f0ec00c6943c940fe` / tx `0x1f3775089b449f4c9cab886f2061f336e8dca205366b6a12b74f4489cd9651a1`
- depositId `1502809`: 129.675000 USDC to arbitrum / status `filled` / fill `0x1de68554898d8724593588fdd9268655ce98c557792cabfed5065b1bc1201d67` / tx `0x22c79b4eaae9136c1c7a30dbc64052513946fb6ca1c3de5b8f3265ef834c59d7`
- depositId `1502814`: 17.099121 USDC to base / status `filled` / fill `0xee4ffbb4ac8cbf69f59a22454303dd23f123c7934feaabb446b3c4f700483fcd` / tx `0xe8b16c9bf9a657a5f02b282cb8beebbea96fe3810a1f60abb99d1801d05ba30c`

## Interpretation

This batch experiment tests whether the Across resolver works beyond a single hand-picked transaction. It scans a fixed block window, filters stablecoin deposit events, and verifies a bounded sample through Across' public status API.
The experiment is still protocol-specific, but it is stronger than a single case study because it applies the same resolver logic to multiple public stablecoin bridge events in a bounded block range.
