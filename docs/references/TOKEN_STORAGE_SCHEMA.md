# Token storage schema (local node only)

Token configs are stored per node in the `LocalTokenConfig` collection. They are **not** propagated to other nodes. The structure is keyed by `chainType` and then by `chainId`; each (chainType, chainId) document holds token-type entries (e.g. ERC20, ERC721) with `transferSig` / `transferNames` and a `contracts` array.

## Response shape: `GET /getTokens`

The API returns data in this form (grouped by chain type). `chainId` is always a string (normalized from number or string in requests).

```json
{
  "ethereum": [
    {
      "chainId": "1234",
      "ERC20": {
        "transferSig": "transfer(address,uint256)",
        "transferNames": ["to", "amount"],
        "contracts": [
          {
            "contractAddress": "0x1234567890123456789012345678901234567890",
            "name": "just mytoken",
            "symbol": "NUT",
            "symbolURL": "https://...",
            "decimals": 18
          },
          {
            "contractAddress": "0x8887761890123456789012345678901234567890",
            "name": "worldwide mytoken2",
            "symbol": "BALL",
            "symbolURL": "https://...",
            "decimals": 6
          }
        ]
      },
      "ERC721": {
        "transferSig": "transferFrom(address,address,uint256)",
        "transferNames": ["from", "to", "tokenId"],
        "contracts": [
          {
            "contractAddress": "0xabcdef1234567890123456789012345678901234",
            "name": "myNFT1",
            "symbol": "GGT",
            "tokenURI": "https://xxxxxxxx.com/hhhhhhh"
          },
          {
            "contractAddress": "0xabcdeaaa34567890123456789012345678901234",
            "name": "myNFT2",
            "symbol": "AAA",
            "tokenURI": "https://xxyyyddxx.com/hjjjhh"
          }
        ]
      },
      "CTMERC20": {
        "transferSig": "c3transfer(string,uint256,string)",
        "transferNames": ["toStr", "amount", "toChainIdStr"],
        "contracts": [
          {
            "contractAddress": "0x123aa347890123456789012345678901234567890",
            "name": "new token",
            "symbol": "YYR",
            "symbolURL": "https://..."
          }
        ]
      },
      "CTMRWA1": {
        "transferPartialSig": "transferPartialTokenX(uint256,string,string,uint256,uint256,uint256,string)",
        "transferPartialNames": ["fromTokenId", "toAddressStr", "toChainIdStr", "value", "ID", "version", "feeTokenStr"],
        "transferWholeSig": "transferWholeTokenX(string,string,string,uint256,uint256,uint256,string)",
        "transferWholeNames": ["fromAddrStr", "toAddressStr", "toChainIdStr", "fromTokenId", "ID", "version", "feeTokenStr"],
        "contracts": []
      }
    },
    {
      "chainId": "7654",
      "ERC20": {
        "transferSig": "transfer(address,uint256)",
        "transferNames": ["to", "amount"],
        "contracts": [
          {
            "contractAddress": "0x1234667890123456789012345678901234567890",
            "name": "mytoken",
            "symbol": "AAA",
            "symbolURL": "https://...",
            "decimals": 18
          },
          {
            "contractAddress": "0x8887761890123456789012345678901234567890",
            "name": "yst",
            "symbol": "BBBU",
            "symbolURL": "https://...",
            "decimals": 6
          },
          {
            "contractAddress": "0x8888861890123456789012345678901234567890",
            "name": "mytok",
            "symbol": "XT",
            "symbolURL": "https://..."
          }
        ]
      },
      "ERC721": {
        "transferSig": "transferFrom(address,address,uint256)",
        "transferNames": ["from", "to", "tokenId"],
        "contracts": [
          {
            "contractAddress": "0xabcd456aa3456789012345678901234567890e2f",
            "name": "myNFT3",
            "symbol": "MYHAT",
            "tokenURI": "https://xxya3tyddxx.com/hjddhh"
          }
        ]
      },
      "CTMERC20": {
        "transferSig": "c3transfer(string,uint256,string)",
        "transferNames": ["toStr", "amount", "toChainIdStr"],
        "contracts": [
          {
            "contractAddress": "0x22deaa347890123456789012345678901234567890",
            "name": "another new token",
            "symbol": "HR",
            "symbolURL": "https://..."
          }
        ]
      }
    }
  ],
  "solana": [],
  "near": [],
  "stellar": [],
  "ton": []
}
```

Note: `chainType` is stored and returned in lowercase (e.g. `ethereum`, `solana`, `near`, `stellar`, `ton`) for consistent lookup.

## Contract fields by token type

| tokenType   | Required in contract        | Optional / notes |
|------------|-----------------------------|------------------|
| ERC20      | contractAddress             | name, symbol, symbolURL (can be ""), decimals (number) |
| ERC721     | contractAddress             | name, symbol, tokenURI |
| CTMERC20   | contractAddress             | name, symbol, symbolURL, decimals (number) |
| CTMRWA1 | contractAddress             | name, symbol, symbolURL; transfer sigs set by server (see below) |

## CTMRWA1 transfer signatures (CTMRWA1X.sol)

For **CTMRWA1**, the server sets two transfer descriptors from **CTMRWA1X.sol**:

- **Partial value transfer** — `transferPartialTokenX`: transfer part of the fungible balance of a tokenId to an address (same or other chain).
  - `transferPartialSig`: `"transferPartialTokenX(uint256,string,string,uint256,uint256,uint256,string)"`
  - `transferPartialNames`: `["fromTokenId", "toAddressStr", "toChainIdStr", "value", "ID", "version", "feeTokenStr"]`

- **Whole token transfer** — `transferWholeTokenX`: transfer a whole tokenId to an address (same or other chain).
  - `transferWholeSig`: `"transferWholeTokenX(string,string,string,uint256,uint256,uint256,string)"`
  - `transferWholeNames`: `["fromAddrStr", "toAddressStr", "toChainIdStr", "fromTokenId", "ID", "version", "feeTokenStr"]`

Here `ID` is the RWA token ID, `version` is the RWA contract version; addresses and chain IDs are passed as strings for cross-chain use.

## chainType and chainId

- **chainType**: e.g. `ethereum`, `solana`, `NEAR`, `stellar`, `TON`. Stored lowercase for lookup; new chain types can be added.
- **chainId**: For Ethereum typically an integer in the request; for others often a string. Always normalized to a string in storage and in the response.

## Adding and removing tokens

- **POST /addToken**: Send `chainType`, `chainId`, `tokenType`, and `contract` (with at least `contractAddress`). For ERC721, include `tokenId` in the contract; the same (chainType, chainId, tokenType, contractAddress, tokenId) is updated if it exists, otherwise the contract is appended. **Agents:** For token types that store **`decimals`** (e.g. **ERC20**, **CTMERC20**), you **must** obtain the correct decimals from the **user or operator** (or from authoritative on-chain reads the user approves). **Do not** assume or default to **18**—many tokens use 6, 8, or other values; wrong decimals corrupt amounts and UX.
- **POST /removeToken**: Send `chainType`, `chainId`, `tokenType`, and `contractAddress` to remove that contract from the list. For **ERC721**, `tokenId` is required: only the contract entry with that `contractAddress` and `tokenId` is removed.

Both endpoints require management key signature (same as `postChainDetails` / `removeChainDetails`).
