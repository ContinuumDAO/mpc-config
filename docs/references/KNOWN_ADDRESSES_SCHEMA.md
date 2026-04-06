# Known Addresses schema (local node only)

Known addresses are stored per node in the `LocalKnownAddresses` collection. They are **not** propagated to other nodes. Each document represents one address for one chain type, with optional chainId restrictions and an EOA vs contract flag.

## Storage model

- **Collection**: `LocalKnownAddresses`
- **Unique key**: `(chainType, address)` — one document per address per chain type. The same address value can appear in multiple documents for different chain types (e.g. one for `ethereum`, one for `solana`).
- **Index**: Unique index on `(chainType, address)` for fast lookup and upsert.

## Document shape

| Field       | Type     | Required | Description |
|------------|----------|----------|-------------|
| `chainType` | string   | yes      | Chain type (e.g. `"ethereum"`, `"solana"`). Stored lowercase. |
| `address`   | string   | yes      | The address (normalized: e.g. lowercase for Ethereum). |
| `name`      | string   | no       | Display name for the address. |
| `chainIds`  | []string | yes      | List of chain IDs this address is valid on for this chain type. **If empty, there are no restrictions** — the address is considered valid on all chains of that type. |
| `isContract`| bool     | yes      | `true` = contract address; `false` = EOA (Externally Owned Account). |
| `updatedAt` | string   | yes      | ISO 8601 timestamp of last update. |

## Example documents

```json
{
  "chainType": "ethereum",
  "address": "0x1234567890123456789012345678901234567890",
  "name": "My Wallet",
  "chainIds": ["1", "137"],
  "isContract": false,
  "updatedAt": "2025-03-10T12:00:00Z"
}
```

```json
{
  "chainType": "ethereum",
  "address": "0xabcdef123456789012345678901234567890abcd",
  "name": "USDC Contract",
  "chainIds": [],
  "isContract": true,
  "updatedAt": "2025-03-10T12:05:00Z"
}
```

```json
{
  "chainType": "solana",
  "address": "So11111111111111111111111111111111111111112",
  "name": "Wrapped SOL",
  "chainIds": ["mainnet-beta"],
  "isContract": false,
  "updatedAt": "2025-03-10T12:10:00Z"
}
```

## Semantics

- **chainType**: Same convention as tokens/chains (e.g. `ethereum`, `solana`, `near`, `stellar`, `ton`). Stored and compared in lowercase.
- **chainIds**: For Ethereum typically numeric strings (`"1"`, `"137"`); for Solana might be `"mainnet-beta"`, `"devnet"`, etc. Empty array = no restriction (valid on any chain of that type).
- **isContract**: When `false`, the address is an EOA; when `true`, it is a contract. Used by callers for validation or UI (e.g. warning when sending to a contract).

## API

- **GET /getKnownAddresses** — Returns all known addresses, grouped by chain type. Optional query params: `chain_type`, `chain_id`, `is_contract` (0 or 1; 1 = contracts only, 0 = EOAs only).
- **POST /addKnownAddress** — Add or update a known address (body: `chainType`, `address`, `name` (optional), `chainIds`, `isContract`; requires management auth).
- **POST /removeKnownAddress** — Remove a known address by `chainType` and `address` (requires management auth).

All endpoints are local to the node; no cross-node sharing.
