# Known Addresses schema (local node only)

Known addresses are stored per node in the `LocalKnownAddresses` collection. They are **not** propagated to other nodes. Each document represents one address for one chain type, with optional network restrictions (**`chainIds`**) and optional spend / account classification.

## Storage model

- **Collection**: `LocalKnownAddresses`
- **Unique key**: `(chainType, address)` — one document per address per chain type. The same address string can appear in multiple documents for different chain types (e.g. one for `ethereum`, one for `bitcoin`).
- **Index**: Unique index on `(chainType, address)` for fast lookup and upsert.
- **Normalization** (server-side): The pair `(chainType, address)` stored in Mongo is canonicalized so lookups and removals stay stable (**see §Address normalization**).

## Document shape

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `chainType` | string | yes | Chain family (e.g. `"ethereum"`, `"solana"`, **`"bitcoin"`**). Stored lowercase. |
| `address` | string | yes | Canonical address string for that chain (**normalized** server-side — see below). |
| `name` | string | no | Display label for operators / UI. |
| `chainIds` | []string | yes | Networks on which this entry is intended to apply; **empty** = **no restriction** (any network of this `chainType`). For Bitcoin, prefer the **`bitcoin-<network>`** convention below; other chains keep existing conventions (`"1"` for Ethereum mainnet, `"mainnet-beta"` for Solana, etc.). List elements trimmed; for **`chainType`** **`bitcoin`** they are stored **lowercase**. |
| `isContract` | bool | yes | Ethereum-style: **`true`** = contract, **`false`** EOA. For **bitcoin simple payment recipients** normally **`false`**. Scripts / multisigs are not modeled as Solidity contracts — use **`addressSubtype`** + **`name`** instead of flipping this flag without product agreement. |
| `addressSubtype` | string | no | Spend / encoding hint. **Mandatory for rich Bitcoin UX** once you differentiate SegWit vs Taproot; empty or omitted means “unspecified” (backward compatible). For **`chainType`** **`bitcoin`**, allowed values when set are: **`p2pkh`**, **`p2sh`**, **`p2sh-p2wpkh`**, **`p2wpkh-v0`**, **`p2tr`**, **`unknown`**. Invalid values are rejected by **`POST /addKnownAddress`**. Other **`chainType`** values **may reuse this field later**; today they are accepted as arbitrary trimmed strings without server validation. Stored as provided (bitcoin subtypes lowered). |
| `updatedAt` | string | yes | ISO 8601 UTC timestamp of last upsert. |

## Address normalization (unique key correctness)

Because Mongo keys on raw `address`:

| Chain | Rule |
|-------|------|
| **Ethereum** (and anything starting with **`0x`**) | **`0x` + lowercase hex.** |
| **Bitcoin — Bech32 / Bech32m** (**`bc1…`**, **`tb1…`**, **`bc1p…`**, **`tb1p…`**) | Entire string **trimmed**, then **`ToLower`** (BIP‑173 / BIP‑350 human-readable part conventions + stable keys). Matches how **SegWit v0 MPC P2WPKH** helpers encode addresses (**`bitcoinp2wpkhtestnet`** overlaps Signet **`tb`** in **btcd** — same rule here). |
| **Bitcoin — legacy Base58** (**`1…`**, **`3…`**) | **Trim only.** Base58 checksums are **case-sensitive**; **never lowercase** blindly. |

**Recommendation:** Prefer storing **canonical Bech32** outputs from your indexer / **`btcutil.DecodeAddress`** (round-trip encoded) rather than MixedCase user paste; the server lowercases **`bc*` / `tb*`** prefixes only — **mixed-case Bech32 is invalid protocol-wise** anyway.

Optional hardening later: **`POST /addKnownAddress`** could **reject** malformed Bech32 by decoding (**`btcutil.DecodeAddress`** + **`chaincfg`**) instead of casing alone.

### Bitcoin `chainIds` convention (recommended)

So **`GET /getKnownAddresses?chain_id=…`** matches predictably:

| Network | Suggested `chainIds` token |
|---------|----------------------------|
| Mainnet | `bitcoin-mainnet` |
| Testnet (TestNet3) | `bitcoin-testnet` |
| Signet | `bitcoin-signet` |
| Regtest | `bitcoin-regtest` |

Empty **`chainIds`** = allowlist applies to transfers on **any** Bitcoin network configured in product (narrow in UI if needed).

### Bitcoin `addressSubtype` (SegWit now, Taproot next)

Use **`addressSubtype`** so frontends render icons / route to the right MPC signing flow without inferring witness version from prefix alone (prefix is almost enough, but explicit helps audits):

| Value | Meaning |
|-------|---------|
| `p2wpkh-v0` | Native SegWit v0 P2WPKH (**ECDSA MPC path** documented in `BITCOIN_MPC_EVALUATION.md`). |
| `p2tr` | **Taproot** pay-to-taproot output (**witness v1**). **Signing today:** threshold ECDSA MPC does **not** cover BIP 340 Schnorr alone — reserve this for **threshold Schnorr (e.g. FROST)** or mark **`unknown`** until implemented. Listing Taproot addresses is still useful as an allowlist label. |
| `p2sh-p2wpkh` | Wrapped SegWit (**P2SH** enclosing P2WPKH). ECDSA MPC same as **`p2wpkh-v0`** at key level; different script envelope. |
| `p2pkh` | Legacy uncompressed/compressed ECDSA (**non-SegWit**). Same curve; sighash semantics differ (**pre-BIP143** on non-segwit inputs). |
| `p2sh` | Generic **`3…`** (unknown inner script — policy / treasury). |
| `unknown` | Human allowlist entry when script type unclear. |

**Taproot spend planning:** Backend does **not** need a second collection today; **extend** enums / validation when you add Schnorr signing (e.g. optional **`signingScheme`**: `ecdsa | bip340` on the **sign** path, not necessarily on known addresses — but you **may** add **`addressSubtype`-dependent** UI checks).

## Example documents

### Ethereum (unchanged)

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

### Bitcoin — native SegWit v0 (MPC / P2WPKH)

```json
{
  "chainType": "bitcoin",
  "address": "bc1qm8kh3fp58gs593p6y7wfduznjchlajmrkl78p8",
  "name": "Ops hot wallet",
  "chainIds": ["bitcoin-mainnet"],
  "isContract": false,
  "addressSubtype": "p2wpkh-v0",
  "updatedAt": "2026-05-11T12:00:00Z"
}
```

### Bitcoin — Taproot (allowlist only until Schnorr MPC)

```json
{
  "chainType": "bitcoin",
  "address": "bc1p…",
  "name": "Treasury P2TR (future FROST)",
  "chainIds": ["bitcoin-mainnet"],
  "isContract": false,
  "addressSubtype": "p2tr",
  "updatedAt": "2026-05-11T12:00:00Z"
}
```

### Solana (unchanged)

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

## API

- **`GET /getKnownAddresses`** — Returns known addresses **grouped by `chainType`**. Optional query params: **`chain_type`**, **`chain_id`**, **`is_contract`** (`0` or `1`). Each entry includes **`address`**, **`name`**, **`chainIds`**, **`isContract`**, **`updatedAt`**, and **`addressSubtype`** when present.
- **`POST /addKnownAddress`** — Upsert (body: **`chainType`**, **`address`**, optional **`name`**, **`chainIds`**, **`isContract`**, optional **`addressSubtype`**, management auth). **`addressSubtype`** validated when **`chainType`** is **`bitcoin`**.
- **`POST /removeKnownAddress`** — Remove by **`chainType`** + **`address`** (same normalization as add — use the same canonical string the UI got from **`GET`**).

All endpoints are **local to the node**; no cross-node replication.

## API evolution notes (optional next steps)

- **`GET /getKnownAddresses?address_subtype=p2tr`** — not implemented yet; add if allowlists grow large.
- **Strict Bech32 decode** on write — stronger than casing-only normalization.
- **Cross-field checks:** e.g. reject **`addressSubtype: p2tr`** if address does not decode as witness v1 (optional product rule).
