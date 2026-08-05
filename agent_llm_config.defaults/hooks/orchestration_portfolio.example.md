## Orchestration portfolio assessment (Plan → sub-agents)

Use with skill **`orchestration_planning`** for **`mode: portfolio`** / “Assess my portfolio…”. Plan chat drafts the manifest only; specialists post **`mpc-task-result v1`** on KeyGen.

Split into **~3 leaves**. The middle leaf must recover **performance statistics** for staked / perps / lending exposure where Continuum MCP tools return them (not invented).

```yaml
# mpc-orchestrate v1
tasks:
  - id: portfolio-wallet-inventory
    prompt: |
      Inventory KeyGen balances on every configured chainId via agent_get_balance
      (native + key ERC-20s/LSTs: ETH, stables, stETH/wstETH, …).
      Table by chain/asset (human amounts). Include venue cash wallets if HL/Arcus packs are loaded.
      No USD pricing required. No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 12
      maxWallClockMs: 180000
      maxChildSpawns: 0

  - id: portfolio-protocol-performance
    prompt: |
      Recover live performance for protocol exposure (continuum__load_defi_protocol as needed).
      Perps (Hyperliquid / GMX / Arcus): ctm_*_fetch_positions (+ open/account context when useful).
      Report size/side, entry/mark, unrealized PnL USD, liquidation, leverage/margin, ROE when returned.
      Staked/vaulted: ctm_hyperliquid_fetch_staking_summary + fetch_delegations + fetch_user_vault_equities;
      ctm_gmx_fetch_staking_power; cross-ref LST balances when Lido has no position-read tool.
      Lending / Morpho Midnight when configured: rates, cost basis, pending fees if returned.
      Uniswap v4 LP: ctm_uniswap_v4_lp_list_positions — registry ids; note fees/IL/ROI gaps.
      Explicitly state tool gaps (e.g. Aave/Lido often balance-only). Do not invent PnL or earned APY.
      As-of dating. Sources for any external claims. No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 14
      maxWallClockMs: 180000
      maxChildSpawns: 0

  - id: portfolio-priced-rollup
    dependsOn: ["portfolio-wallet-inventory", "portfolio-protocol-performance"]
    prompt: |
      With operator consent, load CoinGecko/CMC; price inventory + protocol notionals/uPnL into a USD snapshot.
      Concentration by asset/chain/venue; as-of dating. Sources (title + https). No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 10
      maxWallClockMs: 150000
      maxChildSpawns: 0
```

**Performance fields to prefer when present:** unrealized PnL (USD), entry vs mark, liquidation, leverage/margin, ROE, staking delegated/vault equity, lending effective rate / cost basis.

**Known gaps:** Lido and Aave often lack MCP user-position/earned-APY reads (use balances + note gap). Uniswap v4 LP list is registry-oriented (fees/IL may be unavailable).

**Allowed swaps** (keep ~3): `portfolio-risk-notes` (liq distance, margin health); funding/cash drag; rewards/points when a pack exposes them.

**Anti-patterns:** one catch-all portfolio leaf; inventing uPnL/APY; skipping `fetch_positions` when perps packs are available; marking portfolio tasks `role: coordinator`.

### Synthesis

`orchestratorOnReply` rolls up inventory + protocol performance + USD snapshot, calls out tool gaps, and posts a KeyGen **REPLY** via `send_key_gen_message`.
