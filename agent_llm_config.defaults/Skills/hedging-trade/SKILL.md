---
name: hedging-trade
description: Use in Plan mode when the operator wants to reduce directional risk without dumping core inventory. Covers delta hedges, partial hedges, protective puts/collars, stable sleeves, curated Morpho/Euler Earn, basis/funding books, hedged LP, and Pendle PT/YT. Skip for chart-only or unhedged directional trade-ideas. After the hedge is live, load hedging-monitor for unwind — do not keep cron unwind rules here.
---

# Hedging-aware Plan mode

You design a **markdown plan** the human co-signer can Accept, then a machine `mpc-orchestrate v1` block. You do not broadcast. Every on-chain leg still goes through MultiSign + MPC Accept/Reject (`execution-policy`).

Authoritative planning rules stay in `orchestration-plan.yaml` and `orchestration_planning`. This skill only adds **hedge policy**.

## When to load

Load if the goal mentions hedge, protect, overlay, delta-neutral, funding capture, collar, put, de-risk, stable sleeve, “keep the coins,” hedge my LP, Pendle PT/YT, Morpho Earn, Euler Earn, or reinsurance vault.

If the operator only wants a long/short idea, stay on `trade-defaults`.

Never load this skill for unwind/close/roll/monitor — that is **`hedging-monitor`**.

## Collect before locking the plan

One message; skip questions already answered. Then write the plan file and stop (no live fetches, no `ctm_*_build_*_multisign`).

1. **Inventory** — KeyGen vs named assets/venues/wrappers (spot, wstETH, Uniswap v4 / Curve / Aerodrome / Pendle LP, Aave/Euler collateral, Morpho Earn and Euler Earn shares, Pendle PT/YT, open perps / Derive options).
2. **What must be preserved** — never sell core, keep yield, keep voting power, keep LP in range, Pendle expiry.
3. **Risk to cut** — crash, event window, funding flip, IL, borrow-rate spike, falling implied yield, or crypto-beta concentration.
4. **Hedge ratio** — 25% light, 50% event, 100% flat. Default **50%** if they will not pick.
5. **Horizon** — hours / days / weeks. Perps for short windows; Derive, stables, curated Earn, or Pendle PT to expiry for longer.
6. **Budget** — max option premium, max funding/day, max leverage on the short, min health factor after the hedge (default **1.4**).
7. **Venue preference** — Hyperliquid, GMX, Arcus, Derive if required, Aave, Morpho Blue, Morpho/Euler Earn, Pendle, or “cheapest executable.”
8. **Curated vault opt-in** — allow Morpho Earn **and** Euler curated Earn allocations into non-crypto classes (reinsurance, private credit, RWA), or **crypto-lending only**? Default **crypto-lending only**.
9. **Unwind triggers** — event done, funding < X, price reclaims Y, HF < Z, Pendle near expiry, Earn exit liquidity, option DTE / roll.

Do not block research if size is deferred. Do block **execution / compose** until inventory + ratio + venue exist.

## Strategy picker (choose one primary)

| Condition | Default overlay |
|---|---|
| Liquid perp, horizon ≤ 14d, want to keep coins | Short perp, same asset, isolated margin |
| Illiquid alt | Cross-hedge ETH or BTC at 50–70% of beta; label it imperfect |
| Want defined max loss, IV not blown out | **Derive** protective put; collar only if they accept capped upside |
| Refuse perp margin / isolated liq, or HL/GMX/Arcus cannot fill inside stated bps | **Derive** if a liquid option exists; else smaller perp slice or stable sleeve |
| Horizon event-dated or > ~14d and perp funding/liq is the worse cost | **Derive** put/collar when IV is not extreme |
| Want dry powder, no derivative margin | Swap sleeve to USDC via Uniswap/Curve/CCTP → Aave / Morpho Blue / Euler lend / Ethena / Sky / Maple |
| Opted in to curated / RWA classes | Morpho Earn **or** Euler curated Earn (equal footing). Cite Exposure / Strategies. **Not** a delta hedge |
| Want carry, not direction | Staked or spot long + matching short (basis book). Stress negative funding |
| Uniswap v4 / Curve / Aerodrome / Pendle LP to keep | Measure token betas, short the dominant crypto beta (or Derive put if options rules fire); leave the LP in range |
| Falling implied yield on LST / LRT / sUSDe | Buy Pendle **PT** (lock implied APY to expiry) |
| Long yield / points (not crash insurance) | Buy Pendle **YT** — label as not crash insurance |
| Looping wstETH or holding sUSDe and want the yield side locked | Pendle PT on that market |
| Existing Aave/Morpho/Euler borrow | Raise HF first. Do not add a perp short that competes for the same stable margin |

**Derive — use when required** (not optional flavor text). Must choose Derive when any of these hold and a liquid option exists: defined max loss; event-dated or >~14d horizon; refuse perp margin / depth fail; IV not extreme. If IV is blown out, say so and fall back (smaller put, perp slice, or stable sleeve). Covered call / overwrite is **income**, not crash insurance — never present a short call alone as a hedge. Do not use Derive for hours-long windows, zero-premium asks, or unlisted assets (cross-hedge ETH/BTC or say unsupported). Quote premium as % of notional; strike 5–15% OTM; expiry covering the event + 3–7d; include greeks in Hedge design.

Never present HLP, GM, or vault LP as the hedge. Those are inventory.

Pendle **Boros / YU** only if `list_defi_protocols` actually exposes it.

## Sizing rules

- Hedge **units**, not “leverage × margin.” Match spot quantity × hedgeRatio.
- Prefer **isolated** margin on the short. State liquidation price vs invalidation.
- After any lending change, recompute health factor. Refuse the plan if preview HF < operator floor (default 1.4) or if the short’s margin is the same capital as loan collateral without a buffer.
- Options: strike 5–15% OTM, expiry covering the event + 3–7d. Quote premium as % of notional.
- Pendle: name market, expiry, implied APY vs floating.
- Partial > full unless they explicitly want to flatten.
- Write notional, margin, leverage, estimated funding/day or PT implied APY, and a 24h / 7d P&L table for ±10% and ±30%.

### Hedged LP (Uniswap v4 / Curve / Aerodrome / Pendle)

1. Read the live LP. Uniswap v4 `ctm_uniswap_v4_lp_list_positions` is registry-based and may miss unregistered NFTs. Curve / Aerodrome / Pendle via `load_defi_protocol` + official position/LP tools. State tool gaps (fees, IL, ROI often missing) — do not invent IL.
2. Split into token notionals at mark. Hedge **units** of the **crypto beta** (`qty × hedgeRatio`), not “the LP NFT.” A 50/50 ETH-USDC Uni v4 position at 50% hedge → short **0.5 × ETH qty**. A stable-only Curve pool needs **no** perp overlay (peg/protocol risk only).
3. Default overlay: isolated perp short of the dominant beta (ETH or BTC). Use Derive put on that beta if the options rules fire. Dual-volatile LPs: short the larger beta or both, labeled imperfect.
4. Pendle LP: short the **underlying** (e.g. stETH/ETH), not PT vs YT against each other, unless they asked for a rate hedge.
5. Leave the LP in range unless they ask to exit. Unwind the **overlay** first.
6. Residual: range exit, IL vs the hedge, basis, gauge/lock, Pendle expiry. Never call a hedged LP “delta-neutral.”

### Curated Earn (Morpho + Euler)

After opt-in, require Morpho **Exposure** or Euler **Strategies** (labels + % of TVL) in the plan. A Re / reinsurance / RWA / private-credit row is **not** crash insurance. Residual risk is curator, allocation drift, liquidity/exit, and the underlying class — cite those rows, do not summarize as “USDC yield.” Default crypto-lending only. Refuse to treat a Re/RWA vault as a substitute for a perp or Derive put.

## Workstreams every hedge plan must have

Mirror these in the human plan **and** in `mpc-orchestrate` tasks (research only):

1. **hedge-inventory-exposure** — balances, open perps, Derive options, loans, Morpho+Euler Earn, Uni/Curve/Aero/Pendle LP. Use `continuum` + loaded DeFi protocols. Do not invent positions.
2. **hedge-venue-market** — mark, funding, OI, IV/skew if options, depth for the size, Pendle implied APY, Morpho Exposure + Euler Strategies.
3. **hedge-protocol-risk** — one short paragraph per named protocol / curator / asset class.

**Hedge design**, capital path, and **Unwind** stay in the human markdown (plan-time). Do not put compose or MultiSign in the first fence.

Research leaves stay multi-source. TA is optional; a hedge can be event-driven with no chart idea. Synthesis ranks one **primary** overlay plus a fallback (e.g. PT if HL depth fails).

## What you must write into plans/<planId>.md

Frontmatter `mode` = `hedging`.

Human sections: Goal, Assumptions, Inventory, Hedge design, Workstreams, Risks, Unwind.

Then the trailing `mpc-orchestrate v1` fence with the three research leaves only.

Unwind section must list triggers + preferred action per overlay. After the operator agrees and open-hedge legs exist, tell them (or the follow-on) to load **`hedging-monitor`** and schedule the monitor — do not keep unwind cron rules in this skill.

## Execution policy (follow-on / Orchestrator — not first Execute)

- Compose only after the operator agrees the MD plan.
- One MultiSign theme per leg (swap, bridge, perp, Derive option, Pendle, Morpho/Euler Earn deposit/withdraw, lend) so Accept/Reject is readable.
- Default `autoSubmitMultisign: false`.
- If a leg fails, stop; do not “complete the hedge” with a different asset.

See `hooks/orchestration_hedging.example.md`.
