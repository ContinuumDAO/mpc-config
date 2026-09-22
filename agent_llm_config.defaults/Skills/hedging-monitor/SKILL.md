---
name: hedging-monitor
description: Watch a live hedge and compose unwind (hold / tighten / close / roll) against a frozen Unwind contract. Use after open-hedge MultiSign exists, or when the operator says unwind, close the hedge, tighten, roll the collar/PT, or monitor my hedge. Skip for greenfield hedge design (that is hedging-trade).
---

# Hedging monitor (unwind)

This skill **only** owns watch + unwind. Planning stays in **`hedging-trade`**. Authoritative cron rules are in **`scheduled-automation`**. On-chain compose follows **`execution-policy`**.

## When to load

- Follow-on / Orchestrator after open-hedge MultiSign exists.
- Interactive or Telegram: “unwind”, “close the hedge”, “tighten”, “roll the collar/PT”, “monitor my hedge”.
- **Never** from the greenfield Plan interview.

Load **`hedging-monitor`** + **`execution-policy`**. Also load **`scheduled-automation`** when creating or editing the cron job.

## Frozen contract (required)

Copy from `plans/<planId>.md` **Unwind** + **Hedge design** into the cron `message` / `synthesis.cronPrompt`. Cron **cannot elicit**. Embed:

- Venue, asset, side, target size, isolated vs cross
- Invalidation / TP, max funding/day, min HF, Pendle market + expiry, option DTE
- Morpho and/or Euler Earn vault id/address, allowed asset-class tags (vanilla vs curated/RWA/reinsurance), min exit liquidity
- Derive instrument, strike, expiry, premium cap, roll vs expire
- Preferred action per trigger: hold / tighten (reduce notional or move SL) / close / roll
- `telegramNotify: true` when a trigger fires (off for silent all-clear if the operator prefers)

Thread the job on the **same `[Orchestrator]`** conversation (`agent_schedule_orchestration_cron` or `conversationId` + `orchestrationTopLevelMessageId`). Default cadence `every` daily (or operator-chosen). Avoid sub-hour loops.

## Each monitor turn

1. Discover live tools (`continuum__search_continuum_tools` / `load_defi_protocol`) — do not hardcode fetch names.
2. Read open hedge + supporting book: perp position, Derive options, Pendle PT/YT/LP, Morpho Earn Exposure + Euler Earn Strategies, Aave/Morpho/Euler HF, margin.
3. Compare to the frozen contract. Pick **one** recommendation: hold / tighten / close / roll.
4. If **hold**: short KeyGen/Telegram summary; no MultiSign.
5. If **tighten / close / roll**: compose **unwind** MultiSign — one theme per leg, one `requestId` per Accept round. Stop at proposal. **`autoSubmitMultisign: false`**. Do not Accept, Get Sig, or broadcast unless the frozen message already embeds that authorization (v1 default: **never** auto-accept unwind).
6. If the position is already gone: report close vs stored target/invalidation, disable or skip the cron, do not invent a close story.

## Unwind legs by overlay

| Live overlay | Unwind compose |
|--------------|----------------|
| Perp short | Reduce or close on HL / GMX / Arcus (limit first; market only if frozen depth rule allows) |
| Derive put/collar/call | Close or roll expiry/strike |
| Pendle PT | Hold to expiry **or** sell PT; never unwrap unless the contract says so |
| Pendle YT | Sell YT; optional rate-hedge roll |
| Uniswap v4 / Curve / Aerodrome / Pendle LP overlay | Close or tighten the **perp/put overlay** first. Remove LP only if Unwind says exit the pool (out of range, expiry, or operator asked) |
| Stable sleeve (vanilla) | Rotate back only if Unwind explicitly says restore beta |
| Morpho or Euler Earn curated vault | Existing Earn withdraw. Re-read Morpho Exposure / Euler Strategies before close; if allocation drifted into a class they did not opt into, prefer exit even if APY looks fine |
| HF breach | Follow the frozen order (add collateral **or** cut the short first) — do not guess |

If a close leg fails, stop. Do not “finish the unwind” on a different asset.

When a cron job has **`telegramNotify: true`**, the host sends the final assistant message after a successful run. Do **not** also call `send_telegram_message` for that delivery. End the turn with a concise operator-facing summary.

See `hooks/orchestration_hedging_monitor.example.md`.
