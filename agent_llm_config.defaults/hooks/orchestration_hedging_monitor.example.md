## Hedging monitor cron (unwind)

Use with skills **`hedging-monitor`**, **`execution-policy`**, and **`scheduled-automation`**. Schedule on the **same `[Orchestrator]`** conversation after open-hedge MultiSign exists (`agent_schedule_orchestration_cron` or `conversationId` + `orchestrationTopLevelMessageId`).

Cron **cannot elicit**. Freeze Unwind + Hedge design in the job **`message`**. Default cadence `every` daily. Set **`telegramNotify: true`** when a trigger should ping the operator. v1: **never** auto-Accept or broadcast unwind.

### Example job message

```text
Load hedging-monitor and execution-policy.
Frozen hedge contract (do not re-interview):
- Overlay: isolated Hyperliquid ETH perp short, 6 ETH notional, 2x, 3500 USDC margin
- Invalidation: ETH +8% from entry on the short; TP: ETH −12%
- Max funding/day: 0.08% of notional; min Aave HF: 1.5
- Pendle: none
- Morpho/Euler Earn: none
- Derive: none
- Triggers → action:
  - event + 24h settled → close
  - funding < −5% annualized for 24h → close
  - invalidation breached → close
  - HF < 1.5 → cut the short first
  - else → hold
Discover live position tools (search_continuum_tools / load_defi_protocol). Compare to this contract.
Pick one: hold / tighten / close / roll.
Hold: short summary only, no MultiSign.
Tighten/close/roll: draft unwind MultiSign (one theme per leg, one requestId). autoSubmitMultisign false.
Do not Accept, Get Sig, or broadcast.
If the position is already gone: report vs stored target/invalidation and skip further cron action.
```

### Operator notes

- Preferred KeyGen set; 2/2 AI + human Accept is the intended pattern.
- Telegram: host delivers the final assistant message when `telegramNotify: true` — do not also `send_telegram_message`.
- Accept the close/roll MultiSign in the node app or Telegram the same way as a trade build.
