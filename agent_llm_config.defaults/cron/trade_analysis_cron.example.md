## Analysis + optional trade submit (Hyperliquid perp example)

Load MCP: **hyperliquid**, **continuum** (chart bundle). Non-interactive.

### Steps (prose — customize)

1. `load_defi_protocol` hyperliquid; `fetch_ohlcv` for operator symbol/interval.
2. `analyze_chart_patterns` on the session-bound OHLCV.
3. `analyze_momentum` on the same session.
4. If consensus gate ALLOWED and submit step enabled, call **`submit_trade_from_consensus`** with **`tradeIdeaId`** per selection rules below (resolve **`szHuman`** via Hyperliquid open context first).

### Selection guidance (prose — agent decides tradeIdeaId)

Prefer **chart_pattern** when `status=clear`; else **key_levels** rank-1 bounce; skip **partial** setups unless **momentum** agrees.

### tradeConsensus (YAML fence — paste into cron message)

```yaml
tradeConsensus:
  requiredSources: [chart_pattern, momentum]
  minAgree: 2
  minConfidence: 0.45
  allowPartial: false
  blockOnConflict: true
  submitTradeFromConsensus: true
```

### Hint-only variant

Set `submitTradeFromConsensus: false` (or omit) to inject the consensus matrix without requiring **`submit_trade_from_consensus`**.

### GMX variant

Replace Hyperliquid size resolution with GMX **`sizeUsdHuman`**, **`collateralToken`**, **`collateralAmountHuman`**; use **`build_trade_from_trade_idea`** with `protocolId: gmx` on interactive/orchestrator threads — cron submit still uses the same bridge after idea selection.
