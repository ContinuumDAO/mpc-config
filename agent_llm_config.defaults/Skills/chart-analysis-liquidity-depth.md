# Chart analysis: liquidity depth

Tool: **`continuum__analyze_liquidity_depth`**.

**Spot order-book walls only** (Binance or Coinbase Advanced Trade). Not a Trade Idea — do **not** invent entry/target/invalidation or call trade-build tools from this analysis.

## Workflow

1. Fetch OHLCV (any chartable source) and keep the session bind.
2. Call **`analyze_liquidity_depth`** with `toolResult` / `{ title, ohlcvDigest }` (and `symbol` if needed: `BTCUSDT` for Binance, `BTC-USD` for Coinbase).
3. Present **`analysis.levelMenu`** as a numbered table: `#`, `side` (bid/ask), `price`, `avgSize`, `relativeStrength` (0–1), `distancePct` from mid.
4. Quote **`summary`**, `warmingUp`, `sampleCount`, `windowSec`. If warming up, say the average is still accumulating.

When the OHLCV session is **`coinbase_candles`**, the tool defaults to **`depthExchangeId: coinbase`**. For Binance klines it defaults to **`binance`**.

## Optional left-axis profile

When the operator asks to show depth on the chart, call **`apply_liquidity_depth_drawings`** with the same OHLCV session and **`profileBins`** from structuredContent (preferred) or let the tool re-sample. This overlays an averaged bid/ask profile left of the price axis (AI chat + Telegram Mini App).

## Desk defaults (`trade-desk.yaml` `universal`)

| Knob | Default | Role |
|------|---------|------|
| `depthExchangeId` | `binance` | Spot depth venue (`coinbase` when using Coinbase OHLCV) |
| `depthSampleIntervalSec` | `12` | Poll interval |
| `depthAverageWindowSec` | `300` | Rolling average window |
| `depthLimit` | `500` | Book depth limit |
| `depthLevelCount` | `8` | Rows in `levelMenu` |

## Hard rules

- Spot only — do not claim perp / futures book depth.
- Do not treat walls as trade setups.
- Do not invent a heatmap history; this is a rolling average of polled spot snapshots.
- Do not parse Coinbase raw `pricebook` nesting — analysis uses Continuum **NormalizedDepthSnapshot**.
