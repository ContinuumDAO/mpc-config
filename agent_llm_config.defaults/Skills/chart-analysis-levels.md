# Chart analysis: key levels

Two **`analyze_*`** tools share the same ranked level menu / OHLCV session but produce **different** trade ideas:

| Tool | Trade idea kind | Setup field | Use when |
|------|-----------------|-------------|----------|
| **`continuum__analyze_key_levels`** | **`key_levels`** | `keyLevelsTradeSetup` | Nearest support **bounce** (`kl-bnc`) or nearest resistance **rejection** (`kl-brk`); target = next key level |
| **`continuum__analyze_key_level_fibonacci`** | **`key_level_fibonacci`** | `keyLevelFibTradeSetup` | Outer concentric swing range: **0.618** retrace inside range (`kl-fib`; entry at Fib 0 / 1.0 leg), or **1.618 extension** above/below range (`kl-fib-ext`; retest entry at broken **Fib 1.0** leg) |

Summarize **`analysis.levels`** (ranked support/resistance), **`nearestSupport`**, **`nearestResistance`**, and distance from **`lastClose`**.

For fib ideas, also note **`priceRegime`** (`inside_range` | `above_range` | `below_range`), **`fibPairs`**, and primary/alternate setup status.

**Chart apply (separate steps):**

- Nearest level only: `apply_key_level_drawings` with **`levelNumber`** (no Fib overlay).
- Fib range: `apply_key_fib_drawings` with **`fibPairNumber`** (Fib overlay 0 / 0.618 / 1 only; optional bold **1.618 extension** horizontal when `targetSource: fib_extension`).

Raw horizontal levels without trade setup: `calculate_key_levels` → `apply_chart_drawings`.

Build/prefill policy: skill **`trade-defaults`**.
