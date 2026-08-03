---
name: chart-analysis-levels
description: Use for key level analysis on charts. Skip otherwise.
---

# Chart analysis: key levels

Two **`analyze_*`** tools share the same ranked level menu / OHLCV session but produce **different** trade ideas:

| Tool | Trade idea kind | Setup field | Use when |
|------|-----------------|-------------|----------|
| **`continuum__analyze_key_levels`** | **`key_levels`** | `keyLevelsTradeSetup` | Nearest support **bounce** (`kl-bnc`) or nearest resistance **rejection** (`kl-brk`); target = next key level. Historical **break+retest** lives here as nested **`breakRetestAlternative`** (`kl-ret`). |
| **`continuum__analyze_key_level_fibonacci`** | **`key_level_fibonacci`** | `keyLevelFibTradeSetup` | **Strongest-bracket** Fib: strongest key level **below** × strongest **above** last close → inside-range **0.618** fade (`kl-fib`; entry at Fib leg, bounce offsets). Invalid when either leg is missing or below desk **`fibKeyLevelMinConfidence`**. |

Summarize **`analysis.levels`** (ranked support/resistance), **`nearestSupport`**, **`nearestResistance`**, and distance from **`lastClose`**.

For fib ideas, note **`priceRegime: inside_range`** (always when a valid bracket exists), both bracket Level #s, and **`keyLevelFibTradeSetup`** side / status.

**Chart apply (separate steps):**

- Nearest level only: `apply_key_level_drawings` with **`levelNumber`** (no Fib overlay).
- Fib range: `apply_key_fib_drawings` with **`fibPairNumber`** (Fib overlay **0 / 0.618 / 1** plus leg horizontals).

Raw horizontal levels without trade setup: `calculate_key_levels` → `apply_chart_drawings`.

Build/prefill policy: skill **`trade-defaults`**.
