# Cron message examples

| File | Purpose |
|------|---------|
| `jobs.json` | **Repository catalog** of cron job templates (not copied to runtime; activate via UI or `POST /addCronJobFromCatalog`) |
| `trade_analysis_cron.example.md` | Copy-paste template for multi-analysis (patterns, momentum, trend, key levels, fib) + optional **`tradeConsensus`** / **`tradeBuild`** YAML; supports **hyperliquid**, **arcus**, **gmx**, **uniswap** execution |

See skill **`scheduled-automation`** for schedule kinds, non-interactive rules, and orchestration threading.

Copy example content into **`add_cron_job`** / UI — catalog templates default to **disabled** until the operator activates them.
