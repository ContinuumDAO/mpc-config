# Cron message examples

| File | Purpose |
|------|---------|
| `jobs.json` | **Repository catalog** of cron job templates (not copied to runtime; activate via UI or `POST /addCronJobFromCatalog`) |

Bundled jobs in `jobs.json`:

| Name | Default active | Role |
|------|----------------|------|
| `auto-sign-and-broadcast` | yes | Poll ready sign requests; trigger Get Sig and broadcast on-chain (originator node) |
| `auto-accept-sign-request` | no | Poll Join-tab pending requests; auto-accept via `sign_request_agree` with thoughts `Sign request agreed to automatically at <ISO 8601 UTC>` |
| `conditional-accept-sign-request` | no | Policy-gated Join accept/reject from embedded `signAcceptPolicy` YAML (ctm1 Purpose codes + additional prose); see **`sign_accept_policy.example.md`** |
| `trade_analysis_cron.example.md` | Copy-paste template for multi-analysis (patterns, momentum, trend, key levels, fib) + optional **`tradeConsensus`** / **`tradeBuild`** YAML; supports **hyperliquid**, **arcus**, **gmx**, **uniswap** execution |

See skill **`scheduled-automation`** for schedule kinds, non-interactive rules, and orchestration threading.

Copy example content into **`add_cron_job`** / UI — catalog templates default to **disabled** until the operator activates them.
