# Cron message examples

| File | Purpose |
|------|---------|
| `jobs.json` | **Repository catalog** of cron job templates (not copied to runtime; activate via UI or `POST /addCronJobFromCatalog`) |
| `trade-cron.yaml` | Host YAML (`kind=cron-trade`). Node-wide **`tradeConsensus`** / **`tradeBuild`** defaults. Edit on the Cron tab **Host YAML config** row. |
| `trade_analysis_cron.example.md` | Read-only copy-paste trade-analysis cron **message**. Cron tab **View template** or **`GET /getCronTradeAnalysisExample`**. Not a catalog job. |
| `sign_accept_policy.example.md` | Template for **`conditional-accept-sign-request`** (`signAcceptPolicy` lives in the job **`message`**, not a host YAML file). |
| `continuum_dao_vote_policy.example.md` | Template for **`appraise-and-vote-proposals`** and **`conditional-accept-governance-vote`**. Machine defaults live in host YAML **`continuum-dao-vote-policy.yaml`**. |
| `forum_replies_cron.example.md` | Setup for **`notify-forum-replies`** (Forum username, Telegram, baseline vs notify). Watch state is agent-written **`data/cron/notify-forum-replies.yaml`**, not a host YAML kind. |

Bundled jobs in `jobs.json`:

| Name | Default active | Role |
|------|----------------|------|
| `auto-sign-and-broadcast` | yes | Poll ready sign requests; trigger Get Sig and broadcast on-chain (originator node) |
| `auto-accept-sign-request` | no | Poll Join-tab pending requests; auto-accept via `sign_request_agree` with thoughts `Sign request agreed to automatically at <ISO 8601 UTC>` |
| `conditional-accept-sign-request` | no | **Trade** Join only. Skips ContinuumDAO governor types (`propose` / `cast_vote` / `execute` / `cancel`). See **`sign_accept_policy.example.md`** |
| `appraise-and-vote-proposals` | no | ContinuumDAO **vote only** (never propose; never load `continuum-dao-compose-proposal`). See **`continuum_dao_vote_policy.example.md`** |
| `notify-forum-replies` | no | Read-only: new replies to **your** Forum posts → Telegram with the formatted post. Set `forumWatch.forumUsername`. See **`forum_replies_cron.example.md`** |
| `conditional-accept-governance-vote` | no | ContinuumDAO **governor Join** only. Reject propose/execute/cancel. See **`continuum_dao_vote_policy.example.md`** |
| `close-call` | no | Close Call on technocore.chat. UTC minutes 1,6,11,… Load skill **`close-call`**. Watch each sweep, register once in room `close1`, hold unless a slow target needs one adjusting trade. |
| `trade_analysis_cron.example.md` | Copy-paste template for multi-analysis (patterns, **momentum + candlestick confirmation**, trend, key levels, fib, Elliott waves) + optional **`tradeConsensus`** / **`tradeBuild`** YAML; supports **hyperliquid**, **arcus**, **gmx**, **uniswap** execution. **Pattern C** documents optional cron supervisor spawn strands (`agent_spawn_sub_agent` / join) for multi-analyze jobs |

See skill **`scheduled-automation`** for schedule kinds, non-interactive rules, orchestration threading, cron supervisor spawn, and **`telegramNotify`** (host delivers the final assistant message to Telegram).

| Job field | Meaning |
|-----------|---------|
| **`telegramNotify`** | When `true`, after a successful run the host DMs the final answer to **`TELEGRAM_OPERATOR_CHAT_ID`**. Off by default on high-frequency silent jobs. |

Copy example content into **`add_cron_job`** / UI — catalog templates default to **disabled** until the operator activates them.
