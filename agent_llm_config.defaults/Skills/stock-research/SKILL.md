---
name: stock-research
description: US stock research menu — screens, calendars, earnings, news, filings, sectors, watchlists, and price alerts. Load before any stock-research-* recipe. Skip for a single-asset chart or an unhedged trade idea (trade mode / trade-defaults).
---

# Stock research

Shared rules for the recipe skills. Load this skill first, then the one recipe that matches the ask. Do not run every recipe.

| Ask | Load |
|---|---|
| Breakout hunter, quality at a discount, screen US stocks | **`stock-research-screener`** |
| Week-ahead risk map, earnings calendar, macro on a watchlist | **`stock-research-calendar`** |
| Earnings preview, peer showdown | **`stock-research-fundamentals`** |
| Why is it moving, biggest movers | **`stock-research-news`** |
| Filing red flags, latest 10-K / 10-Q / 8-K | **`stock-research-filings`** |
| Sector scorecard, S&P sector ETFs | **`stock-research-sectors`** |
| Build a watchlist | **`stock-research-watchlist`** |
| Price alert, 52-week high alert | **`stock-research-alerts`** |

A named ticker plus technical analysis or a trade idea stays on **trade** mode and **`trade-defaults`**. This family hands off; it does not run `analyze_*` or broadcast.

In Plan mode, keep or set **`mode: stock-research`**. Desks and the `mpc-orchestrate` fence are in **`orchestration-plan.yaml`**. Watchlist writes and alert crons stay in chat, outside the fence.

## Two books

Cash research is the US listing (`NASDAQ:NVDA`). Executable exposure is only a market or pool that `load_defi_protocol` actually returns. Label every row.

| Venue | Load | Executable when | Candles |
|---|---|---|---|
| **Hyperliquid** HIP-3 equity perps | `protocolId: hyperliquid` | A live market (venue ids such as `xyz:NVDA` are not cash prints) | `ctm_hyperliquid_fetch_ohlcv` |
| **Arcus** spot Stock Tokens and perps | `protocolId: arcus` (chain **4663**) | Spot: `ctm_arcus_spot_*`. Perp: `ctm_arcus_*` | `ctm_arcus_spot_fetch_ohlcv` or `ctm_arcus_fetch_ohlcv` |
| **Uniswap** v4 | `protocolId: uniswap` | A pool for that token exists | No protocol OHLCV. Use Hyperliquid, Arcus, or the equity MCP and name the source |
| **Aerodrome** | `protocolId: aerodrome` | A pool exists. Discover swap and LP tools with `get_defi_protocol_skill` after load. Do not invent tool names | Same external source as Uniswap if the skill has no candle tool |

If none of the four lists the name, say **research only**. Do not invent a trade. Do not offer GMX for equities.

A US-stock screen (market cap, 52-week high, revenue growth) uses an equity MCP. DeFi listings are an incomplete universe. After the screen, intersect hits with live Hyperliquid, Arcus, Uniswap, and Aerodrome markets. Mark each row with the venues that listed it, or research only. Quote venue mark and cash print when both exist.

A tradable conclusion points at trade mode / **`trade-defaults`** / `build_trade_from_trade_idea` with `protocolId` `hyperliquid`, `arcus`, `uniswap`, or `aerodrome`. Do not broadcast. Uniswap (and Aerodrome when it is spot-only) follows the existing proximity rule: a structure idea is actionable only when last price is already inside desk entry proximity. Donchian for “near the 52-week high” is a follow-on via **`chart-analysis-donchian`** on Hyperliquid or Arcus bars, or the equity MCP when the DEX has no candles.

## MCP ladder

Call `list_mcp_servers` first. Recommend only servers this recipe needs that are not already active. Do not `agent_load_mcp_server` until the operator agrees. `load_defi_protocol` does not need a catalog add. Do not invent quota numbers; point at `setupUrl`.

1. Already active on the node.
2. No API key: `business-latest` and `finance-news` (news), `world-affairs` (macro), `edgartools` (SEC filings; `EDGAR_IDENTITY` is a contact email, not a paid key).
3. Free key or a free monthly allowance, only if step 2 cannot do the job: `alphavantage` (`ALPHA_VANTAGE_API_KEY`) for bars and quotes; `financial-modeling-prep` (`FMP_API_KEY`) for screeners, earnings, peers, and sectors; `massive` (`MASSIVE_API_KEY`) for aggregates; `alpaca` (`ALPACA_API_KEY` + `ALPACA_SECRET_KEY`) for stock bars.
4. **Search.** If `agent_web_search` or `AGENT_DEFAULT_SEARCH_MCP` already works, keep it. If none is set, recommend **`brave-search`** (`BRAVE_API_KEY`, free monthly allowance) and suggest Variable **`AGENT_DEFAULT_SEARCH_MCP=brave-search`** after they add it. Do not recommend `duckduckgo`. `tavily` only if they decline Brave.
5. Do not lead with paid or crypto-only servers (`equibles`, `messari`, `nansen`, paid `coinmarketcap`).

| Recipe | Primary | Fallback |
|---|---|---|
| Screeners and sectors | `financial-modeling-prep` | `alphavantage` or `massive` |
| Earnings and peers | `financial-modeling-prep` or `alphavantage` | `edgartools` for the filing itself |
| News | `business-latest` and `finance-news` | Social reads below, when configured |
| Filings | `edgartools` | — |
| Calendar | `edgartools` plus `world-affairs` / `business-latest` | Watchlist file, not an MCP |

## Social reads

Narrative with an as-of time. Not a price, a filing, or a trade signal. Use on news, calendar, and single-name work. Read only. Do not post, follow, or like unless the operator explicitly asks.

**Continuum social search** is on the **continuum** MCP. Node app: **AI Agent → MCP Servers → Continuum → Social search**. Activate with `continuum__search_continuum_tools` / `continuum__activate_tool_group` (`social_search`, or `social:reddit` / `social:telegram` / `social:discord`). Allowlists live in the node’s `social-search.yaml`. Do not rewrite that file. Setup: **`docs/references/API_IMPLEMENTATION.md`** (Telegram search, Discord, Reddit).

| Source | Tools | Recommend if not ready |
|---|---|---|
| Reddit | `search_reddit_posts`, `search_reddit_tickers`, `get_reddit_thread` | `REDDIT_CLIENT_ID`, `REDDIT_CLIENT_SECRET`, `REDDIT_USER_AGENT` (script app) |
| Telegram channels | `search_telegram_messages`, `search_telegram_tickers` | `TELEGRAM_API_ID` + `TELEGRAM_API_HASH`, then the phone-login wizard (`TELEGRAM_SESSION_PATH`). This is not bot notify (`send_telegram_message`) |
| Discord | `search_discord_messages`, `search_discord_tickers` | `DISCORD_BOT_TOKEN` (optional `DISCORD_APPLICATION_ID`). Message Content intent; bot must have joined the guild |

**X** is catalog server **`x`**, in addition to Continuum social search. Variables: `TWITTER_API_KEY`, `TWITTER_API_SECRET`, `TWITTER_ACCESS_TOKEN`, `TWITTER_ACCESS_SECRET`. Do not claim a free quota. Recommend adding it when it is inactive, then wait.

If a source is already configured, search inside its allowlist. If the allowlist is empty, suggest a short starting set and stop. The operator decides:

- Reddit: ticker subreddit, one general equities subreddit, one sector subreddit — examples they can drop.
- Telegram: public channels they already read for that name or sector.
- Discord: servers and channels they will invite the bot to.
- X: the issuer’s official account, its investor-relations account, and one or two sector or wire accounts they already trust.

Do not invent follower counts or authority. After they confirm, store subreddits, channels, guilds, and X handles in `user_folder/data/stock-research/social-accounts.md` and tell them to put the same names into **Social search** / `social-search.yaml`. Reuse that file later.

## Writes

Watchlist files and alert crons are drafted, shown, and written only after the operator says yes.

- Watchlists: `user_folder/data/stock-research/watchlists/<name>.md`
- Social handles: `user_folder/data/stock-research/social-accounts.md`

Do not write loose files at the `user_folder` root.
