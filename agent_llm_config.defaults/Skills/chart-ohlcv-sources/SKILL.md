---
name: chart-ohlcv-sources
description: OHLCV provider choice: DeFi protocols vs catalog MCP servers (`initialLoad: false`; host auto-loads on chart intents)
---

# OHLCV source priority

Pair with **`chart-defaults`**, **`chart-periods`**, **`chart-analysis-menu`**. Reference: **`chart_docs`**, **`coinmarketcap_public_docs`**, **`coinbase_public_docs`**.

Continuum does **not** endorse third-party data providers. Pick sources from **operator intent** and **what is loaded in this chat** — not brand preference.

## Never auto-load data sources

**Do not** call **`agent_load_mcp_server`** for CoinMarketCap, CoinGecko, or any other market-data MCP unless the **operator explicitly chooses** that provider (by name, or by picking from options you offer).

If no OHLCV source is loaded and no fetch has run in this chat:

1. **Stop** — do not chart, analyze, or load providers on your own.
2. Call **`continuum__list_ohlcv_sources`** — **`active`** is on this node / loaded DeFi; **`repository`** is catalog MCP not yet added plus other DeFi `fetch_ohlcv` protocols. For the full MCP catalog (search, news, …) use **`list_mcp_servers`**.
3. **Ask the operator** which source to use, quoting that list.
4. After they choose → **enable that source** (see below) → **fetch OHLCV** → pass full fetch object once, then **`{ title, ohlcvDigest }`** from **`meta.sessionBind`** on follow-ups.

Chart/analysis tools return a clear error when called without data; treat that as “ask the operator first”.

## Two kinds of OHLCV sources (do not confuse them)

| Kind | Examples | How to enable in this chat | Fetch tool |
|------|----------|----------------------------|------------|
| **DeFi protocol** (already on **continuum** MCP) | Hyperliquid, Arcus, GMX, Aave, Uniswap, … | **`continuum__load_defi_protocol`** `{ "protocolId": "hyperliquid" }` — **not** **`agent_load_mcp_server`** | `ctm_<protocol>_fetch_ohlcv` |
| **Optional catalog MCP server** | `coinmarketcap-public`, `coinbase-public`, `coingecko`, `binance`, `financial-modeling-prep`, `alpaca`, `equibles`, `technical-indicators`, … | **`continuum__agent_load_mcp_server`** `{ "serverId": "…" }` after operator choice | `coinmarketcap-public__*`, `coinbase-public__*`, `coingecko__*`, `binance__*`, `financial-modeling-prep__*`, `alpaca__*`, `equibles__*`, … |

**Hyperliquid is a DeFi protocol, not an MCP `serverId`.**  
`agent_load_mcp_server({ "serverId": "hyperliquid" })` fails with *not configured* — that is expected. Use **`load_defi_protocol({ "protocolId": "hyperliquid" })`** instead, then **`ctm_hyperliquid_fetch_ohlcv`**.

Read-only DeFi (markets, OHLCV, charts, analysis) does **not** require RPC URL, wallet, or node catalog setup — only **`load_defi_protocol`**. Wallet/KeyGen is for **multisign execution** (orders, deposits), not for fetch/chart.

## Load catalog MCP servers before fetch (catalog sources only)

For **CoinGecko, CoinMarketCap public, Coinbase public, Binance, Financial Modeling Prep, Alpaca, Equibles**, etc. — not for Hyperliquid/GMX.

Most catalog servers have **`initialLoad: false`**. Call **`continuum__agent_load_mcp_server`** same turn, **before** fetch, only after the operator picks a **catalog** provider:

```json
{ "serverId": "coinmarketcap-public" }
```

Use **`list_mcp_servers`** → **`activeServers`** before loading. Match **`serverId`** exactly (see below).

## Load DeFi protocols before fetch (DeFi sources only)

When the operator names **Hyperliquid**, **Arcus**, **GMX**, or another DeFi venue:

1. **`continuum__list_defi_protocols`** (optional) — confirm `protocolId`.
2. **`continuum__load_defi_protocol`** `{ "protocolId": "hyperliquid" }` (idempotent).
3. **`ctm_hyperliquid_fetch_ohlcv`** (or the protocol’s `fetch_ohlcv` tool) — same turn or next.

**Do not** call **`agent_load_mcp_server`** for DeFi protocol ids.

## Critical: two different CoinMarketCap server ids

| `serverId` | On node | API key | Use for OHLCV charts |
|------------|---------|---------|---------------------|
| **`coinmarketcap-public`** | Active on node (seed / add from catalog) | **Not** for keyless tools | **Yes** — `get_kline_candles`, etc. |
| **`coinmarketcap`** | Catalog (user-activated) | **`COINMARKETCAP_API_KEY`** required | Only if key configured; not a substitute for **`coinmarketcap-public`** |

When the operator says **“load CoinMarketCap”** or **“use CMC”** → load **`coinmarketcap-public`**, **not** **`coinmarketcap`**, unless they explicitly need catalog full MCP **and** the key is configured.

If **`agent_load_mcp_server({ serverId: "coinmarketcap" })`** returns *set environment variable COINMARKETCAP_API_KEY* → **load failed**. Do **not** tell the operator CMC is loaded. Offer **`coinmarketcap-public`** or **`coingecko`** as alternatives and let them choose.

If a chosen server is **missing** from **`activeServers`** → tell the operator to **Add from repository** once or check **`MCP_default_servers.json`** seed on new nodes.

## Rule 1 — Named venue or provider wins

| Operator says | Enable | Fetch |
|---------------|--------|-------|
| Hyperliquid, perp, HL | **`load_defi_protocol({ "protocolId": "hyperliquid" })`** | **`ctm_hyperliquid_fetch_ohlcv`** |
| Arcus, perp, Robinhood Chain | **`load_defi_protocol({ "protocolId": "arcus" })`** | **`ctm_arcus_fetch_ohlcv`** (chain **4663**) |
| Arcus spot Stock Tokens | **`load_defi_protocol({ "protocolId": "arcus" })`** | **`ctm_arcus_spot_fetch_ohlcv`** (chain **4663**) |
| GMX | **`load_defi_protocol({ "protocolId": "gmx" })`** | **`ctm_gmx_fetch_ohlcv`** |
| CoinMarketCap / CMC | **`agent_load_mcp_server({ "serverId": "coinmarketcap-public" })`** | **`coinmarketcap-public__get_kline_candles`** (etc.) |
| CoinGecko | **`agent_load_mcp_server({ "serverId": "coingecko" })`** or **`coingecko-pro`** | **`coingecko__execute`** |
| Binance | **`agent_load_mcp_server({ "serverId": "binance" })`** | **`binance_get_klines`** (or `binance__*` klines tool) with **`response_format: "json"`** |
| Coinbase / Advanced Trade | **`agent_load_mcp_server({ "serverId": "coinbase-public" })`** | **`coinbase-public__get_product_candles`** (`productId` e.g. `BTC-USD`, `interval` e.g. `1h`) |
| Financial Modeling Prep / FMP | **`agent_load_mcp_server({ "serverId": "financial-modeling-prep" })`** | Historical / chart tools (e.g. full, light, or intraday chart). Requires **`FMP_API_KEY`** in Variables |
| Alpaca | **`agent_load_mcp_server({ "serverId": "alpaca" })`** | **`get_stock_bars`** / **`get_crypto_bars`** (timeframes `1Min`, `5Min`, `15Min`, `1Hour`, `1Day`). Requires **`ALPACA_API_KEY`** + **`ALPACA_SECRET_KEY`** |
| Equibles | **`agent_load_mcp_server({ "serverId": "equibles" })`** | **`GetStockPrices`** (daily OHLCV). Requires **`EQUIBLES_API_KEY`**. Use **`GetLatestPrices`** for latest close (not a chart series) |
| Other DeFi (Aave, Uniswap, …) | **`load_defi_protocol({ "protocolId": "<id>" })`** | That protocol’s **`ctm_*`** tools (see **`get_defi_protocol_skill`**) |

## Rule 2 — Generic spot (no venue or provider named)

Use the **first loaded OHLCV-capable MCP server** in this chat, in order:

1. **`coingecko-pro`** (if loaded and key configured)
2. **`coingecko`** (if loaded)
3. **`binance`** (if loaded)
4. **`coinbase-public`** (if loaded)
5. **`financial-modeling-prep`** (if loaded and **`FMP_API_KEY`** configured)
6. **`alpaca`** (if loaded and **`ALPACA_API_KEY`** + **`ALPACA_SECRET_KEY`** configured)
7. **`equibles`** (if loaded and **`EQUIBLES_API_KEY`** configured)
8. Any other **loaded** server that exposes spot OHLCV (future catalog sources)

**If no OHLCV source is loaded in this session** → **ask the operator** which provider to use. Offer concise options (e.g. CoinGecko, CoinMarketCap public, Coinbase, Binance, Financial Modeling Prep, Alpaca, Equibles, Hyperliquid). **Do not** silently load **`coinmarketcap-public`**, **`coinbase-public`**, **`coingecko`**, **`binance`**, **`financial-modeling-prep`**, **`alpaca`**, or **`equibles`**.

After the operator chooses and you load the server:

- **`coinmarketcap-public`**: keyless **`get_kline_candles`**, optional Pro **`get_crypto_ohlcv_historical`** when **`COINMARKETCAP_API_KEY`** is in Variables
- **`coinbase-public`**: keyless **`get_product_candles`** (normalized Continuum bars); optional CDP Variables for authenticated routes
- **`coingecko`** / **`coingecko-pro`**: **`coingecko__execute`** → **`coins.ohlc.get`** or market chart — see **`chart-periods`**
- **`binance`**: **`binance_get_klines`** with **`response_format: "json"`** — see **`chart-periods`**
- **`financial-modeling-prep`**: historical / chart tools — rows use **`date`** + OHLC + **`volume`**; envelopes `{ symbol, historical }` or `{ data: […] }`. Pass the **full** object as **`toolResult`**. Keep **`date`**. Requires **`FMP_API_KEY`**. See **`chart-periods`**
- **`alpaca`**: **`get_stock_bars`** / **`get_crypto_bars`** — rows use **`t`/`o`/`h`/`l`/`c`/`v`**; envelopes `{ symbol, timeframe, bars }` or `{ bars: { TICKER: […] } }`. Pass the **full** object as **`toolResult`**. Keep **`t`**. Requires **`ALPACA_API_KEY`** + **`ALPACA_SECRET_KEY`**. See **`chart-periods`**
- **`equibles`**: **`GetStockPrices`** — daily OHLCV as a markdown table or `{ data: [{ date, open, high, low, close, volume }] }`. Pass the **full** object as **`toolResult`**. Keep **`date`**. Requires **`EQUIBLES_API_KEY`**. **`GetLatestPrices`** is a snapshot, not bars. See **`chart-periods`**

| When | Fetch |
|------|-------|
| **`coingecko`** / **`coingecko-pro`** loaded (operator chose) | **`coingecko__execute`** — see **`chart-periods`** |
| Operator chose CMC | **`coinmarketcap-public__get_kline_candles`** (or **`get_crypto_ohlcv_historical`** if Pro key on continuum-mcp) |
| Operator chose Coinbase | **`coinbase-public__get_product_candles`** — see **`chart-periods`** |
| Operator chose Binance | **`binance_get_klines`** with **`response_format: "json"`** — see **`chart-periods`** |
| Operator chose Financial Modeling Prep / FMP | Historical / chart tools — see **`chart-periods`** |
| Operator chose Alpaca | **`get_stock_bars`** / **`get_crypto_bars`** — see **`chart-periods`** |
| Operator chose Equibles | **`GetStockPrices`** — see **`chart-periods`** |

If fetch fails (429, empty, stale), report to the operator and offer **other sources** — do not auto-switch without their choice.

## Rule 3 — Fetch before analyze or chart (mandatory)

Fetch OHLCV first. Then branch on operator intent:

| Intent | After fetch |
|--------|-------------|
| **Analyze / interpret** (no chart requested) | **`analyze_*`** with full fetch as **`toolResult`**. **Do not** call **`prepare_chart_from_rows`**. |
| **Chart / plot / draw** | **`prepare_chart_from_rows`** with full fetch as **`toolResult`**. |

**Never** call **`prepare_chart_from_rows`** with only **`title`** / **`label`**. **Never** rewrite candle timestamps — pass fetch JSON verbatim (Hyperliquid uses **`timestampMs`**; Binance uses **`openTime`** ms; FMP uses **`date`**; Alpaca uses **`t`**; Equibles uses **`date`** — do not add or replace with a generic **`time`** field).

**Catalog / CEX chart path (Binance, Coinbase, CMC, CoinGecko):** Continuum MCP renders the chart. After a successful OHLCV fetch, the node **binds the session** and **auto-prepares only when the operator explicitly asked to chart/plot/render** (e.g. “chart the 4H BTC”). **Cron / scheduled analysis** and fetch-only / analyze-only turns must **not** call **`prepare_chart_from_rows`** (mentions of “chart bundle” or `chart_pattern` are not plot requests). Tool text may be a **slim** summary — do **not** re-paste full `klines` / `candles` / execute rows. Follow-ups: **`{ title, ohlcvDigest }`** or the fetch object once without rewriting vendor timestamps (`openTime`, `timestampMs`, Continuum `time`).

Plot example:

```json
{
  "title": "ETH/USD 4H — last 7d",
  "label": "ETH/USD",
  "toolResult": { "... full output from fetch ..." }
}
```

Analysis example:

```json
{
  "title": "ETH/USD 4H — last 7d",
  "toolResult": { "... same full fetch output ..." }
}
```

→ pass to **`continuum__analyze_momentum`** (or other **`analyze_*`**), not **`prepare_chart_from_rows`**.

Order: **(1) operator chooses source → `load_defi_protocol` OR `agent_load_mcp_server` as appropriate → (2) fetch → (3a) analyze_* OR (3b) prepare_chart_from_rows** — never both unless the operator asked for analysis **and** a chart.

Follow-ups on the **same** dataset: **`{ title, ohlcvDigest }`** from **`meta.sessionBind`** — do not re-paste fetch JSON. After the operator changes symbol, interval, or lookback → new fetch (replaces session bind automatically).

## Rule 4 — Orchestration task split

- **Analysis sub-agent:** step 3a only; **`mpc-task-result`** body = analysis JSON; **no** chart attachment.
- **Plot sub-agent:** step 3b (optional drawings); attach chart via **`post_key_gen_chart_attachment`**.

Keeps KeyGen context lean — analysis prose in one task, chart JSON in another.

## Live chart ticks

| Source | Live binding |
|--------|----------------|
| CoinGecko | **`coinId`** + **`bucketSec`** on execute output |
| Binance | Full klines JSON (`symbol` + `klines`) → **`binance.tickerPrice`** |
| Financial Modeling Prep | Full historical/chart JSON (`symbol` + `historical` / `data`) → **`fmp.quote`** |
| Alpaca | Full bars JSON (`symbol` + `bars` or `{ bars: { TICKER: […] } }`) → **`alpaca.latestTrade`** |
| Equibles | Static — use **`GetLatestPrices`** / **`GetLiveQuote`** as tools; no chart poller (shared daily quota) |
| Other third-party klines | Static unless a live adapter exists |
| Hyperliquid / DeFi | Full fetch JSON; node may bind perp live |

## Adding future sources

Add a row to Rule 2’s loaded-server list. Document tool, bar shape, volume, keys in this file and **`chart-periods`**.
