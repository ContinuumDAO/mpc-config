## Orchestration stock research (Plan → sub-agents)

Use with skills **`orchestration_planning`** and **`stock-research`** for **`mode: stock-research`**. Plan chat drafts the manifest only. Specialists post **`mpc-task-result v1`** on KeyGen.

Run **one desk**. Delete the other leaves before Execute. The single-name example below is not the screen, week-ahead, or sector desk.

Watchlist writes and alert crons stay in chat (`stock-research-watchlist`, `stock-research-alerts`). They are not tasks in this fence. No `build_trade_from_trade_idea` and no broadcast. A listed name hands off to trade mode.

```yaml
# mpc-orchestrate v1
tasks:
  - id: stock-research-fundamentals
    prompt: |
      Earnings preview for <TICKER> (legal name + ticker). Last 4 quarters of EPS vs
      estimates, this quarter's forecast, and what surprised last time. Use an active
      equity MCP (financial-modeling-prep or alphavantage). Cite edgartools for the
      filing behind a surprise. As-of dating. No buy/sell prices. No tradeIdeas.
      End with Sources (title + https) when you have URLs.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 14
      maxWallClockMs: 180000
      maxChildSpawns: 0

  - id: stock-research-news
    prompt: |
      Why is <TICKER> moving. Two lines per move with sources from business-latest and
      finance-news. If Continuum social search (social:reddit, social:telegram,
      social:discord) or catalog server x is already configured, add read-only posts
      from the operator's allowlist and label them narrative with an as-of time.
      Do not post, follow, or like. No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 12
      maxWallClockMs: 180000
      maxChildSpawns: 0

  - id: stock-research-filings
    prompt: |
      Latest SEC filing for <TICKER> vs the previous periodic filing via edgartools.
      List changes in risk factors, debt, and share count. Name form type and filing
      date. Flag a change only when both filings support it. No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 12
      maxWallClockMs: 180000
      maxChildSpawns: 0
```

**Screen desk** replaces the three tasks with one `stock-research-screener` leaf. **Week-ahead** is one `stock-research-calendar` leaf and requires a saved watchlist. **Sectors** is one `stock-research-sectors` leaf.

Put topic-relevant AI Ready ids on `mcpServers` next to `continuum` (free RSS and `edgartools` first; free-key `financial-modeling-prep` / `alphavantage` / `massive` / `alpaca` when the operator has agreed). Do not attach every AI Ready server.

**Anti-patterns:** all ten cards in one fence; watchlist or cron writes inside the fence; inventing venue listings; treating Uniswap or Aerodrome as a candle source; GMX for equities.

### Synthesis

`orchestratorOnReply` cites the leaves that ran, labels each name executable (Hyperliquid, Arcus, Uniswap, Aerodrome) or research only, preserves as-of dating, and posts a KeyGen **REPLY**. Orders stay on a trade-mode follow-on.
