---
name: stock-research-screener
description: Breakout hunter and Quality at a discount. Screen US stocks near a 52-week high on rising volume, or profitable growers cheap versus their own history. Load stock-research first.
---

# Stock screens

Load **`stock-research`** for the MCP ladder, venue map, and consent rules. One screen per ask. Do not also run calendar, filings, or alerts unless they ask.

## Breakout hunter

Screen US stocks within about **3% of their 52-week high**, volume about **2× the 30-day average**, market cap over **$2B**. Rank by relative volume.

1. `list_mcp_servers`. Prefer an active screener. If none, recommend `financial-modeling-prep` (`FMP_API_KEY`), else `alphavantage` or `massive`. Wait for agreement before `agent_load_mcp_server`.
2. Run the screen from tool results. If the free tier cannot filter all three conditions, say which filter you applied in the tool and which you checked on the returned rows. Do not invent the missing rows.
3. Intersect the top names with Hyperliquid, Arcus, Uniswap, and Aerodrome (`stock-research` venue table). Mark each hit executable (name the venues) or research only. Quote venue mark vs cash print when both exist.
4. Return a short ranked table: ticker, distance to 52-week high, relative volume, market cap, venues. Sources or the tool name that produced the rows.
5. Offer a watchlist via **`stock-research-watchlist`** only after they pick names. Donchian on a chosen executable name is a trade-mode follow-on (`chart-analysis-donchian`), not part of this screen.

## Quality at a discount

Find profitable companies with revenue growth over about **15%**, P/E below their **5-year average**, and falling debt. Top **10**, one line each.

1. Same MCP consent as the breakout screen. Fundamentals screens are `financial-modeling-prep` first.
2. Keep a name only when the tool returned the growth, valuation, and debt fields you cite. Drop names with missing fields instead of filling them in.
3. One line each: ticker, growth, P/E vs 5-year average, debt direction, and venue map (or research only).
4. Stop at 10. Offer the watchlist skill if they want the list saved.
