---
name: stock-research-watchlist
description: Build a watchlist. Show the list from a screen or named tickers and wait for a yes before writing it. Load stock-research first.
---

# Build a watchlist

Load **`stock-research`**. This is a write. Show the list and wait for an explicit yes before any file is created.

1. Take names from the current conversation (a screen, a peer set, or tickers they typed). If there are no names, ask. Do not pull a fresh screen unless they ask.
2. For each name, map Hyperliquid, Arcus, Uniswap, and Aerodrome using the menu skill. Record the venue symbol or pool when a tool returned it, otherwise **research only**.
3. Show a draft table: ticker, why it is on the list, venues. Ask what to call the list. Default name **`Breakouts`** only if this list came from the breakout screen and they do not pick another name.
4. After yes, write `user_folder/data/stock-research/watchlists/<name>.md` with that table and the as-of date. One file per list. Do not overwrite an existing name unless they said to replace it.
5. Do not create alerts here. Point at **`stock-research-alerts`** if they want a 52-week-high ping.
