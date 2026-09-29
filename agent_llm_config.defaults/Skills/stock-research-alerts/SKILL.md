---
name: stock-research-alerts
description: Alerts on autopilot. For each confirmed watchlist name, draft a price alert at its 52-week high, show the list, and wait for a yes before creating cron jobs. Load stock-research first.
---

# Alerts on autopilot

Load **`stock-research`** and **`scheduled-automation`**. Draft first. Create cron jobs only after an explicit yes. The job checks price. It does not submit a trade.

1. Read the watchlist they name, or `user_folder/data/stock-research/watchlists/Breakouts.md` when they say Breakouts. If the file is missing, stop and point at **`stock-research-watchlist`**.
2. For each name, fetch the 52-week high from an active equity MCP (recommend `alphavantage`, `financial-modeling-prep`, or `massive` if needed, then wait). When the name is listed on Hyperliquid or Arcus, also note the venue mark and whether the high is a cash print or a venue high. Uniswap and Aerodrome use that same external high and the skill must name the candle source.
3. Show one line per name: ticker, level, venue, candle source, proposed schedule (default weekday check, not a tight loop). Ask which names to keep.
4. After yes, add **one cron job per confirmed name** via `add_cron_job`. Freeze in the job `message`: ticker, numeric level, venue, candle source, and “report only — do not build or broadcast”. Set **`telegramNotify: true`** so the host sends the final answer. Do not also call `send_telegram_message` for that delivery.
5. The message must be non-interactive (`scheduled-automation`). Include how to load the candle source. End the interactive turn with the job names you created. Offer `run_cron_job` once before they enable a job, and wait if they want that test.
