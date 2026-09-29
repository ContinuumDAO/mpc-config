---
name: stock-research-news
description: Why is it moving? Pull today's news on the biggest movers, or on a named stock, and explain each move in two lines with sources. Load stock-research first.
---

# Why is it moving

Load **`stock-research`**.

1. If they did not name tickers, ask which book: their watchlist, or the session's biggest movers. For a watchlist, read `user_folder/data/stock-research/watchlists/`. If the file is missing, ask for tickers. Do not invent movers.
2. News: `business-latest` and `finance-news` (no key) when active. Recommend them if absent, then wait. Keep a working search path; if none is set, recommend **`brave-search`** per the menu skill.
3. Social reads when Continuum social search or **`x`** is configured. Use the saved allowlist in `user_folder/data/stock-research/social-accounts.md` when it exists. Posts are narrative with an as-of time, not the cause by themselves.
4. For each name, two lines: what moved, and the source (title + URL, or the tool return). As-of dating. A past print is not "upcoming".
5. If a name is on Hyperliquid or Arcus, you may quote the venue mark next to the cash print. Do not place an order.
