---
name: stock-research-sectors
description: Sector scorecard. Compare the 11 S&P sector ETFs over 1 week, 1 month, and 3 months, and say which sectors are gaining and which are fading. Load stock-research first.
---

# Sector scorecard

Load **`stock-research`**.

The 11 sector ETFs: XLK, XLF, XLV, XLY, XLC, XLI, XLP, XLE, XLU, XLRE, XLB.

1. `list_mcp_servers`. Prefer `financial-modeling-prep` for the three windows. Else `alphavantage` or `massive`. Recommend, then wait, if none is active.
2. Table each ETF: 1-week, 1-month, and 3-month return from the tool. Leave a cell blank rather than estimating it.
3. Say which sectors are gaining and which are fading, using only that table. Name the window.
4. These ETFs are cash-market baskets. Do not treat a sector ETF as a Hyperliquid or Arcus listing unless a tool shows that market. No trade ideas.
