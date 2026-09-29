---
name: stock-research-calendar
description: Week-ahead risk map. List earnings and macro events this week that touch the active watchlist, and flag the three biggest risks. Load stock-research first.
---

# Week-ahead risk map

Load **`stock-research`**. This recipe reads an existing watchlist. It does not create one.

1. Read `user_folder/data/stock-research/watchlists/`. If none exists, say so and stop. Point them at **`stock-research-watchlist`**. Do not invent a default universe.
2. Earnings dates: `edgartools` (set `EDGAR_IDENTITY` if the tool asks) or `financial-modeling-prep` / `alphavantage` if already active. Recommend a missing server, then wait.
3. Macro headlines that can touch those names: `world-affairs` and `business-latest` (no key).
4. Social color only for names already on the list, and only when Continuum social search or **`x`** is configured (`stock-research` social rules). Search the saved allowlist. Do not widen to new accounts in this recipe.
5. List each earnings report and macro event this week that touches a watchlist name. As-of date every claim. Past events stay in the past.
6. Flag the **three** biggest risks, each with the name it hits and the source. No trade ideas and no orders.
