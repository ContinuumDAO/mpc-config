---
name: stock-research-filings
description: Filing red flags. Read the latest SEC filing for a named stock and list changes in risk factors, debt, and share count versus the previous filing. Load stock-research first.
---

# Filing red flags

Load **`stock-research`**. One issuer per run.

1. Use **`edgartools`**. If it is not active, recommend adding it. `EDGAR_IDENTITY` is a contact email for SEC fair access, not a paid key. Wait before `agent_load_mcp_server`.
2. Read the latest 10-K, 10-Q, or 8-K the tool returns, and the previous periodic filing for the comparison. Name the form type and filing date.
3. List changes in **risk factors**, **debt**, and **share count** versus that previous filing. Quote figures the tool returned. If a section is missing, say so.
4. Flag a change only when both filings support it. Do not infer a red flag from a headline.
5. One line on whether Hyperliquid, Arcus, Uniswap, or Aerodrome lists the name. The filing is about the cash issuer either way. No trade.
