---
name: open-diagram
description: Draw a checked architecture diagram when the operator asks for a picture, or when a Solidity task finds open-diagram already active. Skip this when they only want a plugin created, smoked, or published.
---

# open-diagram

Use this when the operator asks for a diagram, map, or picture of how something fits together. Also use it from **`evm-foundry`** after Solidity source is written, and only when **`open-diagram`** is already an active MCP server. Plugin create, review, smoke, and publish do not need it. If the operator did not ask for a picture and this is not that Solidity case, do not load it.

## Load

1. **`agent_load_mcp_server`** with `{ "serverId": "open-diagram" }`.
2. Call **`open-diagram__format_guide`** once in the conversation before the first diagram.
3. Write JSON or Mermaid. Call **`open-diagram__check`** and fix every named layout problem until it reports 0.
4. Call **`open-diagram__draw`**. The node writes `data/diagrams/<name>.svg` and the node app opens that file in a diagram window. PNG is skipped on the node image because Chrome is not installed. Use **`open-diagram__describe`** to compare the picture with the request.

Do not pass Python. Do not invent owners, numbers, or statuses. Keep panel titles to two to four words.

The diagram is an illustration. If it disagrees with **`mpa-plugin-author`**, the plan file, or a `.sol` file, that file is the source of truth.
