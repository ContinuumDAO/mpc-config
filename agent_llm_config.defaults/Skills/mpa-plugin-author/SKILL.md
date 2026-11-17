---
name: mpa-plugin-author
description: Search, install, adapt, and create MPA Wallet plugins. Use when the operator wants a plugin from mpaplugins.continuumdao.org, a Pi/Claude/Codex package turned into this node's format, or a new plugin of their own.
---

# MPA plugin author

A plugin is a directory `user_folder/plugins/<name>/`. Installing it adds a slash prompt and one or more skills. The operator runs it with `/<name> …` or `agent_load_skill`. An optional `extension/index.js` (or `.ts`) runs in a Node worker only after the operator approves the permission card.

## Tools

These tools are added to the chat only after this skill is loaded. A plugin's own tools appear only after that plugin's skill is loaded, which its slash prompt asks for.

- `agent_search_plugins` — query the index. Optional `indexUrl` (https URL or a local `index.json` path).
- `agent_install_plugin` — `name` from the index, or `localPath` under `user_folder`. An index install is refused unless the package EIP-712 signature recovers to the KeyGen address in the index and the archive sha256 matches. The tool returns a recommendation from **`mpa-plugin-review`** and does not open the permission card.
- `agent_enable_plugin` / `agent_disable_plugin` / `agent_uninstall_plugin` — `agent_enable_plugin` with `confirmPermissions: true` is the permission card. Call it only after the operator has seen the review recommendation and asked to continue.
- `agent_adapt_plugin` — `path` under `user_folder` to a Pi, Claude (`.claude-plugin/plugin.json`), or Codex (`plugin.json`) package. Writes `mpa-plugin.json` and a slash prompt. Leaves the original manifest in place. Lists Pi APIs this worker does not run (`registerFlag`, providers, shortcuts).
- `agent_create_plugin` — local draft only. `name` (kebab-case) and `description`. Optional `skillBody` and `promptBody`. This does not publish.
- `agent_smoke_plugin` — `name` of a plugin in `user_folder/plugins`, `tool` as registered in the entrypoint, optional `arguments` object. Runs the files currently in that directory, including an edit from this turn. `agent_install_plugin` is not required first. Returns the result or the error. Does not enable the plugin or open the permission card. The first run does not grant net, shell, or writes. If that result needs one of those, or a Variable, the same call asks the operator and runs again with what they approved. The plugin stays off. DeFi and market-data subpaths in the manifest are available. If it returns an error in the plugin, or a result that does not do what was asked, fix the plugin and call it again in the same turn. A quoted error is not finished. A no-error result that does not do the job is not finished. If the tool says a permission or a Variable is missing, do not edit the plugin. Call it again. That asks the operator, stores the Variable without showing the value, and smokes again. A decline is not finished. The plan Smoke check is frozen at Execute. Call this tool with that Tool and those Arguments. The host checks Expect. Do not edit the Smoke check. Do not catch an error and return a clean string. Do not retry the same entrypoint into a pass. Do not enable the plugin.
- `agent_create_plugin` writes `README.md` next to the skill and the slash prompt. Edit that README so it describes the plugin. It is part of the directory the operator publishes.
- `agent_export_plugin_for_github` — call this when the operator wants to publish and does not yet have a commit. It checks the installed plugin and tells them to click **Download for GitHub** on AI Plugins. That archive is the plugin directory publish will compare. Repeat those steps. Do not push from the node.
- `agent_create_plugin_new_version` — publish the local plugin after the operator has pushed. The download omits `.trust.json`, `.mpa-state.json`, and `.position-state.json`. The commit must contain the same files as that archive, including `README.md`. Do not add a file only on GitHub. The commit does not need `version`, `versionDate`, `nodeKey`, `veCtmId`, `groupId`, or `keyGenAddress`. Pass `repository` (`https://github.com/owner/name`), the full 40-character `commit`, and `path` when the plugin is a directory inside the repository. The tool writes the release stamp into `mpa-plugin.json` and the catalog ignores those six fields when it compares the commit. A private repository cannot be published. The node must have veCTM privilege, and `keyGenId` (or the preferred KeyGen) must be a multi-agree KeyGen in that GroupId. The first release is `v1.0.0` even when the working manifest uses a later version. A later catalog version must be greater, must use the same repository and path, and must be signed by the same KeyGen, veCTM id, and GroupId. The tool opens a `multiSignRequest`. After members `signRequestAgree` and the signature is triggered, call it again with `requestId`.
- `agent_update_plugin` — replace the installed copy with the repository's current signed version. Older packages remain in the repository. A changed entrypoint needs approval again.

`mpa-plugin.json` on a published package includes `nodeKey`, `veCtmId`, `groupId`, `keyGenAddress`, `version` (`v1.2.3`), and `versionDate` (`YYYY-MM-DD`). The repository index keeps those fields plus the EIP-712 `digest` and `signature`, and a `versions` list of older releases.

Do not claim an entrypoint is running until the operator has approved it. Do not put key material, bootstrap, or signing endpoints in a plugin.

## Review before approval

Before `agent_install_plugin`, `agent_update_plugin`, or `agent_enable_plugin`, load **`mpa-plugin-review`**. Tell the operator its install or do-not-install recommendation first, including each risk and the `accept` or `reject` rule from **`mpa-plugin-review.yaml`**. Ask whether they want to continue. Only after they explicitly say yes, call `agent_enable_plugin` with `confirmPermissions: true`. That opens the permission card. Do not open it in the same step as the recommendation.

## Package

```text
plugins/<name>/
  mpa-plugin.json
  skills/<name>/SKILL.md
  prompts/<name>.md
  extension/index.js    # optional
```

`mpa-plugin.json` fields: `name`, `version`, `description`, `skills`, `prompts`, optional `mcp`, optional `entrypoint`, `permissions`, optional `defiModules`, optional `marketModules`, optional `variables`, optional `agentReputation`. `skills` is `["skills/<name>"]`. `prompts` is `["prompts/<name>.md"]`. A bare name is expanded to that path when the manifest is read or saved. A published package also has `versionDate`, `nodeKey`, `veCtmId`, `groupId`, and `keyGenAddress`.

`variables` lists Variable names. The entrypoint checks `pi.variableConfigured(name)`, which is true or false. It does not receive the value.

`pi.preferredKeyGenAddress()` returns the node's current preferred KeyGen Ethereum address (`0x` and 40 hex characters). The host resolves it when the tool or hook runs. It throws when no preferred KeyGen is set. Do not import the node SDK to read it, and do not hard-code an address. Use a different address only when the operator named one.

`import { Interface, Contract, JsonRpcProvider, parseUnits } from 'ethers'` is available. The node image supplies the package. Do not construct `Wallet`, `HDNodeWallet`, `SigningKey`, or a mnemonic. Those throw, because a plugin has no private key. Encode the call, then return `pi.signRequest({ chainId, to, data, value, purpose })`. That opens a multiSignRequest for the preferred KeyGen. `purpose` is the text the group reviews. Nothing is broadcast until members accept it. A `JsonRpcProvider` needs `net:https`. Import the package root `ethers`, not a subpath.

`import express from 'express'` is available. Use `express.json()` and `app.get`, `app.post`, `app.put`, `app.patch`, and `app.delete` for routes. `app.listen` needs `net:https` in the manifest and listens on `127.0.0.1`. Import the package root `express`, not a subpath. The review lists an Express import as network. A POST, PUT, PATCH, or DELETE route or fetch is an `http-post`, `http-put`, `http-patch`, or `http-delete` finding. The shipped rule for each is reject.

`import { z } from 'zod'` is available. Use it to check a request body or a tool argument. Import the package root `zod`, not a subpath.

`secrets` binds a Variable name to a library argument: `{ "variable": "MY_API_KEY", "field": "apiKey", "exports": ["myQuote"] }`. `exports` limits the fill to those functions. Omit `exports` to fill that argument on every function from an imported module. DeFi modules also export `trustedVariableBindings` for their own arguments. The host reads those bindings and substitutes the Variable inside the worker, the same way a chart fetch substitutes `THE_GRAPH_API_KEY` without showing it. You do not copy a library binding into `variables` or `secrets` for that fill to happen, and you do not pass the value as a tool argument. `pi.variableConfigured(name)` stays true or false. The entrypoint never receives the value.

Chat OHLCV tools (`ctm_*_fetch_ohlcv` and any slim `agentView`) return a summary. Candle rows are not in that JSON. A plugin that needs the rows calls the library export in the entrypoint (`uniswapV4FetchOhlcv` returns `candles`). Do not tell the agent to pass the chat summary in as `candles`.

`agentReputation` reserves the EIP-8004 identity. When present, `standard` is `EIP-8004`. Optional `chainId`, `agentRegistry` (`eip155:<chainId>:0x…`), and `agentId` are stored for a later reputation check and are not resolved now.

Install and update scan JavaScript, TypeScript, shell scripts, and skill or prompt instructions. Findings cover process execution, filesystem access, network, tool hooks, and requests that the agent run a shell, fetch a URL, or write files. The plugin stays off until the operator approves that list. The Node process can read `user_folder` after a filesystem read or write was accepted, and can write there after a write was accepted. Network is allowed for `net:https` or accepted network code. Child processes are allowed for `process:spawn` or accepted process-execution code. A skill or prompt that mentions a shell or a URL requires approval and does not by itself open those rights. Paths outside `user_folder` stay blocked.

Permissions: `user_folder:read` (default), `user_folder:write`, `net:https`, `process:spawn`, `hooks:before_tool`, `hooks:session`.

The worker entrypoint exports a default function:

```js
export default function (pi) {
  pi.registerTool({ name, description, parameters, async execute(args) { return 'text' } })
  pi.registerCommand(name, { description })
  pi.on('session_start', (_event, ctx) => { ctx.ui.notify('ready', 'info') })
  pi.on('session_shutdown', () => {})
  pi.on('tool_call', (event) => {
    if (event.toolName === 'agent_bash') return { block: true, reason: 'blocked' }
  })
}
```

Tool names are exposed as `plugin_<name>_<tool>`. The worker does not receive management keys or a private key. `pi.signRequest` opens a multi-sign request the group reviews. `fetch` throws unless network was granted.

## Libraries

Leave `defiModules` and `marketModules` off when the plugin only needs its own code. `hello-mpa` is that shape. Name a subpath only when the entrypoint imports it. The node image supplies the packages. The plugin does not run `npm install`.

In a normal chat, if this plugin needs `find_library_function`, a library export, or an entrypoint import, stop and tell the operator to open a plan and choose Create a plugin. Do not search from that chat. In a plugin plan, the specialist calls `find_library_function`. It returns the import path, the export name, the purpose, the arguments, and the return fields. Load **`mpa-plugin-libraries`** for the full list. Use the export name. Do not call `ctm_*` tools or `load_defi_protocol` from the entrypoint, and do not import `@continuumdao/continuum-node-sdk`. An import that is not listed throws. A subpath has no leading slash, and `..` is refused.

```js
export default async function (pi) {
  const aero = await pi.importDefi('protocols/evm/aerodrome')
  pi.registerTool({
    name: 'quote',
    async execute(args) {
      const quoted = await aero.aerodromeQuote(args)
      return JSON.stringify(quoted)
    },
  })
}
```

`importDefi('protocols/evm/aerodrome')` requires `defiModules` to include `protocols/evm/aerodrome`. The tool returns that result. A build export returns an unsigned payload. The agent opens the sign request afterwards. `build_trade_from_*` stays an agent tool. Technical analysis exports (`calculateTechnicalIndicator`, `analyzeMovingAverages`, `tradeIdeaFromAnalyzeOutput`) are in the same index under market data.

## Index

`https://mpaplugins.continuumdao.org/index.json` lists the current package for each name: `name`, `version`, `versionDate`, `description`, `downloads`, `source`, `sha256`, `repository`, `commit`, `commitUrl`, `permissions`, `nodeKey`, `veCtmId`, `groupId`, `keyGenAddress`, `digest`, and `signature`. `downloads` is how many times that version’s package was fetched. The host keeps the counter beside the catalog and copies it onto each record when the index is read. It is not part of the signed release. `commitUrl` opens the public GitHub tree for that commit. `versions` keeps older releases. Publish with `POST /publish` on that host (`MPA_PLUGINS_PUBLISH_URL`). The host checks the signature before it replaces the current entry. Until that host exists, pass `indexUrl` or install from a local directory. A bundled example lives at `agent_llm_config.defaults/plugins/hello-mpa` in the mpc-config tree. Copy it under `user_folder` before `agent_install_plugin`. The Node page AI Plugins section lists published plugins and plugins already on the node. Install and publish stay in node chat.

## Prompt

The shipped prompt is the explicit invocation. Its body should tell the agent to load the plugin skill and apply `$ARGUMENTS`. Keep `argument-hint` in the frontmatter.
