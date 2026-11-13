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
- `agent_create_plugin_new_version` — publish the local plugin. The node must have veCTM privilege, and `keyGenId` (or the preferred KeyGen) must be a multi-agree KeyGen in that GroupId. The first release is `v1.0.0`. A later version is chosen by the author, must be greater, and must be signed by the same KeyGen, veCTM id, and GroupId. The tool opens a `multiSignRequest`. After members `signRequestAgree` and the signature is triggered, call it again with `requestId`.
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

`mpa-plugin.json` fields: `name`, `version`, `description`, `skills`, `prompts`, optional `mcp`, optional `entrypoint`, `permissions`, optional `agentReputation`. A published package also has `versionDate`, `nodeKey`, `veCtmId`, `groupId`, and `keyGenAddress`.

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

Tool names are exposed as `plugin_<name>_<tool>`. The worker does not receive management keys or signing RPCs. `fetch` throws unless network was granted.

## Index

`https://mpaplugins.continuumdao.org/index.json` lists the current package for each name: `name`, `version`, `versionDate`, `description`, `source`, `sha256`, `permissions`, `nodeKey`, `veCtmId`, `groupId`, `keyGenAddress`, `digest`, and `signature`. `versions` keeps older releases. Publish with `POST /publish` on that host (`MPA_PLUGINS_PUBLISH_URL`). The host checks the signature before it replaces the current entry. Until that host exists, pass `indexUrl` or install from a local directory. A bundled example lives at `agent_llm_config.defaults/plugins/hello-mpa` in the mpc-config tree. Copy it under `user_folder` before `agent_install_plugin`, or install that absolute path from the Plugins tab.

## Prompt

The shipped prompt is the explicit invocation. Its body should tell the agent to load the plugin skill and apply `$ARGUMENTS`. Keep `argument-hint` in the frontmatter.
