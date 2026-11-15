---
name: mpa-plugin-review
description: Recommend whether to install or update an MPA plugin before any permission approval. Use for "should I install this plugin?" the way continuum-dao-vote-policy answers "should I vote?". Follow host YAML mpa-plugin-review.yaml. Never approve permissions in the same step as the recommendation.
---

# MPA plugin review

Load before `agent_install_plugin`, `agent_update_plugin`, or `agent_enable_plugin`, and whenever the operator asks whether a plugin should be installed. Also load **`mpa-plugin-author`** so the plugin tools are available.

This skill does not approve permissions and does not enable a plugin. It appraises the security review the same way **`continuum-dao-vote-policy`** appraises a proposal.

## pluginReview (edit on this node)

Machine-editable defaults live in host YAML **`mpa-plugin-review.yaml`** (`kind=mpa-plugin-review`). Edit via the Skills tab **Host YAML configs** row, or `POST /upsertHostYamlConfig`. The node injects the installed file when this skill loads. Follow that YAML. The example below is the cautious default.

```yaml
pluginReview:
  version: 1
  defaultAction: reject
  cleanAction: accept
  risks:
    entrypoint: reject
    shell: reject
    net: reject
    fs-read-user: reject
    fs-read-outside: reject
    fs-write-user: reject
    fs-write-outside: reject
    hook-before-tool: reject
    skill-shell: reject
    skill-net: reject
    skill-write: reject
    key-material: reject
    protocol-library: reject
    http-post: reject
    http-put: reject
    http-patch: reject
    http-delete: reject
```

Each value is `accept` or `reject`. `defaultAction` applies when a finding has no rule. `cleanAction` applies when the audit has no risk findings. A missing rule uses `defaultAction`.

`defiModules` and `marketModules` are not risk ids. When the manifest lists them, name each subpath in the recommendation. They allow the entrypoint to import `@continuumdao/ctm-mpc-defi` and `@continuumdao/ctm-market-data`. They do not grant management keys or open a sign request.

`protocol-library` means the entrypoint names a protocol the library already covers and builds that call with `Interface`, `encodeFunctionData`, or `pi.signRequest` without `pi.importDefi` of that protocol's module. The library export is the path that keeps the protocol's approve, slippage, and batch steps.

`http-post`, `http-put`, `http-patch`, and `http-delete` mean the package sends or accepts that method: an Express route, a `fetch` or request whose method is that verb, or a shell `curl -X` of that verb. Each shipped rule is reject. GET is not one of these findings.

## Appraisal

1. Install or update first. Those tools copy the package and return the audit plus a recommendation. They do not open the permission card.
2. Tell the operator the recommendation before anything else: **install** or **do not install**. List every risk finding with its `accept` or `reject` rule and the file location. Quote the installed YAML. Do not soften a `reject` into a yes.
3. **do not install** when any listed rule is `reject`, or when `cleanAction` is `reject` and there are no findings. **install** when there are no findings and `cleanAction` is `accept`, or when every listed rule is `accept`.
4. Stop there. Ask whether they want to continue to the permission card.
5. Only after they explicitly say yes, call `agent_enable_plugin` with `confirmPermissions: true`. That opens the permission card. A `reject` recommendation does not forbid that later step. An `accept` recommendation does not skip it when the audit listed risks.
6. Approving a finding that reads or writes outside `user_folder` still does not open those paths. Say that when such a finding is in the list.

Do not call `agent_enable_plugin` with `confirmPermissions: true` in the same turn as the recommendation.
