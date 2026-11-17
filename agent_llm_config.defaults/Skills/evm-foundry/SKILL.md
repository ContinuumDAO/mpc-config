---
name: evm-foundry
description: Solidity under evm/. The host requires the official Etherscan MCP server with an API key, a node chain with an RPC, and a Foundry profile. A written .sol file is not done. Dry-run forge on a fork of that RPC, check KeyGen gas without broadcasting, then create the deploy multi-sign request. The operator can call that tool later.
---

# EVM Foundry

Load when the operator asks for a Solidity contract, a Foundry test, or a forge script under `evm/`.

Before coding, the host asks the operator to confirm the Foundry profile and one EVM chain that is already configured on this node (it must have an RPC). The official Etherscan MCP server (`https://mcp.etherscan.io/mcp`) must be enabled with `ETHERSCAN_API_KEY`. The community server does not replace it. The Solidity version can be one that is not installed yet; the host downloads it into `.svm/`. The form offers `optimizer` true, `optimizer_runs` 200, `via_ir` true, and `gas_limit` 10_000_000_000. Those answers are pinned in `evm/foundry.toml`. Use that compiler in the source pragma. Do not change these settings.

The end-to-end run is a dry-run on a fork of that chain RPC, cwd `evm/`: `forge test --fork-url` or `forge script` with `--rpc-url` and no `--broadcast`. Read the preferred KeyGen native balance on that chain. It must cover the dry-run estimate. Do not broadcast to discover the cost. After that dry-run, offer a QuillShield audit once (load `evm-audit`). A decline still calls `continuum__deploy_built_contract_multi_sign_request` with the dry-run `run-latest.json`. That tool is not in the forge bundle. Find it with `continuum__search_continuum_tools` or call it by name. That multi-sign request is the deployment. The operator can call the same tool later. After the request is executed and the contract is on chain, verify the source with the official Etherscan server.

A file under `evm/` is not finished work.

**Done** is a dry run on a fork of the chosen node chain, from `agent_bash` with **cwd** `evm/`:

1. `forge test --fork-url` with that chain's RPC
2. `forge script` with `--rpc-url` or `--fork-url` set to that RPC, and no `--broadcast`

Read the preferred KeyGen native balance on that chain. It must cover the dry-run estimate. Do not broadcast to discover the cost. After that dry-run, offer a QuillShield audit once. Load `evm-audit`. A decline still calls `continuum__deploy_built_contract_multi_sign_request`. That multi-sign request is the deployment, and the operator can call the same tool later.

On success, say so. On revert, quote the revert reason from that output. Do not claim the run passed when it reverted.

**Rewrite only.** When the task changes an existing contract, also compare the old bytecode (`cast code`) or an old `cast call` with the new one, and report both. A new contract does not need that comparison.

Do not treat `forge build`, a written source file, or `forge --broadcast` as the deployment. The deployment is `continuum__deploy_built_contract_multi_sign_request`.
