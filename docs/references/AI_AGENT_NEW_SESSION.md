# AI agent: new session and environment bootstrap

Use this checklist when an **agent session starts** and before relying on **`KEYGEN_ID`**, helpers under **`$MPA_PATH/scripts`**, or management API calls. It complements the **[MPA wallet skill](../skill/SKILL.md)** (`mpa-wallet` on Clawhub): same scope, egress, and security rules apply.

## What the mpa-wallet skill does

The skill drives **day-to-day** operation of an **MPC / MPA wallet** via the node’s **management API**: KeyGen messaging, building **`multiSignRequest`** bodies **only** with repo helpers, **`POST /multiSignRequest`** with Ed25519 **`clientSig`** / **`signedMessage`**, and EVM execution via **`executeSignResult.py`** only. It does **not** replace node installation or ContinuumDAO’s published setup guides.

## Read the environment first

1. Load **`$MPA_PATH/.env`** (if **`$MPA_PATH`** is unset, treat **`~/.mpa`** as the usual default and look for **`~/.mpa/.env`**).
2. If the file is **missing**, do not invent values: walk through the variables below with the operator.

### Variables if `.env` is missing or incomplete

| Variable | Required | Notes |
| -------- | -------- | ----- |
| **`KEYGEN_ID`** | Optional at first | MPC key / KeyGen identifier for signing and helpers. May be unset until the node is healthy and a key is chosen or created (see [KeyGen ID after health](#keygen-id-after-health)). |
| **`MPA_PATH`** | Yes | Agent workspace root (default suggestion: **`~/.mpa`**). Verify it exists or set it before continuing. |
| **`MPC_AUTH_URL`** | Yes | Base URL for the management API (typical: **`http://127.0.0.1`** or **`http://localhost`**). Must match where the node listens. |
| **`MANAGEMENT_PORT`** | Yes | Port for the management API (typical: **`8080`**). |
| **`AUTH_KEY_PATH`** | Yes | Directory containing the Ed25519 management key material used for API signing—see **`ED25519_MANAGEMENT_KEY_SIGNING.md`**; the skill expects **`mpc_auth_ed25519`** under this path (see skill metadata). Prefer a **dedicated** directory, not necessarily **`~/.ssh`**. |
| **`MPC_CONFIG_PATH`** | Yes | Path to the **git clone** of **`mpc-config`** (or equivalent) on the host—the tree that contains **`recipes/`**, **`references/`**, **`scripts/`**, **`tools/`**, and **`docs/`** (e.g. **`CONFIGURING_ED25519_KEYS.md`**) at its root. |

## Symlinks under `$MPA_PATH`

The helpers and docs are developed in the repo; **`$MPA_PATH`** often mirrors them via symlinks.

If **all** of these exist on disk under **`$MPC_CONFIG_PATH`**:

- **`recipes`**
- **`references`**
- **`scripts`**
- **`tools`**

…and the corresponding paths under **`$MPA_PATH`** are **not** yet symlinks pointing there, **create**:

1. `$MPA_PATH/recipes` → `$MPC_CONFIG_PATH/recipes`
2. `$MPA_PATH/references` → `$MPC_CONFIG_PATH/references`
3. `$MPA_PATH/scripts` → `$MPC_CONFIG_PATH/scripts`
4. `$MPA_PATH/tools` → `$MPC_CONFIG_PATH/tools`

Optionally symlink **`$MPC_CONFIG_PATH/docs`** → **`$MPA_PATH/docs`** if you want paths like **`$MPA_PATH/docs/CONFIGURING_ED25519_KEYS.md`** from the skill to resolve; otherwise use **`$MPC_CONFIG_PATH/docs/...`** directly.

If **any** destination directory is missing, the repo is probably not installed or **`MPC_CONFIG_PATH`** is wrong. Tell the operator and ask whether an **MPC node** (and this repo) is installed. If **not**, share the **ContinuumDAO** links listed under **Prerequisites** in **`../skill/SKILL.md`** (running a node, creating an MPC signer, Foundry skill).

## Confirm the node is up

Call **`GET $MPC_AUTH_URL:$MANAGEMENT_PORT/health`** (see **`API_IMPLEMENTATION.md`**) and treat a successful response as “node reachable on the configured URL and port.”

## KeyGen ID after health

If **`KEYGEN_ID`** is still unset after **`/health`** succeeds:

1. Ask the operator for an existing KeyGen / result ID to use, **or**
2. Offer to start a **new** KeyGen via **`POST /keyGenRequest`** (management-signed per **`ED25519_MANAGEMENT_KEY_SIGNING.md`**). Use the **`multi-agree`** style flow with the required curve/key-type fields as documented in **`API_IMPLEMENTATION.md`** (**`/keyGenRequest`**). Confirm **threshold** ( **`threshold`+1** nodes must agree). If several Ed25519 management keys are allow-listed, ask **which** key should sign the new request.

Follow with **`POST /keyGenRequestAgree`** from other nodes as required by the protocol; details are in **`instructions.md`** and **`API_IMPLEMENTATION.md`**. Check for the new KeyGen 2 minutes after all nodes have agreed and set KEYGEN_ID to the newly created KeyGen.
