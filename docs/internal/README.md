# Internal design notes

Engineering plans that span **mpc-repo** (`mpc-config`) and sibling projects (**mpc-auth**, **continuumdao-node-app**). These are not end-user documentation.

| Document | Contents |
|----------|----------|
| [NGROK_BROWSER_HTTPS_ATTACH_EVALUATION.md](./NGROK_BROWSER_HTTPS_ATTACH_EVALUATION.md) | Optional **ngrok** tunnel in front of Browser HTTPS **:8443** so the hosted app attaches over a **publicly trusted** URL without importing **webTLS** certs. Trial steps, JWT/CORS/Host-header notes, limitations — not part of install yet. |
| [EVM_TX_PARAMS_PROPOSAL_AND_TRIGGER.md](./EVM_TX_PARAMS_PROPOSAL_AND_TRIGGER.md) | Proposal vs trigger TxParams, `MessageHash` invariants, and cross-repo behavior. **Implemented in mpc-auth:** `proposal_tx_params` / optional `txParams` on create; **merge** at trigger into **`execute_tx_params`** (batch) or **`TxParams`** (single); **`GET ?tx_params=1`** returns merged or proposal. Sync with **API_IMPLEMENTATION.md** in this repo. |
