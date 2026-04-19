# Internal design notes

Engineering plans that span **mpc-repo** (`mpc-config`) and sibling projects (**mpc-auth**, **continuumdao-node-app**). These are not end-user documentation.

| Document | Contents |
|----------|----------|
| [EVM_TX_PARAMS_PROPOSAL_AND_TRIGGER.md](./EVM_TX_PARAMS_PROPOSAL_AND_TRIGGER.md) | Proposal vs trigger TxParams, `MessageHash` invariants, and cross-repo behavior. **Implemented in mpc-auth:** `proposal_tx_params` / optional `txParams` on create; **merge** at trigger into **`execute_tx_params`** (batch) or **`TxParams`** (single); **`GET ?tx_params=1`** returns merged or proposal. Sync with **API_IMPLEMENTATION.md** in this repo. |
