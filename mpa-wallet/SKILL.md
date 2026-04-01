---
name: mpa-wallet-agent
description: >
  Manage Multi-Party Agent (MPA) Ethereum wallets via MPC threshold signatures.
  Use when an AI agent needs to operate a KeyGen wallet on a co-located MPC node,
  including creating and reviewing multi-sign requests, reading on-chain state
  with Foundry cast, communicating with other nodes via the KeyGen messaging
  channel, and managing chain configs, tokens, and known addresses. Triggers on
  MPA wallet operations, multiSignRequest flows, KeyGen messaging, on-chain
  queries for MPC wallets, and Ed25519-signed management API calls.
---

# MPA Wallet Agent

Compact recipe for AI agents managing MPC wallets on a co-located node.
All POST requests use Ed25519 management key signing (never MetaMask).

## 1 — Bootstrap

### 1.1 KeyGen ID

Read `KEYGEN_ID` from `~/.env`. If absent, ask the user for it, then write it:

```bash
echo "KEYGEN_ID=<value>" >> ~/.env
```

### 1.2 Ed25519 Key

Private key lives at `~/.ssh/mpc_auth_ed25519` (PEM or OpenSSH, chmod 600).
Confirm the corresponding public key is registered on the node:

```bash
curl -s http://localhost:8080/getPublicMgtKey | jq .
```

The response is an array of 64-hex public keys. One must match the agent's key.

### 1.3 Foundry

Foundry (forge + cast) is a hard dependency. Install if missing:

```bash
curl -L https://foundry.paradigm.xyz | bash && foundryup
```

Verify: `forge --version && cast --version`

### 1.4 Node API

Default base URL: `http://localhost:8080`
Health check: `curl -s http://localhost:8080/health | jq .`

## 2 — KeyGen Info

```bash
curl -s "http://localhost:8080/getKeyGenResultById?id=$KEYGEN_ID" | jq .Data
```

Key fields in `.Data`:
- `ethereumaddress` — the MPC wallet address
- `pubkeyhex` — MPC public key (128 hex), called `pubKey` in multiSignRequest
- `keylist` — array of node keys (128 hex each)
- `Threshold` — threshold+1 nodes must agree to sign
- `globalnonce` — count of signatures created for this KeyGen
- `ClientKeys` — map of node key → client key (Ed25519 64-hex or Ethereum address)

The agent's node key is the key in `ClientKeys` whose value matches the agent's
Ed25519 public key (64 hex from `getPublicMgtKey`).

## 3 — Context: What Happened Before

Before acting, read existing context. Filter by your KeyGen ID.

### 3.1 Sign request history

```bash
curl -s "http://localhost:8080/listSignRequests" | jq '.Data[] | select(.KeyGenRequestId=="'$KEYGEN_ID'")'
```

Status values: `live`, `pending`, `blocked`, `shelved`, `success`.
Key fields: `Purpose` (originator's description), `Thoughts` (per-node comments),
`DestinationChainID`, `DestinationAddress`, `SignatureText`, `BatchSize`.

### 3.2 Sign results (executed transactions)

```bash
curl -s "http://localhost:8080/listSignResults" | jq '.Data[] | select(.KeyGenRequestId=="'$KEYGEN_ID'")'
```

Includes `transactionhash` for executed transactions.

### 3.3 Messages

```bash
curl -s "http://localhost:8080/listMessages?keyGenId=$KEYGEN_ID" | jq .
```

**Always read messages before acting.** Messages are persistent context shared
across all nodes and survive agent/LLM changes. See [references/messaging.md](references/messaging.md).

## 4 — On-Chain Queries (Foundry cast)

Always use `cast` for on-chain data. Get the RPC URL from chain config:

```bash
RPC=$(curl -s "http://localhost:8080/getChainDetails?chain_id=59144" | jq -r '.Data.rpcGateway')
```

### 4.1 Balance

```bash
cast balance $WALLET_ADDRESS --rpc-url $RPC
cast from-wei $(cast balance $WALLET_ADDRESS --rpc-url $RPC)
```

### 4.2 Blockchain nonce (current tx count)

```bash
cast nonce $WALLET_ADDRESS --rpc-url $RPC
```

This is the nonce to use with `--first-nonce` in forge scripts. Do NOT confuse
with `globalnonce` (which counts MPC signatures, not blockchain transactions).

### 4.3 Registration and fees

See [references/fees.md](references/fees.md) for the full fee contract interface.

```bash
# Is the KeyGen registered?
cast call 0x55aD6Df6d8f8824486C3fd3373f1CF29eCecF0A3 \
  "isRegistered(address)(bool)" $WALLET_ADDRESS --rpc-url $RPC

# Fee config for this KeyGen
cast call 0x55aD6Df6d8f8824486C3fd3373f1CF29eCecF0A3 \
  "keyGenFeeConfig(address)(address,uint256,uint256,uint256,bytes32)" \
  $WALLET_ADDRESS --rpc-url $RPC

# Global nonce (for getRemainingNonces)
GNONCE=$(curl -s "http://localhost:8080/getGlobalNonceByKeyGenId?id=$KEYGEN_ID" | jq -r '.Data.globalnonce')

# Remaining signatures before top-up
cast call 0x55aD6Df6d8f8824486C3fd3373f1CF29eCecF0A3 \
  "getRemainingNonces(address,uint256)(uint256)" $WALLET_ADDRESS $GNONCE --rpc-url $RPC
```

## 5 — Ed25519 Signing Pattern

All management POST endpoints follow the same pattern.

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import json, requests

API = "http://localhost:8080"

def load_key():
    with open("~/.ssh/mpc_auth_ed25519".replace("~", __import__("os").path.expanduser("~")), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def get_nonce(pub_key_hex):
    r = requests.get(f"{API}/getPublicMgtKeyNonce", params={"publicKey": pub_key_hex})
    return r.json()["Data"]["nonce"]

def sign_and_post(endpoint, body, sig_field="sig"):
    """Sign body[sig_field]="" canonical JSON, fill signature, POST."""
    key = load_key()
    body[sig_field] = ""
    canonical = json.dumps(body, separators=(",", ":"), sort_keys=False).encode()
    body[sig_field] = key.sign(canonical).hex()  # 128 hex
    return requests.post(f"{API}/{endpoint}", json=body)
```

For endpoints using `clientSig` + `signedMessage` (e.g. multiSignRequest,
signRequestAgree), set both to `""` before signing, then fill `clientSig`
with the 128-hex signature and leave `signedMessage` empty (the backend
recomputes canonical JSON for Ed25519 verification).

## 6 — Creating Transactions (multiSignRequest)

### 6.1 Write a Forge script

```bash
forge script ./script/YourScript.s.sol:YourContract \
  --rpc-url $RPC \
  --sender $WALLET_ADDRESS
```

Do NOT use `--broadcast` (the MPC address has no private key).
Output: `broadcast/YourScript.s.sol/<chain_id>/run-latest.json`

### 6.2 Convert to multiSignRequest payload

```bash
NONCE=$(cast nonce $WALLET_ADDRESS --rpc-url $RPC)

python3 ~mpcnode/mpc-config/scripts/generateSignRequestWithFoundryScript.py \
  --key-gen-id=$KEYGEN_ID \
  --file=broadcast/YourScript.s.sol/<chain_id>/run-latest.json \
  --first-nonce=$NONCE \
  --purpose="Description of what this transaction does" \
  --mpc-auth-url=http://localhost:8080
```

Requires `pip install eth_account`. Output is JSON with `endpoint` and `body`.

### 6.3 Sign and submit

Take `body` from the script output. Add `clientSig`:

```python
body = script_output["body"]  # already has keyList, pubKey, hashes
body["clientSig"] = ""
body["signedMessage"] = ""
canonical = json.dumps(body, separators=(",", ":")).encode()
body["clientSig"] = private_key.sign(canonical).hex()
resp = requests.post(f"{API}/multiSignRequest", json=body)
request_id = resp.json()["Data"]  # e.g. "Sign20260401..."
```

### 6.4 Communicate to the group

After submitting, send a message explaining the request:

```python
sign_and_post("sendMessage", {
    "keyGenId": KEYGEN_ID,
    "title": "New sign request: <short description>",
    "body": "I've proposed <details>. Request ID: <request_id>. Please review.",
    "Nonce": get_nonce(MY_PUBLIC_KEY),
    "Sig": ""
})
```

## 7 — Reviewing & Agreeing to Requests

When another node creates a sign request, review it:

```bash
curl -s "http://localhost:8080/getSignRequestById?id=$REQUEST_ID" | jq .
```

Examine `Purpose`, `SignatureText`, `DestinationChainID`, `DestinationAddress`.
Use cast/web search to verify the target contract and parameters.

### Accept

```python
sign_and_post("signRequestAgree", {
    "requestId": REQUEST_ID,
    "clientSig": "",
    "signedMessage": "",
    "accept": True,
    "thoughts": "Verified destination contract on explorer"
}, sig_field="clientSig")
```

### Reject

```python
sign_and_post("signRequestAgree", {
    "requestId": REQUEST_ID,
    "clientSig": "",
    "signedMessage": "",
    "accept": False,
    "thoughts": "Risk assessment: <reason>"
}, sig_field="clientSig")
```

## 8 — Triggering & Executing

Once threshold+1 nodes agree, the originator triggers:

```bash
# Check readiness
curl -s "http://localhost:8080/isSignRequestReadyById?id=$REQUEST_ID" | jq .Data.ready
```

```python
sign_and_post("triggerSignRequestById", {
    "requestId": REQUEST_ID,
    "nonce": get_nonce(MY_PUBLIC_KEY),
    "sig": ""
})
```

After triggering, poll for the result:

```bash
curl -s "http://localhost:8080/getSignResultById?id=$REQUEST_ID" | jq .
```

Then update status after broadcast:

```python
sign_and_post("updateSignResultStatusById", {
    "requestId": REQUEST_ID,
    "status": "executed",
    "transactionHash": "0x...",
    "nonce": get_nonce(MY_PUBLIC_KEY),
    "sig": ""
})
```

## 9 — Shelving a Request

If feedback from nodes (Thoughts) suggests abandoning:

```python
sign_and_post("shelveSignRequest", {
    "RequestId": REQUEST_ID,
    "Nonce": get_nonce(MY_PUBLIC_KEY),
    "Sig": ""
}, sig_field="Sig")
```

## 10 — Chain, Token & Address Management

```bash
# List chains
curl -s http://localhost:8080/getChainDetails | jq .

# List tokens
curl -s http://localhost:8080/getTokens | jq .

# List known addresses
curl -s http://localhost:8080/getKnownAddresses | jq .
```

To add a chain, token, or address, use the corresponding POST endpoints
with Ed25519 signing. See [references/api-reference.md](references/api-reference.md).

## Key Rules

1. **Always read messages and sign request history before acting.**
2. **Communicate every action via the messaging channel** so context persists.
3. **Use cast for all on-chain queries** — never external APIs like Etherscan.
4. **Blockchain nonce != globalnonce.** Use `cast nonce` for `--first-nonce`.
5. **threshold+1 nodes must agree** before a signature can be triggered.
6. **Only the originator can trigger and update** sign results.
7. **Purpose and Thoughts are critical context** — write clear ones, read others'.
