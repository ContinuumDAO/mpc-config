# KeyGen Messaging API

KeyGen messaging lets nodes in a keyGen (participants in that key’s `KeyList`) send and read short messages in a per-keyGen channel. 
**Response format and general API conventions** (base URL, logging, `APIResponse` shape) follow the main `./API_IMPLEMENTATION.md`.

## Overview

A simple messaging system between all nodes that participated in a given **keyGen** (identified by `keyGenId`, i.e. the KeyGen result’s `requestId`). Only nodes whose public key is in that keyGen’s `KeyList` can send and receive messages in that keyGen’s channel.

---

## Scope

- **Scope**: Messages are scoped by **keyGen**, not by GroupId. Each keyGen has its own message channel; participants are the nodes in that keyGen’s `KeyList`.
- **Participants**: Only nodes that are in the keyGen’s `KeyList` can list, send, read, and mark messages as read for that keyGen.

---

## Message Model

### Message identity

- **`id`**: Unique message identifier. **Recommended**: `SHA256(hex(node_public_key) || "." || canonical_timestamp)` encoded as hex, so that (sender + time) is collision-resistant and verifiable. Alternatively, a UUID if you prefer randomness over determinism.

### Top-level vs reply

- **Top-level message**: Has a **`title`** field (required). No `replyTo`.
- **Reply**: Has **`replyTo`** set to the `id` of the message being replied to. No `title` (or `title` omitted/empty).

### Content and metadata

- **`body`** (or `content`): Plain text, **max 512 characters** (UTF-8).
- **`senderNodeKey`**: Node public key (hex) of the sender. Must be in the keyGen’s `KeyList`.
- **`keyGenId`**: KeyGen request/result id (same as KeyGen result’s `requestId`) this message belongs to.
- **`createdAt`**: Timestamp when the message was created; **always UTC** (e.g. ISO8601 with Z or Unix ms).

### Read receipts

- **`read`**: Array of **read receipts**. Each receipt is:
  - **`nodeKey`**: Node public key (hex) that read the message.
  - **`signature`**: Signature over a canonical string (e.g. `messageId` or `messageId || keyGenId`) using that node’s **node client key**, so other nodes can verify that this node acknowledged reading.
- When a node reads a message, it adds its receipt and **broadcasts the updated message (or just the new receipt)** to the other nodes in the keyGen so they can update their copy.

### Deletion

- **Only the message originator** (the node whose public key equals `senderNodeKey`) may delete a message. No other node can delete it.
- When the originator deletes a message, **that message and all its replies** are deleted (the whole sub-tree: the message and every reply that has `replyTo` pointing to it or to any reply in that tree). Other messages in the keyGen are unchanged.
- Deletion can be hard (remove from store) or soft (mark as deleted and omit from list/get). Either way, list and getMessageThread must not return deleted messages.

---

## Authorization

- Every endpoint requires that the **calling node** (the node serving the API) is in the keyGen’s **KeyList**. The server resolves `keyGenId` to the keyGen result and checks `p.NodeKey.PublicKey ∈ KeyList`. If not, the response is **403** with an error message.
- **Delete** is only allowed for the **message originator** (`senderNodeKey` equals the calling node’s public key). Otherwise **403**.

### Management key signature (sendMessage, markMessageRead, multiMarkMessagesRead, deleteMessage, multiDeleteMessages)

These five endpoints require a **management key signature** in the request body: **`Nonce`** and **`Sig`**. The signature type depends on the **client key** for this node in the keyGen (from the keyGen’s `ClientKeys`):

- **If the client key is an Ethereum address** (Ethereum wallet): sign the request payload (exact JSON of the body with `Sig` set to `""`) using **`personal_sign`** (EIP-191) from the node’s management address (`NodeMgtKey`). Obtain the next nonce via `GET /getNodeMgtKeyNonce` — response `Data` is `{ "key": "<NodeMgtKey 0x…>", "nonce": <int> }` (same Ethereum address as `GET /getNodeMgtKey`). See `GET /getMessageToSign` in `./API_IMPLEMENTATION.md` for the signing flow.
- **If the client key is Ed25519** (64 hex): sign the same payload with the **Ed25519** management key (config `PublicMgtKey` or a key added via `POST /addManagementKey`). Signature must be 128 hex characters. Use `GET /getAllowedEd25519MgtKeys` and `GET /getPublicMgtKeyNonce` (optional `?publicKey=<64_hex>` for added keys) for nonce — **not** `getNodeMgtKeyNonce`, which tracks only the Ethereum `NodeMgtKey`. See `./API_IMPLEMENTATION.md` for Ed25519 mgt auth.
- If the client key is missing or of another form, the server accepts **either** Ethereum wallet (`NodeMgtKey` / `personal_sign`) or Ed25519 (same as other mgt-protected endpoints).

The server verifies the signature and consumes the nonce (replay protection). If signature check is disabled via config (`IgnoreMgtKeySigCheck`), the body may omit `Nonce` and `Sig`.

---

## Endpoints

### `POST /sendMessage`

Creates a new message (top-level or reply) in the keyGen channel. **Requires management key signature** (see above).

**Request body (JSON):**

| Field     | Type   | Required | Description |
|----------|--------|----------|-------------|
| `Nonce`    | int    | Yes (mgt) | Next nonce for **this** signer: **Ethereum / NodeMgtKey** → `GET /getNodeMgtKeyNonce` (`Data.nonce` for `NodeMgtKey`). **Ed25519** → `GET /getPublicMgtKeyNonce` (optional `?publicKey=`). Sequences are independent. |
| `Sig`      | string | Yes (mgt) | Signature over the exact JSON of this body with `Sig` set to `""` (Ethereum wallet `personal_sign` or Ed25519 128-hex). |
| `keyGenId` | string | Yes | KeyGen request/result id (keyGen channel). |
| `title`    | string | For top-level | Required for top-level messages; omit or empty for replies. |
| `replyTo`  | string | For replies | Message `id` this reply targets. |
| `body`     | string | Yes | Message text; max **512** characters (UTF-8). |

**Validation:**

- Top-level: `title` required, `replyTo` empty/omitted.
- Reply: `replyTo` required and must reference an existing message in the same keyGen; `title` must be empty/omitted.
- **Rate limit:** 6 messages per minute per (keyGenId, node). Exceeding returns **429**.

**Response (200):** `data` is the created message object (`id`, `keyGenId`, `senderNodeKey`, `title`/`replyTo`, `body`, `createdAt` UTC, `read: []`).

**Errors:** 400 (validation), 403 (not in KeyList), 404 (keyGen not found), 409 (duplicate message id), 429 (rate limit), 401 (invalid or missing mgt signature).

---

### `GET /listMessages`

Returns a paginated list of messages for the keyGen.

**Query parameters:**

| Parameter   | Type   | Required | Description |
|------------|--------|----------|-------------|
| `keyGenId` | string | Yes | KeyGen channel. |
| `unread`   | bool   | No | If `true`, only messages the calling node has not marked read. |
| `fromTime` | string | No | Inclusive lower bound for `createdAt` (UTC). |
| `toTime`   | string | No | Inclusive upper bound for `createdAt` (UTC). |
| `top_level` | bool  | No | If `true`, only top-level messages (have `title`). |
| `pagenum`  | int    | No | 1-based page (default 1). |
| `pagesize` | int    | No | Page size (default 20, max 100). |

**Response (200):** `data` is `{ "list": [ ...messages ], "total": N }`. Order: `createdAt` descending.

**Errors:** 400 (missing keyGenId), 403 (not in KeyList).

---

### `GET /getMessageById`

Returns a single message by id.

**Query parameters:**

| Parameter   | Type   | Required | Description |
|------------|--------|-----------|-------------|
| `keyGenId` | string | Yes | KeyGen channel. |
| `messageId`| string | Yes | Message id. |

**Response (200):** `data` is the message object (or 404 if not found / deleted).

**Errors:** 400 (missing params), 403 (not in KeyList), 404 (message not found).

---

### `GET /getMessageThread`

Returns the top-level message and its reply tree (nested, max depth 3).

**Query parameters:**

| Parameter   | Type   | Required | Description |
|------------|--------|----------|-------------|
| `keyGenId` | string | Yes | KeyGen channel. |
| `messageId`| string | Yes | **Top-level** message id (must have a `title`). |

**Response (200):** `data` is a **nested** message object: the root has a `replies` array; each reply may have its own `replies` (up to depth 3). Within each `replies` array, order is `createdAt` ascending.

**Errors:** 400 (missing params or message is not top-level), 403 (not in KeyList), 404 (message not found).

---

### `POST /markMessageRead`

Adds the calling node’s read receipt to the message (idempotent). **Requires management key signature** (see above).

**Request body (JSON):**

| Field      | Type   | Required | Description |
|-----------|--------|----------|-------------|
| `Nonce`      | int    | Yes (mgt) | Same as **`POST /sendMessage`**: Ethereum / NodeMgtKey → `GET /getNodeMgtKeyNonce`; Ed25519 → `GET /getPublicMgtKeyNonce` (`?publicKey=` if needed). |
| `Sig`        | string | Yes (mgt) | Signature over the exact JSON of this body with `Sig` set to `""`. |
| `keyGenId`   | string | Yes | KeyGen channel. |
| `messageId`  | string | Yes | Message id. |
| `signature`  | string | No  | Optional: client signs `messageId||keyGenId` with node client key; stored on the read receipt. |

**Response (200):** `data` is `"ok"`.

**Errors:** 400 (missing body), 401 (invalid or missing mgt signature), 403 (not in KeyList), 404 (message not found).

---

### `POST /multiMarkMessagesRead`

Adds the calling node’s read receipt to **each** of the given messages (idempotent per message). **Requires management key signature** (see above). Accepts a list of message ids in one request.

**Request body (JSON):**

| Field       | Type     | Required | Description |
|------------|----------|----------|-------------|
| `Nonce`      | int      | Yes (mgt) | Same as **`POST /sendMessage`**: Ethereum / NodeMgtKey → `GET /getNodeMgtKeyNonce`; Ed25519 → `GET /getPublicMgtKeyNonce` (`?publicKey=` if needed). |
| `Sig`        | string   | Yes (mgt) | Signature over the exact JSON of this body with `Sig` set to `""`. |
| `keyGenId`   | string   | Yes      | KeyGen channel. |
| `messageIds` | []string | Yes      | List of message ids to mark as read. Must not be empty. |
| `signature`  | string   | No       | Optional: client signature; stored on each receipt if provided. |

**Response (200):** `data` is `{ "marked": N, "notFound": [ ... ] }` where `marked` is the number of messages that were successfully marked (or already had a read receipt from this node), and `notFound` is the list of message ids that did not exist or were deleted.

**Errors:** 400 (missing body or empty messageIds), 401 (invalid or missing mgt signature), 403 (not in KeyList).

---

### `POST /deleteMessage`

Soft-deletes the message and **all its replies**. Only the **message originator** may call this. **Requires management key signature** (see above).

**Request body (JSON):**

| Field      | Type   | Required | Description |
|-----------|--------|----------|-------------|
| `Nonce`      | int    | Yes (mgt) | Same as **`POST /sendMessage`**: Ethereum / NodeMgtKey → `GET /getNodeMgtKeyNonce`; Ed25519 → `GET /getPublicMgtKeyNonce` (`?publicKey=` if needed). |
| `Sig`        | string | Yes (mgt) | Signature over the exact JSON of this body with `Sig` set to `""`. |
| `keyGenId`   | string | Yes | KeyGen channel. |
| `messageId`  | string | Yes | Message id. |

**Response (200):** `data` is `{ "deleted": N }` (number of messages removed).

**Errors:** 400 (missing body), 401 (invalid or missing mgt signature), 403 (not in KeyList or not originator), 404 (message not found).

---

### `POST /multiDeleteMessages`

Soft-deletes **multiple** messages (and their reply trees). Only the **message originator** may delete each; others are skipped and listed in `forbidden`. **Requires management key signature** (see above). Each deletion is propagated to other nodes using the same mechanism as `deleteMessage` (sequential, no delay between propagations).

**Request body (JSON):**

| Field       | Type     | Required | Description |
|------------|----------|----------|-------------|
| `Nonce`      | int      | Yes (mgt) | Same as **`POST /sendMessage`**: Ethereum / NodeMgtKey → `GET /getNodeMgtKeyNonce`; Ed25519 → `GET /getPublicMgtKeyNonce` (`?publicKey=` if needed). |
| `Sig`        | string   | Yes (mgt) | Signature over the exact JSON of this body with `Sig` set to `""`. |
| `keyGenId`   | string   | Yes      | KeyGen channel. |
| `messageIds` | []string | Yes      | List of root message ids to delete (each plus its reply tree). Must not be empty. |

**Response (200):** `data` is `{ "deleted": N, "notFound": [ ... ], "forbidden": [ ... ] }` where `deleted` is the total number of messages removed (across all trees), `notFound` are message ids that did not exist or were already deleted, and `forbidden` are message ids the caller is not the originator of (skipped).

**Errors:** 400 (missing body or empty messageIds), 401 (invalid or missing mgt signature), 403 (not in KeyList).

---

## Message and receipt shape

- **Message:** `id`, `keyGenId`, `senderNodeKey`, `title` (top-level only), `replyTo` (replies only), `body`, `createdAt` (UTC), `read` (array of read receipts). Deleted messages are omitted from list/get/thread.
- **Read receipt:** `nodeKey`, `signature`, `signedAt` (UTC). Stored when a node marks a message read; optional client `signature` in the request.

For full semantics (ids, threading depth, propagation, and auth conventions), see `./API_IMPLEMENTATION.md` and `./ED25519_MANAGEMENT_KEY_SIGNING.md`.

---

## Agent message hooks (in-node)

When **`EnableAgentHooks`** is enabled (default), messages whose **title** or **body** contain **`@agent`** (word boundary, default token `agent`) can trigger an automated agent turn inside mpc-auth. Detection is **in-node** on `POST /sendMessage` and MQTT `KEYGENMESSAGE` — no external poll scripts.

| Kind | Trigger | Result |
|------|---------|--------|
| Top-level + **`mpc-orchestrate v1`** block | `@agent` in title/body | Multi-task orchestration (sub-agents per `tasks[]`, optional synthesis cron) |
| Top-level (no manifest) | `@agent` | One hook turn using **`MESSAGE_HOOK_*_TOP_LEVEL.md`** |
| Reply | `@agent` in body | Hook only if orchestration manifest **`prompts.*`** is non-empty; else preset **`MESSAGE_HOOK_*_REPLY.md`** (often empty) |

**Config:** `agent_llm_config/hooks/message_hook.json` and four **`MESSAGE_HOOK_*.md`** files (bundled from **mpc-config**). **Plan → execute:** agent chat with **`conversationPurpose: "plan"`** and **`POST /agent/plan/execute`** — see **[`../AGENT_HOOKS.md`](../AGENT_HOOKS.md)** (user guide) and **API_IMPLEMENTATION.md** (Agent hooks). Example manifest: **`agent_llm_config/hooks/ORCHESTRATION_MANIFEST_EXAMPLE.md`**.

**Body size:** KeyGen message bodies support up to **16384** UTF-8 bytes (orchestration manifests are inline in the body).
