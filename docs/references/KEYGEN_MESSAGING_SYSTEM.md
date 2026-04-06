# KeyGen Messaging System (Internal Spec)

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

## API

All APIs are in the context of the calling node (authenticated by node key). The backend derives `keyGenId` from the request (path or body) and checks that the caller’s node key is in that keyGen’s `KeyList` before allowing access.

### 1. `POST /sendMessage`

**Body (JSON):**

- `keyGenId` (string, required)
- `title` (string, optional) — required for top-level messages; omit or empty for replies
- `replyTo` (string, optional) — message `id` when this is a reply
- `body` (string, required, max 512 chars)

**Validation:**

- If `replyTo` is set, `title` must be omitted/empty and `replyTo` must reference an existing message in the same keyGen.
- If `replyTo` is not set, `title` is required.
- `body` length ≤ 512 (UTF-8).

**Returns:** Created message object (including generated `id`, `senderNodeKey`, `createdAt`, `read: []`).

**Side effect:** Message is stored and broadcast to all other nodes in the keyGen.

---

### 2. `GET /listMessages`

**Query parameters:**

| Parameter   | Type   | Description |
|------------|--------|-------------|
| `keyGenId` | string | Required. KeyGen scope. |
| `unread`   | bool   | If `true`, return only messages the calling node has not yet added a read receipt for. |
| `fromTime` | string | Optional. Inclusive lower bound for `createdAt` (e.g. ISO8601 or Unix ms). |
| `toTime`   | string | Optional. Inclusive upper bound for `createdAt`. |
| `top_level`| bool   | If `true`, return only top-level messages (those with a `title`; i.e. exclude replies). |
| `pagenum`  | int    | 1-based page number. |
| `pagesize` | int    | Page size (e.g. max 100). |

**Returns:** Paginated list of messages (array of message objects, plus optional `total` for total count). Order: e.g. `createdAt` descending (newest first).

---

### 3. `GET /getMessageById`

**Query parameters:**

- `keyGenId` (string, required)
- `messageId` (string, required)

**Returns:** Single message object, or 404 if not found or not in that keyGen.

---

### 4. `GET /getMessageThread`

**Query parameters:**

- `keyGenId` (string, required)
- `messageId` (string, required) — must be a **top-level** message id (a message that has a `title`).

**Returns:** The top-level message plus all replies in the thread (max depth **3**: top-level, then one level of replies, then one more level). every message that is this message or has `replyTo` equal to this message’s `id`, recursively up to that depth. Response is **nested**: the root is the top-level message object with a **`replies`** array; each reply is a message object that may itself have a **`replies`** array (recursively). Order: within each `replies` array, sort by `createdAt` ascending (oldest first).

**Validation:** If `messageId` is not a top-level message, return 400 with a clear error.

---

### 5. Mark as read (read receipts)

**Option A – Dedicated endpoint:**  
`POST /markMessageRead`  
Body: `{ "keyGenId", "messageId" }`.  
Server adds the calling node’s read receipt (signature computed by client and sent, or computed server-side if server has node client key). Then broadcast the new receipt to other nodes.

**Option B – In-band with getMessageById / getMessageThread:**  
When a client calls `getMessageById` or `getMessageThread`, server can optionally add the caller’s read receipt and broadcast if not already present. Requires a query flag like `?markRead=true` to avoid side effects on every read.

Recommendation: **Option A** keeps “read” as an explicit action and avoids surprising side effects on GET.

**Read receipt format:** Each item in `read` includes `nodeKey` and `signature`. Signature = sign with node client key over e.g. `messageId || keyGenId` (canonical format to be fixed in implementation). Other nodes verify using the node’s public key (from KeyList / node registry).

---

### 6. `POST /deleteMessage` (or `DELETE /deleteMessage`)

**Body (JSON):**

- `keyGenId` (string, required)
- `messageId` (string, required)

**Authorization:** Caller’s node key must equal the **originator** of the message (i.e. the message’s `senderNodeKey`). If the caller is not the originator, return **403 Forbidden**.

**Behavior:** Delete the message identified by `messageId` and **all its replies** (the entire sub-tree: every message that is this message or has `replyTo` equal to this message’s `id`, and recursively all replies to those). Persist the deletion and broadcast to other nodes so they remove or hide the same messages.

**Returns:** 200 on success; 403 if caller is not the originator; 404 if message or keyGen not found.

---

## Suggestions to improve the design

1. **Message `id` derivation**  
   Use a deterministic id: `SHA256(senderNodeKey || "." || createdAt_iso_or_unix)` (with fixed format). Reduces duplicates and makes replies stable. Include a short nonce if you need multiple messages per node per second.

2. **Pagination and ordering**  
   - For `listMessages`, return `total` so clients can show “Page 1 of N” and avoid over-fetching.  
   - Clarify sort order (e.g. `createdAt` desc) and that `fromTime`/`toTime` are inclusive.

3. **Thread depth / cycles**  
   - Enforce that `replyTo` only references a message in the same keyGen. **Max depth 3**: top-level, one level of replies, one more level beneath that; reject or ignore replies deeper than that.  
   - Reject `replyTo` cycles (reply chains that would create a loop). Normally a strict “reply only to existing message” and “replies don’t have title” already avoids cycles.

4. **Read receipt broadcast**  
   - Only broadcast the **delta** (new receipt) to reduce payload.  
   - Consider idempotency: if the same node sends “mark read” twice, treat it as one receipt.

5. **Rate limiting and abuse**  
   - Per keyGen (and optionally per node) rate limit: **max 6 messages per minute** to avoid spam.  
   - Optionally require a small proof-of-work or cap message rate per keyGen.

6. **Retention and deletion**  
   - **Originator-only deletion**: Only the message originator can delete a message; deletion removes that message and all its replies. No other node can delete.  
   - Optional TTL or retention policy per keyGen to avoid unbounded growth.

7. **Authorization**  
   - Every endpoint must check: caller’s node key ∈ keyGen’s `KeyList`. Reject otherwise with 403.  
   - For `sendMessage`, additionally verify `senderNodeKey` equals the authenticated node.

8. **Consistency and ordering**  
   - If messages are replicated across nodes, **reject duplicates** by `id`: a message with an existing `id` (same keyGen) is rejected; only the first write is accepted.  
   - Consider sequence numbers or vector clocks if you need a total order for display.

---

## Potential issues and mitigations

| Issue | Mitigation |
|-------|------------|
| **Duplicate message ids** | Deterministic id from (nodeKey, time) plus optional nonce; or use UUID and accept rare collisions; store id unique per keyGen. |
| **Replies to deleted or missing messages** | Originator can delete a message and its reply sub-tree; return 400 if `replyTo` does not exist when sending. list/get omit deleted messages; getMessageThread skips deleted nodes in the tree. |
| **Read receipt replay** | Sign a canonical payload (e.g. `messageId \|\| keyGenId`) and optionally timestamp; reject receipts with duplicate (nodeKey, messageId). |
| **Very long threads** | Max depth **3**: top-level message, one level of replies, and one more level beneath that; deeper replies are not returned by `getMessageThread`. |
| **Spam** | Rate limit per node per keyGen; optional moderation (e.g. threshold to hide or flag). |
| **Clock skew** | All timestamps (e.g. `createdAt`) are **always UTC** (e.g. ISO8601 with Z). Use server-assigned `createdAt` if strict ordering matters; or accept client time but log for debugging. |
| **Storage growth** | Retention policy or TTL; archive old keyGen messages when keyGen is no longer active. |
| **Broadcast failure** | At least one node (e.g. sender or a designated relay) must persist and broadcast; others **update when they come back on-line** (e.g. on next list/get or sync). Define “delivered” vs “read” semantics. |
| **Signature verification** | All nodes must be able to resolve node key → public key for verification; use existing node registry or KeyList. |
| **KeyGen no longer exists** | Omit/reject if keyGen has been deleted: return 404 or 410 for send/list/get when keyGenId is unknown or revoked. |

---

## Summary

- Messages are **per keyGen** (keyGenId = KeyGen result’s requestId); participants = KeyList.
- **Message**: `id`, optional `title` (top-level only), optional `replyTo` (replies only), `body` (≤512 chars), `senderNodeKey`, `keyGenId`, `createdAt`, `read` (array of { nodeKey, signature }).
- **APIs**: `POST sendMessage`, `GET listMessages` (with unread, fromTime, toTime, top_level, pagenum, pagesize), `GET getMessageById`, `GET getMessageThread` (top-level messageId → full thread), **mark message read** (and broadcast receipts), and **deleteMessage** (originator only; deletes message and all its replies).
- **Improvements**: Deterministic ids, pagination total, thread depth/cycle rules, **use delta broadcasts** (e.g. for read receipts), rate limits, retention, strict authZ, and clear consistency rules.
- **Risks**: Duplicates, reply-to-missing, spam, storage, broadcast reliability, signature verification — addressed with the mitigations above.

This doc can be updated once you decide on exact id format and retention/TTL.
