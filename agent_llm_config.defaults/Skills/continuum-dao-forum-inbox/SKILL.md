---
name: continuum-dao-forum-inbox
description: Interactive only. Logged-in user checking Forum Unread / messages. List unread topics, present posts, then mark threads read. Never from cron.
---

# ContinuumDAO forum inbox (interactive)

Load when the operator is **signed in** and wants to **check Forum messages**, Unread, “what did I miss?”, or mark threads read after reading them in chat.

Always load **`continuum-dao-proposals`** for Forum post presentation (composer markdown). **Never** load this skill from cron (`notify-forum-replies` uses local watermarks, not NodeBB Unread).

In agent chat, Continuum tools are **`continuum__<name>`**. Load the protocol first: **`continuum__load_defi_protocol({ "protocolId": "continuum-dao" })`**.

Reads of public posts do not need a ticket. **Unread and mark-read need a ticket** (the operator’s NodeBB session).

## Login

1. `continuum__ctm_continuum_dao_forum_sign_in_eligible({ address })`. If `eligible` is false, stop.
2. If there is no ticket: `continuum__ctm_continuum_dao_build_forum_sign_in_multisign` (interactive). After Get Sig, the node-app exchanges the signature for a ticket. Pass that `ticket` on inbox tools.
3. `continuum__ctm_continuum_dao_forum_me` — confirm `loggedIn` and `username`.

## Check messages

1. `continuum__ctm_continuum_dao_forum_unread({ ticket })`. Optional `filter`: `all` (default), `new`, `watched`, `unreplied`.
2. Print a short list: title, `url`, `replyCount`, `lastPostAt`. Do not dump JSON.
3. For each thread the operator wants to read (or the newest few if they said “catch me up”):
   - `forum_resolve` then `forum_fetch_thread` (page replies; `index: 0` is the OP).
   - Present `content` as markdown — do **not** wrap the body in a code fence. If it is HTML or NodeBB-only markup, summarize.
4. After they have seen a thread, ask whether to mark it **read on the Forum** (clears Unread on forum.continuumdao.org).
5. On yes: `continuum__ctm_continuum_dao_forum_mark_read({ ticket, tid })` (or `url`). Several threads: `tids`.
6. **`all: true` only after an explicit confirm** (“mark everything read”). That also clears topic notifications for those threads.
7. Wrong thread: `continuum__ctm_continuum_dao_forum_mark_unread({ ticket, tid })`.

Unread is **per topic**, not per post. Marking a thread read means “caught up to the current last post.”

## Do not confuse with cron

`notify-forum-replies` Telegrams new replies using a local watermark file. It must **not** call `forum_unread` / `forum_mark_read` (no ticket on cron; would also hide Unread on the website).

## Forbidden from this skill

`forum_delete`, `forum_create_topic`, `forum_create_idea`, propose / vote / execute builders, `sign_request_agree`, `trigger_sign_result`, `broadcast_sign_result`. Reply or react only if the operator asks.
