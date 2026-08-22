---
name: continuum-dao-forum-replies
description: Cron (and optional interactive) watch for new replies to the operator’s Forum posts. Read-only. When used from notify-forum-replies, the host Telegrams the formatted post via telegramNotify.
---

# ContinuumDAO forum reply watch

Load for **notify-forum-replies** cron, or when the operator asks whether anyone replied to their Forum posts. Always load **`scheduled-automation`** on cron. Load **`continuum-dao-proposals`** only for Forum post presentation (composer markdown). **Never** load **`continuum-dao-compose-proposal`**.

In agent chat, Continuum tools are **`continuum__<name>`**. Load the protocol first: **`continuum__load_defi_protocol({ "protocolId": "continuum-dao" })`**.

Cron has **no** forum ticket. Identity is the NodeBB **`forumUsername`** frozen in the job message (`forumWatch`). Do **not** call `forum_me`, `forum_sign_in`, `forum_unread`, `forum_mark_read`, `forum_mark_unread`, or any write tool from cron. For a logged-in inbox in chat, load **`continuum-dao-forum-inbox`** instead.

This job has **`telegramNotify: true`**. The host DMs your **final assistant message**. Do **not** call **`send_telegram_message`**.

## Watch state

Persist watermarks with **`agent_write_file`** / **`agent_read_file`** (no bash approval):

`data/cron/notify-forum-replies.yaml`

```yaml
forumWatchState:
  version: 1
  forumUsername: alice
  updatedAt: 2026-08-22T08:00:00Z
  threads:
    "123":
      title: Example thread
      replyCount: 4
      lastNotifiedPid: 890
```

Missing file = **baseline** this run: record current `replyCount` / `lastNotifiedPid` per watched thread. Do **not** treat existing replies as new.

## What counts as a reply to you

A post is in-scope when **all** of the following hold:

1. Author username is **not** `forumUsername` (skip self-replies).
2. **Either**
   - you are the thread OP (`forum_fetch_thread` `index: 0` username matches), **or**
   - the post’s `toPid` (when present) is one of your pids from `forum_user_post_ids`.
3. On later runs, `pid` is greater than that thread’s stored `lastNotifiedPid`.

Public reads only: `forum_user_post_ids`, `forum_fetch_post`, `forum_fetch_thread`, `forum_reply_count`, `forum_resolve`. Paginate `forum_user_post_ids` until `nextStart` is null.

## Final message (Telegram body)

Host skips Telegram when the final answer is empty/whitespace.

| Outcome | Final assistant message |
|---------|-------------------------|
| New replies | Formatted Forum posts (see below). Do **not** paste the YAML state file. Cap **10** newest. |
| Baseline, or no new replies | One-line baseline confirmation **only on the first successful baseline**. After that, **empty** (no words) so Telegram is silent. |
| Username still `REPLACE_WITH_YOUR_FORUM_USERNAME`, or a blocking tool error | Short operator-facing error (Telegram should fire). |

### Formatted Forum post

`forum_fetch_post` / `forum_fetch_thread` `content` is composer **source**, usually markdown. Emit it as markdown — do **not** wrap the body in a code fence. If it is HTML or NodeBB-only markup (`@mentions`, upload tokens), summarize in plain language.

For each new reply, in newest-last or newest-first (be consistent):

```
## {thread title}
{topic URL from forum_resolve}
**{author username}** · {createdAt}

{content}
```

Separate replies with a blank line. Keep the whole final message under ~16k characters (host Telegram limit).

## Forbidden

`forum_sign_in`, `forum_sign_out`, `forum_me`, `forum_unread`, `forum_mark_read`, `forum_mark_unread`, `forum_reply`, `forum_react`, `forum_delete`, `forum_create_topic`, `forum_create_idea`, `send_telegram_message`, propose / vote / execute / cancel builders, `sign_request_agree`, `trigger_sign_result`, `broadcast_sign_result`.
