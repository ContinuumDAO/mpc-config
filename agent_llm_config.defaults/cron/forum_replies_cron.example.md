# Forum reply Telegram cron

Catalog job **`notify-forum-replies`** (default **disabled**, **`telegramNotify: true`**).

Polls forum.continuumdao.org for new replies to **your** Forum posts and, when any appear, the host DMs the formatted post body to Telegram.

Read-only. No forum ticket on cron — freeze your NodeBB username in the job message after one **interactive** `forum_me`. Do **not** call `forum_unread` / `forum_mark_read` from this job (that is the interactive inbox skill).

## Setup

1. In an interactive agent chat: forum EIP-712 sign-in → `forum_me` → copy `username`.
2. Add **`notify-forum-replies`** from the repository catalog.
3. Edit the job message: set `forumWatch.forumUsername` (replace `REPLACE_WITH_YOUR_FORUM_USERNAME`).
4. Telegram: `/start` the same bot once. Variables: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_OPERATOR_CHAT_ID` (auto-stored on first inbound).
5. **Run now** once (baselines watermarks; you should get a one-line Telegram confirmation). Then enable the job.
6. Restart mpc-auth after `git pull` so the catalog/skill are visible. Existing nodes may need to add skill **`continuum-dao-forum-replies`** if runtime `skills.json` was not updated.

Load skills **`scheduled-automation`** and **`continuum-dao-forum-replies`**. Do **not** call `send_telegram_message` — the host delivers the final assistant message.

## What is watched

- New non-self replies on threads you started (you are the OP).
- Posts whose `toPid` is one of your pids (direct replies to a post you wrote), when that field is present.

State file (agent workspace): `data/cron/notify-forum-replies.yaml`.

## Telegram body

When someone has replied, the final message is the Forum composer markdown (not HTML, not a code fence), plus title, topic URL, author, and timestamp. After the baseline, runs with no new replies end with an empty final message so Telegram stays quiet.
