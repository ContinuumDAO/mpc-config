# Telegram webhook via ngrok (free tier)

Bundled for nodes at **`agent_llm_config.defaults/hooks/TELEGRAM_WEBHOOK_NGROK.md`** (served by **`GET /getTelegramWebhookNgrokGuide`** and linked from **continuumdao-node-app → AI Agent → Webhooks**).

This guide walks through exposing the mpc-auth **inbound hook listener** (port **18090**) to Telegram using a **free ngrok Agent Endpoint**. It complements the general hook overview in **[`AGENT_HOOKS.md`](AGENT_HOOKS.md)**.

Telegram requires a **public HTTPS** URL for `setWebhook`. A stock node listens on **`127.0.0.1:18090` only** — not on Browser HTTPS **:8443**. ngrok provides a temporary **`https://….ngrok-free.dev`** (or **`.ngrok-free.app`**) URL that forwards to that listener.

---

## What you get

- Message a **Telegram bot** → mpc-auth runs an **agent turn** (LLM + MCP tools) → reply is sent back in chat.
- After a one-time **`/start`**, the agent can also **push** with MCP **`send_telegram_message`** (cron / web chat / “notify me when X”) using **`TELEGRAM_OPERATOR_CHAT_ID`**.
- Bundled template: **`telegram_updates`** (`type: telegram`).
- Inbound path: **`POST /hooks/inbound/{webhookId}`** on the hook port (default **18090**).

To query **multiSignRequest** / sign queues from Telegram, edit the webhook **prompt** (or ask in chat) so the agent calls tools such as `list_sign_requests_awaiting_join` and `list_sign_requests_ready`. See **[`AGENT_HOOKS.md`](AGENT_HOOKS.md)** § Telegram.

---

## Prerequisites

1. **`configs.yaml`** (from **`configs-original.yaml`**):

   ```yaml
   EnableAgentHooks: true
   EnableMcpChat: true
   ```

2. **Agent LLM** configured (provider, model, API key) in **continuumdao-node-app → AI Agent → Provider**.

3. **MCP server `continuum`** enabled (**AI Agent → MCP Servers**) so the agent can call node tools.

4. A **Telegram bot** from **@BotFather** (bot token).

5. A **free ngrok account** — required for all tunnel sessions ([ngrok Linux setup](https://dashboard.ngrok.com/get-started/setup/linux)).

6. **continuumdao-node-app** attached to the node (Browser HTTPS, SSH tunnel, or plain HTTP) to manage webhooks and Variables.

---

## Part 1 — Install and authenticate ngrok

Follow the official steps: **[ngrok — Setup on Linux](https://dashboard.ngrok.com/get-started/setup/linux)**

Summary:

1. Sign up at [ngrok dashboard](https://dashboard.ngrok.com/signup) (free tier is enough).
2. Install the ngrok agent on the machine that will run the tunnel (your VPS, or inside Docker — see Part 4).
3. Add your authtoken (from [Your authtoken](https://dashboard.ngrok.com/get-started/your-authtoken)):

   ```bash
   ngrok config add-authtoken <YOUR_AUTHTOKEN>
   ```

### Agent Endpoint vs Cloud Endpoint

When the ngrok dashboard or docs ask which endpoint type to use, choose **Agent Endpoint**.

| | **Agent Endpoint** (use this) | **Cloud Endpoint** |
|---|-------------------------------|---------------------|
| Started by | `ngrok http 18090` (CLI) | Dashboard / API + traffic policy |
| URL | ngrok assigns a free random HTTPS host | You configure a stable URL |
| Lifetime | While the `ngrok` process runs | Always-on in ngrok cloud |
| Fits mpc-auth Telegram setup | **Yes** | Overkill for a first bot |

You do **not** need to create a Cloud Endpoint in the dashboard for this guide — run the CLI on the hook port after Part 2–3 are done.

---

## Part 2 — Configure the webhook on the node

In **continuumdao-node-app → Node → AI Agent**:

### 1. Add the template

**Webhooks → Available from repository → `telegram_updates` → Add**  
Sign with your management key (Ed25519 or NodeMgtKey).

### 2. Note the inbound URL and webhook id

Open **`telegram_updates`** and copy **Inbound URL**, for example:

```http
http://127.0.0.1:18090/hooks/inbound/c11e6cb0-ea18-422b-af6f-fc21523b90f9
```

The last path segment is **`{webhookId}`** — unique per node; keep it for `setWebhook`.

### 3. Set Variables

**AI Agent → Variables**:

| Variable | Value |
|----------|--------|
| **`TELEGRAM_BOT_TOKEN`** | Bot token from @BotFather |
| **`TELEGRAM_OPERATOR_CHAT_ID`** | Your private Telegram chat id (for **`send_telegram_message`**). Auto-stored on first inbound after `/start`; or set it from `getUpdates`. |
| **`WEBHOOK_SECRET_TELEGRAM_UPDATES`** | Long random string (**not** the bot token) |
| **`NGROK_AUTHTOKEN`** | Authtoken from the [ngrok dashboard](https://dashboard.ngrok.com/get-started/your-authtoken) (needed for the automated sidecar) |
| **`NGROK_PAID_PLAN`** | Set to **`true`** when you have a **paid** ngrok subscription — tells the node to use the paid setup (interactive Mini App charts). Omit or leave unset on free ngrok. |

Generate a webhook secret example:

```bash
openssl rand -hex 32
```

### 4. Enable and restart

- Enable **`telegram_updates`** (Active checkbox).
- **Restart the mpc-auth service** when the UI prompts (hook listener reload).

---

## Part 3 — Verify the hook listener (before ngrok)

The hook server must answer on **18090** before Telegram or ngrok can work.

### Docker (typical mpc-config deployment)

`docker-compose.client.yml` / `docker-compose.relay.yml` publish **8080**, **8443**, **18080**, **18081** — **not 18090**. The listener binds **`127.0.0.1:18090` inside the `app` container**.

From the compose project directory (e.g. `~/mpc-config`):

```bash
docker compose exec app sh -c \
'curl -sS -o /dev/null -w "inside: %{http_code}\n" -X POST \
  "http://127.0.0.1:18090/hooks/inbound/<webhook-id>" \
  -H "Content-Type: application/json" \
  -H "X-Telegram-Bot-Api-Secret-Token: <WEBHOOK_SECRET_TELEGRAM_UPDATES>" \
  -d "{\"update_id\":1,\"message\":{\"message_id\":1,\"chat\":{\"id\":1,\"type\":\"private\"},\"text\":\"test\"}}"'
```

| Result | Meaning |
|--------|---------|
| **`inside: 200`** | Ready for ngrok |
| **`inside: 401`** | Enable webhook and/or fix **`WEBHOOK_SECRET_TELEGRAM_UPDATES`** |
| **Connection refused** | **`EnableAgentHooks: false`**, or restart **`app`**; check logs for `agent hook inbound HTTP listening on 127.0.0.1:18090` |

On the **host**, `ss -tlnp | grep 18090` is often **empty** — that is normal for Docker.

### Bare metal (mpc-auth directly on the host)

```bash
curl -sS -o /dev/null -w "local: %{http_code}\n" -X POST \
  "http://127.0.0.1:18090/hooks/inbound/<webhook-id>" \
  -H "Content-Type: application/json" \
  -H "X-Telegram-Bot-Api-Secret-Token: <WEBHOOK_SECRET_TELEGRAM_UPDATES>" \
  -d '{"update_id":1,"message":{"message_id":1,"chat":{"id":1,"type":"private"},"text":"test"}}'
```

Expect **`local: 200`**.

---

## Part 4 — Start ngrok (Agent Endpoint)

### Automated sidecar (preferred on Docker nodes)

On VPS/Linux with **`install-mpc-auth-docker-systemd.sh`**, or on **Windows/macOS Docker Desktop** after the Continuum install (WSL / macOS pending watcher), the node app **Webhooks** panel can enable a host-managed ngrok sidecar:

1. Set Variables: **`NGROK_AUTHTOKEN`**, **`TELEGRAM_BOT_TOKEN`**, and the webhook secret. For a paid ngrok subscription (Mini App charts), also set **`NGROK_PAID_PLAN=true`**.
2. Enable Telegram ngrok for the webhook (panel → **`POST /telegramNgrok/setEnabled`**).
3. Host automation consumes **`/var/lib/mpc-auth-docker/pending-telegram-ngrok.json`** and runs **`docker run --network container:<app> … ngrok/ngrok http 18090`** as container **`mpc-auth-telegram-ngrok`**.
4. Confirm with **`GET /telegramNgrok/status`**, then register the webhook (**`POST /telegramNgrok/registerWebhook`** or the panel action).

| Host | Who watches the pending file |
|------|------------------------------|
| VPS / Linux systemd | **`mpc-auth-telegram-ngrok-pending.path`** |
| Windows Docker Desktop (WSL) | **`wsl-desktop`** pending watcher |
| macOS Docker Desktop | **`macos-desktop`** pending watcher + launchd |

If automation is not installed, use the manual steps below.

### Manual start

Replace **only the host** in the inbound URL with your ngrok HTTPS host. The path **`/hooks/inbound/<webhook-id>`** stays exactly as shown in the Node UI.

### A. Docker — run ngrok on the `app` container network (recommended)

Do **not** run `ngrok http 18090` on the VPS host unless you publish port 18090 (Part 4C). The hook listens on container loopback.

```bash
cd ~/mpc-config   # or your compose project dir
APP_CID=$(docker compose ps -q app)

docker run --rm -it \
  -e NGROK_AUTHTOKEN=<YOUR_AUTHTOKEN> \
  --network "container:${APP_CID}" \
  ngrok/ngrok:latest http 18090
```

Leave this running. Copy the **`https://….ngrok-free.dev`** (or **`.app`**) URL from the ngrok output.

**Alternative:** install ngrok inside the `app` container and run `ngrok http 18090` there (same network namespace).

### B. Bare metal — ngrok on the same host as mpc-auth

```bash
ngrok http 18090
```

Copy the **`https://….ngrok-free.dev`** URL.

### C. Optional — publish 18090 to the host (persistent host-side ngrok)

If you prefer `ngrok http 18090` on the VPS shell:

1. In **`configs.yaml`**:

   ```yaml
   AgentHookListenAddr: 0.0.0.0
   AgentHookListenPort: 18090
   ```

2. In **`docker-compose.yml`** under **`app` → `ports`**:

   ```yaml
   - "127.0.0.1:18090:18090"
   ```

3. `docker compose up -d app` — then `ss -tlnp | grep 18090` on the host should show a listener.

---

## Part 5 — Register with Telegram

Use **`Register with Telegram`** in the node app (recommended), or call **`setWebhook`** manually. Inline keyboard buttons (chain pickers, analysis menus, trade build) require **`callback_query`** in **`allowed_updates`**.

```bash
curl -sS "https://api.telegram.org/bot<BOT_TOKEN>/setWebhook" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://<ngrok-host>/hooks/inbound/<webhook-id>",
    "secret_token": "<WEBHOOK_SECRET_TELEGRAM_UPDATES>",
    "allowed_updates": ["message", "edited_message", "channel_post", "callback_query"]
  }'
```

Example (placeholders):

```bash
curl -sS "https://api.telegram.org/bot123456:ABC-DEF/setWebhook" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://lukewarm-example.ngrok-free.dev/hooks/inbound/c11e6cb0-ea18-422b-af6f-fc21523b90f9",
    "secret_token": "your_random_webhook_secret",
    "allowed_updates": ["message", "edited_message", "channel_post", "callback_query"]
  }'
```

Verify:

```bash
curl -sS "https://api.telegram.org/bot<BOT_TOKEN>/getWebhookInfo"
```

Check:

- **`url`** matches your ngrok URL + path
- **`last_error_message`** is empty
- **`pending_update_count`** drops after you send a new message

Test through ngrok from any machine:

```bash
curl -sS -o /dev/null -w "ngrok: %{http_code}\n" -X POST \
  "https://<ngrok-host>/hooks/inbound/<webhook-id>" \
  -H "Content-Type: application/json" \
  -H "X-Telegram-Bot-Api-Secret-Token: <WEBHOOK_SECRET_TELEGRAM_UPDATES>" \
  -d '{"update_id":1,"message":{"message_id":1,"chat":{"id":1,"type":"private"},"text":"test"}}'
```

Expect **`ngrok: 200`**.

Message your bot in Telegram (e.g. `list pending sign requests`).

---

## Operations

| Topic | Notes |
|-------|--------|
| **Keep ngrok running** | Free Agent Endpoints stop when the process exits; the bot stops receiving updates. |
| **URL changes** | Free ngrok hostnames often change on restart → run **`setWebhook`** again with the new URL. |
| **Charts vs bot chat** | **Free ngrok** (`*.ngrok-free.dev` / `*.ngrok-free.app`): bot messages, analysis buttons, trade ideas, and trade builds work. **Interactive chart Mini Apps do not** — ngrok serves a browser warning page on chart GETs that Telegram WebViews cannot bypass. Use a **paid ngrok plan** with a reserved domain for **Open chart**, or view charts in **continuumdao-node-app** agent chat. |
| **Two secrets** | **`TELEGRAM_BOT_TOKEN`** ≠ **`WEBHOOK_SECRET_TELEGRAM_UPDATES`**. Never reuse the bot token as the webhook secret. |
| **Shared conversation** | All Telegram messages use one agent conversation for this webhook until you tap **New chat** or delete it in **AI Agent → Conversations**. |
| **App attach URL** | Browser HTTPS / SSH tunnel URLs are for **operating** the node — **not** for Telegram `setWebhook`. |

To clear a bad registration:

```bash
curl -sS "https://api.telegram.org/bot<BOT_TOKEN>/deleteWebhook"
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|----------------|-----|
| `Couldn't connect to 127.0.0.1:18090` on **host** | Docker: hook is inside **`app`** | Use Part 4A; test with **`docker compose exec app`** curl |
| Telegram **`404 Not Found`** | ngrok on host forwarding to empty/wrong port | Run ngrok on **container network** (Part 4A) |
| Telegram **`401`** / no reply | Webhook disabled or secret mismatch | Enable webhook; align **`WEBHOOK_SECRET_*`** with `secret_token` in `setWebhook` |
| Inline buttons do nothing | **`setWebhook`** missing **`callback_query`** in **`allowed_updates`** | Run **Register with Telegram** again (node app) or include **`callback_query`** in manual `setWebhook` |
| `bad webhook: An HTTPS URL must be provided` | Used `http://` or localhost in `setWebhook` | Use **`https://<ngrok-host>/hooks/inbound/...`** |
| ngrok **`ERR_NGROK_4018`** | No authtoken | [Linux setup](https://dashboard.ngrok.com/get-started/setup/linux) → `ngrok config add-authtoken` |
| **`inside: 000`** in container | Hooks off or **`app`** not restarted | **`EnableAgentHooks: true`**; restart; check logs for hook listener line |

---

## Chart analysis menus in Telegram

After OHLCV fetch and analysis tools run, mpc-auth sends **numbered option lists** and **inline keyboard buttons** in Telegram (same menus as SSE pickers in the node app chat).

| Action | How |
|--------|-----|
| Pick analysis / chain / overlay | Tap a button, or reply with a number (`2`) or phrase (`Run analysis #1`) |
| Trade ideas | Tap **Build #N**, confirm sizing if prompted, then **Confirm build** |
| Chart / plot | After `plot` / `show chart`, tap **Open chart** (Telegram Mini App — scroll, zoom, live Hyperliquid ticks) |
| Chart overlays (Bollinger bands, etc.) | Summary text in chat; full overlay chart in Mini App after plot + apply tools |

### Interactive chart (Telegram Mini App)

When the agent calls `prepare_chart_from_rows`, mpc-auth stores the `continuum/chart/v1` envelope and sends an **Open chart** button (`web_app`) when your public HTTPS host supports Telegram Mini Apps.

**Free ngrok vs paid ngrok**

| Capability | Free ngrok (`*.ngrok-free.dev`) | Paid ngrok (reserved domain) |
|------------|----------------------------------|------------------------------|
| Bot chat, analysis menus, trade ideas, trade build | Yes | Yes |
| Chart preview in chat (text sparkline + recent OHLC) | Yes | Yes |
| **Open chart** Mini App (interactive) | **No** — blank WebView (ngrok interstitial) | Yes |

If you plot on free ngrok, the bot sends a **text sparkline** and the last few OHLC bars, plus a note that the interactive Mini App needs paid ngrok. Upgrade at [ngrok billing](https://dashboard.ngrok.com/billing), then set **`NGROK_PAID_PLAN=true`** in **AI Agent → Variables** so the node uses the paid setup (paid plans remove ngrok’s browser interstitial even on `*.ngrok-free.dev` / `*.ngrok-free.app` hosts). Prefer a reserved HTTPS hostname when you have one; register the tunnel hostname as the bot **Mini App domain** in @BotFather, and optionally set **`TELEGRAM_WEBAPP_BASE_URL`** if auto-detection fails.

**Hook listener routes** (default port **18090**, same mux as **`POST /hooks/inbound/{webhookId}`**):

```text
GET /telegram/chart/{token}
GET /telegram/chart/{token}/envelope
GET /telegram/chart/static/*
```

**Operator setup (once per bot):**

1. Enable ngrok for webhooks (existing flow) — note the public host.
2. **For charts:** upgrade to a paid ngrok plan. In **AI Agent → Variables**, set **`NGROK_PAID_PLAN=true`** so the node uses the paid setup. Prefer a reserved domain (not only `*.ngrok-free.dev`). In **@BotFather** → your bot → **Bot Settings** → configure the **Mini App domain** to that host (no path).
3. Optional override: set agent env **`TELEGRAM_WEBAPP_BASE_URL`** to your reserved HTTPS host if auto-detection from ngrok state fails.

**Typical flow:**

```text
load hyperliquid
load the 4 hour ETH perp for the last 30 days
plot ETH 4H
```

→ Bot replies with summary + **Open chart** → pinch/drag to zoom; Hyperliquid charts live-update every ~4s when `live` binding is present.

**Limits:** CoinGecko-sourced live ticks in the Mini App may be static until a proxy is added; Hyperliquid/GMX/Arcus use direct browser API calls.

### Resetting the chat session

Tap **New chat** on any bot reply (inline button), or send **`/new`** or **`new chat`**. That clears persisted messages, OHLCV/chart session state, and pending trade-build prompts for this webhook thread — same as deleting the conversation in **AI Agent → Conversations**.

### Trade build from Telegram

1. Tap **Build #N** on a trade idea.
2. If size is missing, reply with e.g. **`0.5 ETH`** (Hyperliquid/Arcus) or paste a **`tradeBuild:`** YAML block (same format as cron jobs).
3. Review the summary and tap **Confirm build** to call `build_trade_from_trade_idea` (multisign).

Optional: attach the **`trade-defaults`** skill to the webhook job prompt path so sizing can be prefilled automatically.

Example sizing reply for Hyperliquid:

```text
0.5 ETH
```

Example YAML block (message body contains `tradeBuild:` followed by a yaml fence with `protocolId`, `chainId`, `szHuman`, etc.).

---

## Related docs

- **[`AGENT_HOOKS.md`](AGENT_HOOKS.md)** — all webhook types, exposure options, KeyGen `@agent` hooks
- **[`references/API_IMPLEMENTATION.md`](references/API_IMPLEMENTATION.md)** — Agent hooks API reference
- **`agent_llm_config.defaults/hooks/webhooks.json`** — bundled **`telegram_updates`** template
