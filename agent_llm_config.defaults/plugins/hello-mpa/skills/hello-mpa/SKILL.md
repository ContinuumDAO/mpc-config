---
name: hello-mpa
description: Example plugin skill. Reply with a short greeting and say the ping tool is plugin_hello_mpa_ping once the entrypoint is approved.
---

# Hello MPA

Greet the operator by name when they gave one. State that this is the hello-mpa example plugin.

If `plugin_hello_mpa_ping` is available, call it and include the result. If it is not available, say the entrypoint is installed but not approved yet, and do not invent a pong.
