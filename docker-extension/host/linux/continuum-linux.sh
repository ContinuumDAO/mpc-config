#!/usr/bin/env sh
# Shipped host wrapper — Docker extension host.cli.exec resolves this by name.
# Delegates to the real host PATH (curl, bash, env, sudo, etc.).
exec "$@"
