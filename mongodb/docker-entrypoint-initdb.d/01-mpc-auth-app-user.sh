#!/bin/bash
# Runs once on empty ./data/mongodb (Mongo official entrypoint).
# No-op unless both root and application passwords are set (see repo .env.example).

set -euo pipefail

if [[ -z "${MONGO_INITDB_ROOT_PASSWORD:-}" || -z "${MONGO_APP_PASSWORD:-}" ]]; then
	exit 0
fi

export MONGO_APP_USER="${MONGO_APP_USER:-mpcauth}"
export MONGO_APP_DATABASE="${MONGO_APP_DATABASE:-DistributedAuth}"
export MONGO_APP_PASSWORD

mongosh --quiet "${MONGO_APP_DATABASE}" --eval '
const u = process.env.MONGO_APP_USER;
const p = process.env.MONGO_APP_PASSWORD;
const dbname = process.env.MONGO_APP_DATABASE;
try {
  db.createUser({ user: u, pwd: p, roles: [{ role: "readWrite", db: dbname }] });
} catch (e) {
  if (e.code !== 51003) throw e;
}
'
