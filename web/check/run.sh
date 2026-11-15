#!/bin/sh
# Starts the three services on a local PostgreSQL and runs browser.js.
# Needs: STIMMIG_DB_URL_PREFIX (for example postgres://stimmig:stimmig@localhost)
# with empty databases stimmig_log, stimmig_reg and stimmig_box, node with
# playwright, and make.
set -e
cd "$(dirname "$0")/../.."
: "${STIMMIG_DB_URL_PREFIX:?set STIMMIG_DB_URL_PREFIX}"
dir=$(mktemp -d)
make web
go build -o "$dir/stimmig" ./cmd/stimmig
key=$(printf 'ab%.0s' $(seq 32))
log=http://127.0.0.1:18081 reg=http://127.0.0.1:18082 box=http://127.0.0.1:18083
export STIMMIG_KEY_ENCRYPTION_KEY=$key
STIMMIG_DATABASE_URL=$STIMMIG_DB_URL_PREFIX/stimmig_log STIMMIG_LISTEN=127.0.0.1:18081 STIMMIG_ADMIN_TOKEN=la \
  STIMMIG_REGISTRAR_TOKEN=lr STIMMIG_BALLOTBOX_TOKEN=lb "$dir/stimmig" log >/dev/null 2>"$dir/log.err" &
pids=$!
STIMMIG_DATABASE_URL=$STIMMIG_DB_URL_PREFIX/stimmig_reg STIMMIG_LISTEN=127.0.0.1:18082 STIMMIG_ADMIN_TOKEN=ra \
  STIMMIG_LOG_URL=$log STIMMIG_LOG_TOKEN=lr STIMMIG_PUBLIC_URL=$reg \
  STIMMIG_EMAIL_SECRET=0123456789abcdef0123456789abcdef "$dir/stimmig" registrar >/dev/null 2>"$dir/reg.err" &
pids="$pids $!"
STIMMIG_DATABASE_URL=$STIMMIG_DB_URL_PREFIX/stimmig_box STIMMIG_LISTEN=127.0.0.1:18083 STIMMIG_ADMIN_TOKEN=ba \
  STIMMIG_LOG_URL=$log STIMMIG_LOG_TOKEN=lb STIMMIG_CLIENT_DIR=web/dist \
  STIMMIG_PUBLIC_LOG_URL=$log STIMMIG_PUBLIC_REGISTRAR_URL=$reg "$dir/stimmig" ballotbox >/dev/null 2>"$dir/box.err" &
pids="$pids $!"
trap 'kill $pids 2>/dev/null' EXIT
sleep 2
CHECK_DIR=$dir STIMMIG_BIN=$dir/stimmig node web/check/browser.js
