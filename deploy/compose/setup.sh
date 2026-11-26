#!/bin/sh
# Writes .env with fresh secrets. Usage: ./setup.sh DOMAIN [--behind-proxy]
# With --behind-proxy, Caddy is not used: a reverse proxy that is already on
# the host terminates TLS (compose.proxy.yaml, nginx.example.conf).
# The services get the names log.DOMAIN, registrar.DOMAIN and vote.DOMAIN.
set -eu
cd "$(dirname "$0")"
if [ $# -lt 1 ] || { [ $# -eq 2 ] && [ "$2" != --behind-proxy ]; } || [ $# -gt 2 ]; then
	echo "usage: $0 DOMAIN [--behind-proxy]" >&2
	exit 2
fi
if [ -e .env ]; then
	echo ".env exists; it holds the keys of the running installation. Remove it only on purpose." >&2
	exit 1
fi
secret() { od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; }
umask 077
proxy=
if [ "${2:-}" = --behind-proxy ]; then
	proxy="
# Behind an existing reverse proxy: no Caddy; log, registrar and ballot box
# listen on PROXY_BIND at the ports below.
COMPOSE_FILE=compose.yaml:compose.proxy.yaml
PROXY_BIND=127.0.0.1
LOG_PORT=8081
REGISTRAR_PORT=8082
BALLOTBOX_PORT=8083
"
fi
cat > .env <<ENV
DOMAIN=$1
$proxy
# Mail for the login links. Without an SMTP server, set PRINT_MAILS=1: the
# registrar then writes the mails to its log (docker compose logs registrar),
# which suits a test with yourself only.
SMTP_ADDR=
SMTP_FROM=
SMTP_USERNAME=
SMTP_PASSWORD=
PRINT_MAILS=1

# Optional OpenID Connect login instead of or besides email.
OIDC_ISSUER=
OIDC_CLIENT_ID=
OIDC_CLIENT_SECRET=

# Generated secrets. Keep a copy: without the key-encryption keys the keys in
# the database, the election key among them, cannot be opened.
DB_ADMIN_PASSWORD=$(secret)
LOG_DB_PASSWORD=$(secret)
REGISTRAR_DB_PASSWORD=$(secret)
BALLOTBOX_DB_PASSWORD=$(secret)
LOG_KEY_ENCRYPTION_KEY=$(secret)
REGISTRAR_KEY_ENCRYPTION_KEY=$(secret)
BALLOTBOX_KEY_ENCRYPTION_KEY=$(secret)
LOG_ADMIN_TOKEN=$(secret)
LOG_REGISTRAR_TOKEN=$(secret)
LOG_BALLOTBOX_TOKEN=$(secret)
REGISTRAR_ADMIN_TOKEN=$(secret)
BALLOTBOX_ADMIN_TOKEN=$(secret)
EMAIL_SECRET=$(secret)
ADMINWEB_TOKEN=$(secret)
ENV
echo "Wrote .env. The admin web token is: $(sed -n 's/^ADMINWEB_TOKEN=//p' .env)"
