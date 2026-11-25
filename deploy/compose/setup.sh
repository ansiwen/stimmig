#!/bin/sh
# Writes .env with fresh secrets. Usage: ./setup.sh DOMAIN
# The services get the names log.DOMAIN, registrar.DOMAIN and vote.DOMAIN.
set -eu
cd "$(dirname "$0")"
if [ $# -lt 1 ]; then
	echo "usage: $0 DOMAIN" >&2
	exit 2
fi
if [ -e .env ]; then
	echo ".env exists; it holds the keys of the running installation. Remove it only on purpose." >&2
	exit 1
fi
secret() { od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; }
umask 077
cat > .env <<ENV
DOMAIN=$1

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
