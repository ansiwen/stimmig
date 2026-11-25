# Stimmig with Docker Compose

A small installation on one host that has Docker: the log service, the
registrar, the ballot box, the admin web page, PostgreSQL, and Caddy for HTTPS
with certificates from Let's Encrypt.

It is for a demo or a trial. One host and one operator run all three
services, so the separation that SPEC.md section 2 relies on (registrar and
ballot box run by different parties) does not exist here: whoever controls
the host can read every ballot before the close, and can try to link
ballots to voters by the time and the network address of registration and
casting (the residual risks of SPEC.md section 2).
Use the Helm chart in `deploy/helm`, with separate operators, for an
election that matters.

## What you need

- A host with Docker and the compose plugin, ports 80 and 443 reachable from
  the internet.
- A domain with three DNS names pointing at the host: `vote.<domain>` (the
  voting page), `registrar.<domain>` and `log.<domain>`.
- For mails to voters: an SMTP server that accepts mail from this host. It
  can ask for a login (PLAIN, only over STARTTLS). Without one, the registrar
  writes the login mails to its log, which is enough to try it yourself.
- This repository on the host (the image is built from it).

## Start

```sh
cd deploy/compose
./setup.sh example.org        # writes .env with fresh secrets; prints the admin web token
```

Edit `.env` for mail: set `SMTP_ADDR` (for example `smtp.example.org:587`),
`SMTP_FROM`, and, if the server needs them, `SMTP_USERNAME` and
`SMTP_PASSWORD`; then remove `PRINT_MAILS=1`. For OpenID Connect login, set
the three `OIDC_` values; the redirect URL at the identity provider is
`https://registrar.<domain>/v1/callback/oidc`.

```sh
docker compose up -d --build
docker compose ps
```

Caddy gets the certificates when the first request for each name arrives.

**Keep a copy of `.env`.** The key-encryption keys in it open the keys in
the database, the election key among them; without them a running election
cannot be tallied. The file is readable only by its owner.

## Run an election

The admin web page listens on the host's loopback address only. From your
own computer:

```sh
ssh -L 8090:127.0.0.1:8090 you@your-host
```

then open <http://127.0.0.1:8090/> and sign in with the admin web token from
`setup.sh` (also in `.env` as `ADMINWEB_TOKEN`). Create the election, publish
the roll, and close and open the phases, or give a schedule in the
definition and let the services do it.

Voters open `https://vote.<domain>/?election=<id>`. The page shows the ID
after the election is created.

With `PRINT_MAILS=1`, the login links are in

```sh
docker compose logs registrar
```

Anyone can verify an election:

```sh
curl -s https://log.<domain>/v1/elections/<id>/export -o election.cbor
docker compose run --rm --no-deps -T log verify /dev/stdin < election.cbor
```

## Operation

- Logs: `docker compose logs <service>`. The ballot box and Caddy do not log
  client addresses: Caddy has no access log, and its error log is switched
  off in the `Caddyfile`, because it names the client of a failed request.
- Update: `git pull`, then `docker compose up -d --build`. Do not update
  while an election is running: a new build changes the hash of the voting
  client that the manifest names.
- Backup: the volume `stimmig_db` holds all data, and `.env` its keys. A dump:
  `docker compose exec db pg_dumpall -U postgres > backup.sql`.
- Each service has its own database and role, and no role may connect to
  another service's database.
- Remove everything, data included: `docker compose down -v`, then delete
  `.env`.
