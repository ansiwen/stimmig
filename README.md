# Stimmig

Stimmig is a platform for ranked-choice elections whose result anyone can
recompute from public data. The design is in [SPEC.md](SPEC.md).

## Status

The project follows the milestones of SPEC.md section 13.

| Milestone | State |
| --- | --- |
| M0: Repository | Done |
| M1: Tally library | Done |
| M2: Log | Done; the log is in memory until the services arrive in M4 |
| M3: Cryptography | Done |
| M4: Services | Done; see the open points in SPEC.md section 14 |
| M5: Web client | Voting client done; the admin interface is the command line |
| M6: Deployment | Image, Helm chart and encrypted key store done; no PKCS#11 HSM |
| M7: Identity | OpenID Connect done; ATProto not built |
| M8: Review | Not started: no protocol model, no external review |

## Tally

The package `tally` computes results for Schulze, Ranked Pairs, Minimax,
Copeland, instant runoff, Borda and single transferable vote. It has no I/O
and uses exact integer and rational arithmetic only.

```bash
go run ./cmd/stimmig tally -manifest manifest.json -ballots ballots.json
```

`manifest.json`:

```json
{
  "candidates": ["A", "B", "C"],
  "method": "schulze",
  "seats": 1,
  "max_ranks": 3,
  "tie_break": ["first-ranks", "declare-tie"]
}
```

`ballots.json` is an array of ballots. A ballot is an array of rank groups,
best first, and a rank group is an array of candidate IDs:

```json
[
  [["A"], ["B", "C"]],
  [["C"]]
]
```

The output is the result as JSON: winners, ranking, pairwise matrix, trace
and tie-break events.

The exact rules of every method and of the tie-break chain are in
[SPEC.md](SPEC.md) section 8.

## Log and verifier

The package `publog` implements the public log: canonically encoded entries
in a Merkle tree, signed tree heads, inclusion and consistency proofs, and
the export format. The packages `canon` and `merkle` hold the deterministic
CBOR encoding and the tree. The formats are in [SPEC.md](SPEC.md) section 7.

```bash
go run ./cmd/stimmig verify election/testdata/election-v1.cbor
```

`verify` checks a log export end to end: the log structure and every tree
head, issuance against the roll, the public counts, both signatures of every
ballot, the published election key, every decryption, and the recomputed
tally. With `-json` it also prints every entry in its JSON rendering.

## Protocol

The packages `credential` and `ballot` hold the cryptography of assurance
profile A: the blind-signed credential, ballot encryption, the ballot
signature and the receipt. The package `election` defines the bodies of the
log entries, the steps that write them, and the verifier. The messages are in
[SPEC.md](SPEC.md) section 5.6.

## Running an election

The services need PostgreSQL. Each service gets its own database:

```bash
export STIMMIG_DATABASE_URL=postgres://stimmig:secret@localhost/stimmig_log
export STIMMIG_LISTEN=127.0.0.1:8081 STIMMIG_ADMIN_TOKEN=log-admin
export STIMMIG_REGISTRAR_TOKEN=log-registrar STIMMIG_BALLOTBOX_TOKEN=log-ballotbox
go run ./cmd/stimmig log
```

```bash
export STIMMIG_DATABASE_URL=postgres://stimmig:secret@localhost/stimmig_registrar
export STIMMIG_LISTEN=127.0.0.1:8082 STIMMIG_ADMIN_TOKEN=registrar-admin
export STIMMIG_LOG_URL=http://127.0.0.1:8081 STIMMIG_LOG_TOKEN=log-registrar
export STIMMIG_PUBLIC_URL=http://127.0.0.1:8082
export STIMMIG_EMAIL_SECRET=change-me-to-32-random-characters
go run ./cmd/stimmig registrar
```

```bash
export STIMMIG_DATABASE_URL=postgres://stimmig:secret@localhost/stimmig_ballotbox
export STIMMIG_LISTEN=127.0.0.1:8083 STIMMIG_ADMIN_TOKEN=ballotbox-admin
export STIMMIG_LOG_URL=http://127.0.0.1:8081 STIMMIG_LOG_TOKEN=log-ballotbox
go run ./cmd/stimmig ballotbox
```

Without `STIMMIG_SMTP_ADDR` the registrar prints the login mails instead of
sending them. The admin drives the election:

```bash
export STIMMIG_LOG_URL=http://127.0.0.1:8081 STIMMIG_LOG_ADMIN_TOKEN=log-admin
export STIMMIG_REGISTRAR_URL=http://127.0.0.1:8082 STIMMIG_REGISTRAR_ADMIN_TOKEN=registrar-admin
export STIMMIG_BALLOTBOX_URL=http://127.0.0.1:8083 STIMMIG_BALLOTBOX_ADMIN_TOKEN=ballotbox-admin
echo '{"title": "Board", "tally": {"candidates": ["A", "B", "C"], "method": "schulze"}}' > election.json
echo 'ada@example.org' > voters.txt
ID=$(go run ./cmd/stimmig admin create -definition election.json)
go run ./cmd/stimmig admin roll -election $ID -voters voters.txt
```

A voter registers, which waits until the mailed link is opened, and votes
after the admin has closed registration and opened the voting:

```bash
go run ./cmd/stimmig client register -state ada.json -election $ID -email ada@example.org \
  -log http://127.0.0.1:8081 -registrar http://127.0.0.1:8082 -ballotbox http://127.0.0.1:8083
go run ./cmd/stimmig admin close-registration -election $ID
go run ./cmd/stimmig admin open-voting -election $ID
go run ./cmd/stimmig client cast -state ada.json -ranking "A>B=C"
go run ./cmd/stimmig admin close-voting -election $ID
go run ./cmd/stimmig admin tally -election $ID
go run ./cmd/stimmig client check -state ada.json
```

Anyone can download and verify the log:

```bash
curl -s http://127.0.0.1:8081/v1/elections/$ID/export -o election.cbor
go run ./cmd/stimmig verify election.cbor
```

The service interfaces are in [SPEC.md](SPEC.md) section 10.

## Deployment

```bash
docker build -t stimmig .
helm install stimmig deploy/helm/stimmig -f my-values.yaml
```

The image runs every role: the role is the command, for example
`docker run stimmig log`. The chart expects one Kubernetes Secret per role
with its database URL and tokens; `deploy/helm/stimmig/values.yaml` lists the
keys. Set `STIMMIG_KEY_ENCRYPTION_KEY` (64 hexadecimal characters) so that the
services encrypt their private keys in the database.

## Voting in the browser

`make web` builds the voting client into `web/dist`. Start the ballot box
with `STIMMIG_CLIENT_DIR=web/dist`, and give voters a link that names the
election, the log and the registrar:

```
http://127.0.0.1:8083/?election=<ID>&log=http://127.0.0.1:8081&registrar=http://127.0.0.1:8082
```

The page runs the same client code as `stimmig client`, compiled to
WebAssembly.

## Tests

The tests of the services need a PostgreSQL database and are skipped without
`STIMMIG_TEST_DATABASE_URL`, for example
`postgres://stimmig:stimmig@localhost/stimmig_test`.


```bash
go test ./...
```

Tally test vectors are in `tally/testdata/vectors`. Their expected results
were worked out by hand or taken from published examples, not from the
library. `election/testdata/election-v1.cbor` is the log export of a complete test
election for independent verifiers.

## Licence

[EUPL-1.2](LICENSE)
