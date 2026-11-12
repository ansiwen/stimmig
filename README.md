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
| M3: Cryptography | Done; an election runs end to end inside the tests |
| M4 to M8 | Not started |

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

## Tests

```bash
go test ./...
```

Tally test vectors are in `tally/testdata/vectors`. Their expected results
were worked out by hand or taken from published examples, not from the
library. `election/testdata/election-v1.cbor` is the log export of a complete test
election for independent verifiers.

## Licence

[EUPL-1.2](LICENSE)
