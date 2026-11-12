# Stimmig

Stimmig is a platform for ranked-choice elections whose result anyone can
recompute from public data. The design is in [SPEC.md](SPEC.md).

## Status

The project follows the milestones of SPEC.md section 13.

| Milestone | State |
| --- | --- |
| M0: Repository | Done |
| M1: Tally library | Done |
| M2 to M8 | Not started |

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

### Tests

```bash
go test ./...
```

Test vectors are in `tally/testdata/vectors`. Their expected results were
worked out by hand or taken from published examples, not from the library.

## Licence

[EUPL-1.2](LICENSE)
