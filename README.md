# Stimmig

Stimmig is a platform for ranked-choice elections whose result anyone can
recompute from public data. The design is in [SPEC.md](SPEC.md).

## Status

The project follows the milestones of SPEC.md section 13.

| Milestone | State |
| --- | --- |
| M0: Repository | Done |
| M1: Tally library | Done, see the open points below |
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

### Rules the specification leaves open

SPEC.md names the methods but not every detail. The library fixes these as
follows; each is a decision to confirm.

- **Pairwise strength.** Schulze, Ranked Pairs and Minimax measure a win by
  its winning votes. Ranked Pairs prefers the smaller opposition among equal
  winning votes.
- **Borda.** A candidate scores one point per candidate ranked below and half
  a point per candidate tied with. Unranked candidates are tied at the bottom.
- **Equal ranks in instant runoff and single transferable vote.** The ballot's
  weight is split equally among the continuing candidates of its highest rank
  group.
- **Single transferable vote.** Droop quota `floor(votes/(seats+1))+1`, fixed
  at the start. Surpluses use the weighted inclusive Gregory method. The
  surpluses of all candidates elected in one round are transferred together.
- **Tie in an elimination.** The tie-break chain orders the candidates with
  the fewest votes, and the last one is eliminated. If the chain ends in
  declare-tie and the tie stands, the count stops and reports it.
- **Tie between equally strong wins in Ranked Pairs.** Such wins are locked
  together when that closes no cycle. Otherwise the tie-break chain orders the
  candidates involved, and the wins are locked by the rank of the winner, then
  of the loser.
- **Head-to-head.** The rule moves the candidate who beats all other tied
  candidates to the top and the one who loses to all to the bottom, and
  repeats. The rest stay tied.
- **Invalid ballots.** They are reported with a reason and not counted.

### Tests

```bash
go test ./...
```

Test vectors are in `tally/testdata/vectors`. Their expected results were
worked out by hand or taken from published examples, not from the library.

## Licence

[EUPL-1.2](LICENSE)
