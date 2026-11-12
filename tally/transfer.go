package tally

import "math/big"

// Rules shared by instant runoff and single transferable vote:
//
//   - A ballot counts for the candidates of its highest rank group that holds
//     a continuing candidate. Its weight is split equally among them.
//   - A ballot with no continuing candidate is exhausted.
//   - The candidate with the fewest votes is eliminated. A tie for the
//     fewest votes goes through the tie-break chain, and the candidate ranked
//     last by it is eliminated. If the chain leaves that tie standing, the
//     count stops and reports the tie.
//
// Instant runoff eliminates until one candidate is left.
//
// Single transferable vote uses the Droop quota floor(votes/(seats+1))+1,
// fixed at the start over the non-empty valid ballots. A candidate who
// reaches the quota is elected. All ballots of an elected candidate are
// transferred at the fraction surplus/total of their weight (weighted
// inclusive Gregory method). The surpluses of all candidates elected in the
// same round are transferred together, so their order never matters. When
// the continuing candidates are as many as the open seats, all are elected.

const (
	continuing = iota
	elected
	eliminated
)

type part struct {
	g int // ballot group
	w *big.Rat
}

type transferCount struct {
	e         *election
	status    []int
	piles     [][]part
	totals    []*big.Rat
	exhausted *big.Rat
}

// give moves a ballot part to the continuing candidates of its highest rank
// group that has any.
func (t *transferCount) give(p part) {
	for _, rank := range t.e.groups[p.g].ranks {
		var to []int
		for _, c := range rank {
			if t.status[c] == continuing {
				to = append(to, c)
			}
		}
		if len(to) == 0 {
			continue
		}
		w := new(big.Rat).Quo(p.w, big.NewRat(int64(len(to)), 1))
		for _, c := range to {
			t.piles[c] = append(t.piles[c], part{p.g, w})
			t.totals[c] = new(big.Rat).Add(t.totals[c], w)
		}
		return
	}
	t.exhausted = new(big.Rat).Add(t.exhausted, p.w)
}

func (t *transferCount) with(status int) []int {
	var cs []int
	for c, s := range t.status {
		if s == status {
			cs = append(cs, c)
		}
	}
	return cs
}

func (t *transferCount) byVotes(cs []int) [][]int {
	return tiersBy(cs, func(a, b int) int { return t.totals[b].Cmp(t.totals[a]) })
}

func (e *election) transfer() {
	t := &transferCount{
		e:         e,
		status:    make([]int, e.n),
		piles:     make([][]part, e.n),
		totals:    make([]*big.Rat, e.n),
		exhausted: new(big.Rat),
	}
	for c := range t.totals {
		t.totals[c] = new(big.Rat)
	}
	votes := 0
	for g, grp := range e.groups {
		votes += grp.count
		t.give(part{g, big.NewRat(int64(grp.count), 1)})
	}
	stv := e.m.Method == STV
	quota := big.NewRat(int64(votes/(e.seats+1)+1), 1)
	if stv {
		e.res.Trace = append(e.res.Trace, Step{Op: "quota", Note: quota.RatString()})
	}

	var electedTiers [][]int // in order of election
	var out []int            // in order of elimination
	numElected := 0
	var tie *Tie

	for round := 1; ; round++ {
		cont := t.with(continuing)
		vals := make([]Value, 0, len(cont)+1)
		for _, c := range cont {
			vals = append(vals, Value{e.m.Candidates[c], t.totals[c].RatString()})
		}
		e.res.Trace = append(e.res.Trace, Step{
			Op:     "count",
			Round:  round,
			Values: vals,
			Note:   "exhausted: " + t.exhausted.RatString(),
		})
		if numElected+len(cont) <= e.seats {
			// As many candidates as open seats: all are elected.
			if len(cont) > 0 {
				for _, c := range cont {
					t.status[c] = elected
				}
				electedTiers = append(electedTiers, t.byVotes(cont)...)
				e.res.Trace = append(e.res.Trace, Step{Op: "elect", Round: round, Candidates: e.names(cont), Note: "last candidates for the open seats"})
			}
			break
		}
		if stv {
			var reached []int
			for _, c := range cont {
				if t.totals[c].Cmp(quota) >= 0 {
					reached = append(reached, c)
				}
			}
			if len(reached) > 0 {
				for _, c := range reached {
					t.status[c] = elected
				}
				electedTiers = append(electedTiers, t.byVotes(reached)...)
				numElected += len(reached)
				e.res.Trace = append(e.res.Trace, Step{Op: "elect", Round: round, Candidates: e.names(reached), Note: "reached the quota"})
				if numElected == e.seats {
					break
				}
				for _, c := range reached {
					surplus := new(big.Rat).Sub(t.totals[c], quota)
					factor := new(big.Rat).Quo(surplus, t.totals[c])
					pile := t.piles[c]
					t.piles[c], t.totals[c] = nil, quota
					if surplus.Sign() == 0 {
						continue
					}
					e.res.Trace = append(e.res.Trace, Step{
						Op:         "transfer-surplus",
						Round:      round,
						Candidates: e.names([]int{c}),
						Note:       "surplus " + surplus.RatString() + ", factor " + factor.RatString(),
					})
					for _, p := range pile {
						t.give(part{p.g, new(big.Rat).Mul(p.w, factor)})
					}
				}
				continue
			}
		}
		// Eliminate the candidate with the fewest votes.
		tiers := t.byVotes(cont)
		lowest := tiers[len(tiers)-1]
		if len(lowest) > 1 {
			broken := e.breakTie(lowest, "elimination", round)
			lowest = broken[len(broken)-1]
		}
		if len(lowest) > 1 {
			tie = &Tie{Context: "elimination", Round: round, Candidates: e.names(lowest)}
			break
		}
		c := lowest[0]
		t.status[c] = eliminated
		out = append(out, c)
		e.res.Trace = append(e.res.Trace, Step{Op: "eliminate", Round: round, Candidates: e.names([]int{c})})
		pile := t.piles[c]
		t.piles[c], t.totals[c] = nil, new(big.Rat)
		for _, p := range pile {
			t.give(p)
		}
	}

	ranking := electedTiers
	if cont := t.with(continuing); len(cont) > 0 {
		ranking = append(ranking, cont)
	}
	for i := len(out) - 1; i >= 0; i-- {
		ranking = append(ranking, []int{out[i]})
	}
	e.res.Ranking = e.nameTiers(ranking)
	for _, tier := range electedTiers {
		e.res.Winners = append(e.res.Winners, e.names(tier)...)
	}
	e.res.Tie = tie
}
