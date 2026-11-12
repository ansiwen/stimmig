package tally

import (
	"math/big"
	"sort"
	"strconv"
)

// schulze ranks by strongest paths. The strength of a pairwise win is its
// number of winning votes.
func (e *election) schulze() {
	n := e.n
	p := make([][]int, n)
	for i := range p {
		p[i] = make([]int, n)
		for j := range p[i] {
			if e.d[i][j] > e.d[j][i] {
				p[i][j] = e.d[i][j]
			}
		}
	}
	for k := 0; k < n; k++ {
		for i := 0; i < n; i++ {
			if i == k {
				continue
			}
			for j := 0; j < n; j++ {
				if j == i || j == k {
					continue
				}
				if s := min(p[i][k], p[k][j]); s > p[i][j] {
					p[i][j] = s
				}
			}
		}
	}
	e.res.Trace = append(e.res.Trace, Step{Op: "strongest-paths", Matrix: p})
	e.finish(peel(e.all(), func(a, b int) bool { return p[a][b] > p[b][a] }))
}

// peel turns a strict partial order into ranked groups: the candidates that
// no remaining candidate beats form the next group.
func peel(cs []int, beats func(a, b int) bool) [][]int {
	rem := append([]int(nil), cs...)
	var tiers [][]int
	for len(rem) > 0 {
		var tier, rest []int
		for _, c := range rem {
			beaten := false
			for _, o := range rem {
				if o != c && beats(o, c) {
					beaten = true
					break
				}
			}
			if beaten {
				rest = append(rest, c)
			} else {
				tier = append(tier, c)
			}
		}
		if len(tier) == 0 { // not a partial order; cannot happen
			tier, rest = rem, nil
		}
		tiers = append(tiers, tier)
		rem = rest
	}
	return tiers
}

// copeland ranks by pairwise wins minus pairwise losses.
func (e *election) copeland() {
	score := make([]int, e.n)
	for i := 0; i < e.n; i++ {
		for j := 0; j < e.n; j++ {
			switch {
			case e.d[i][j] > e.d[j][i]:
				score[i]++
			case e.d[i][j] < e.d[j][i]:
				score[i]--
			}
		}
	}
	e.scoreStep("copeland-scores", score, 1)
	e.finish(tiersBy(e.all(), func(a, b int) int { return score[b] - score[a] }))
}

// minimax ranks by the largest pairwise defeat, measured in the winning
// votes of the opponent. The smallest value is best.
func (e *election) minimax() {
	worst := make([]int, e.n)
	for i := 0; i < e.n; i++ {
		for j := 0; j < e.n; j++ {
			if e.d[j][i] > e.d[i][j] && e.d[j][i] > worst[i] {
				worst[i] = e.d[j][i]
			}
		}
	}
	e.scoreStep("minimax-worst-defeats", worst, 1)
	e.finish(tiersBy(e.all(), func(a, b int) int { return worst[a] - worst[b] }))
}

// borda ranks by Borda score: one point for every candidate ranked below,
// half a point for every candidate tied with.
func (e *election) borda() {
	e.scoreStep("borda-scores", e.borda2, 2)
	e.finish(tiersBy(e.all(), func(a, b int) int { return e.borda2[b] - e.borda2[a] }))
}

func (e *election) scoreStep(op string, score []int, denom int64) {
	vals := make([]Value, e.n)
	for i, s := range score {
		vals[i] = Value{Candidate: e.m.Candidates[i], Value: big.NewRat(int64(s), denom).RatString()}
	}
	e.res.Trace = append(e.res.Trace, Step{Op: op, Values: vals})
}

type pair struct{ w, l int }

// rankedPairs locks pairwise wins from strongest to weakest and skips every
// win that would close a cycle. Strength is the number of winning votes;
// among equal winning votes the smaller opposition is stronger.
//
// Wins of equal strength are locked together when that closes no cycle.
// Otherwise they are ordered by the tie-break chain applied to the candidates
// involved: first by the rank of the winner, then by the rank of the loser.
func (e *election) rankedPairs() {
	n := e.n
	var pairs []pair
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if e.d[i][j] > e.d[j][i] {
				pairs = append(pairs, pair{i, j})
			}
		}
	}
	stronger := func(a, b pair) int {
		if diff := e.d[b.w][b.l] - e.d[a.w][a.l]; diff != 0 {
			return diff
		}
		return e.d[a.l][a.w] - e.d[b.l][b.w]
	}
	sort.SliceStable(pairs, func(i, j int) bool { return stronger(pairs[i], pairs[j]) < 0 })

	locked := make([][]bool, n)
	for i := range locked {
		locked[i] = make([]bool, n)
	}
	lock := func(p pair) {
		op := "lock"
		if reaches(locked, p.l, p.w) {
			op = "skip"
		} else {
			locked[p.w][p.l] = true
		}
		e.res.Trace = append(e.res.Trace, Step{
			Op:         op,
			Candidates: e.names([]int{p.w, p.l}),
			Note:       strconv.Itoa(e.d[p.w][p.l]) + " to " + strconv.Itoa(e.d[p.l][p.w]),
		})
	}
	for start := 0; start < len(pairs); {
		end := start + 1
		for end < len(pairs) && stronger(pairs[start], pairs[end]) == 0 {
			end++
		}
		batch := pairs[start:end]
		start = end
		// Wins that close a cycle with stronger wins are skipped whatever
		// the order inside the batch.
		var open []pair
		for _, p := range batch {
			if reaches(locked, p.l, p.w) {
				lock(p)
			} else {
				open = append(open, p)
			}
		}
		if len(open) > 1 && e.conflict(locked, open) {
			var ok bool
			if open, ok = e.orderPairs(open); !ok {
				return
			}
		}
		for _, p := range open {
			lock(p)
		}
	}
	e.finish(peel(e.all(), func(a, b int) bool { return locked[a][b] }))
}

// conflict reports whether locking all pairs together closes a cycle.
func (e *election) conflict(locked [][]bool, open []pair) bool {
	trial := make([][]bool, e.n)
	for i := range trial {
		trial[i] = append([]bool(nil), locked[i]...)
	}
	for _, p := range open {
		trial[p.w][p.l] = true
	}
	for _, p := range open {
		if reaches(trial, p.l, p.w) {
			return true
		}
	}
	return false
}

// orderPairs orders equally strong pairs with the tie-break chain. It
// reports false, and sets the tie in the result, when two pairs stay tied.
func (e *election) orderPairs(open []pair) ([]pair, bool) {
	seen := make([]bool, e.n)
	var involved []int
	for _, p := range open {
		for _, c := range []int{p.w, p.l} {
			if !seen[c] {
				seen[c] = true
				involved = append(involved, c)
			}
		}
	}
	tiers := e.breakTie(involved, "pair-order", 0)
	rank := make([]int, e.n)
	for r, t := range tiers {
		for _, c := range t {
			rank[c] = r
		}
	}
	cmp := func(a, b pair) int {
		if diff := rank[a.w] - rank[b.w]; diff != 0 {
			return diff
		}
		return rank[a.l] - rank[b.l]
	}
	out := append([]pair(nil), open...)
	sort.SliceStable(out, func(i, j int) bool { return cmp(out[i], out[j]) < 0 })
	for i := 1; i < len(out); i++ {
		if cmp(out[i-1], out[i]) == 0 {
			sort.Ints(involved)
			e.res.Tie = &Tie{Context: "pair-order", Candidates: e.names(involved)}
			e.res.Ranking = [][]string{e.names(e.all())}
			return nil, false
		}
	}
	return out, true
}

// reaches reports whether a path of locked wins leads from a to b.
func reaches(locked [][]bool, a, b int) bool {
	seen := make([]bool, len(locked))
	stack := []int{a}
	seen[a] = true
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if c == b {
			return true
		}
		for o, l := range locked[c] {
			if l && !seen[o] {
				seen[o] = true
				stack = append(stack, o)
			}
		}
	}
	return false
}
