package tally

import "math/big"

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
