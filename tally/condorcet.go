package tally

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
