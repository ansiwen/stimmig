package tally

// breakTie applies the tie-break chain to a group of tied candidates and
// returns them in groups, best first. Each rule is applied only to the
// candidates still tied after the previous one. Every application is recorded
// as a tie-break event.
func (e *election) breakTie(tied []int, context string, round int) [][]int {
	tiers := tiersBy(tied, func(_, _ int) int { return 0 })
	for _, rule := range e.chain {
		var next [][]int
		for _, t := range tiers {
			if len(t) < 2 {
				next = append(next, t)
				continue
			}
			sub := e.applyRule(rule, t)
			e.res.TieBreaks = append(e.res.TieBreaks, TieBreakEvent{
				Context: context,
				Round:   round,
				Rule:    rule,
				Tied:    e.names(t),
				Order:   e.nameTiers(sub),
			})
			e.res.Trace = append(e.res.Trace, Step{
				Op:         "tie-break",
				Round:      round,
				Candidates: e.names(t),
				Note:       context + ": " + string(rule),
			})
			next = append(next, sub...)
		}
		tiers = next
	}
	return tiers
}

func (e *election) applyRule(rule TieBreakRule, t []int) [][]int {
	switch rule {
	case FirstRanks:
		return tiersBy(t, func(a, b int) int {
			for k := 0; k < e.maxRanks; k++ {
				if diff := e.first[b][k] - e.first[a][k]; diff != 0 {
					return diff
				}
			}
			return 0
		})
	case HeadToHead:
		return e.headToHead(t)
	case BordaScore:
		return tiersBy(t, func(a, b int) int { return e.borda2[b] - e.borda2[a] })
	case FixedOrder:
		return tiersBy(t, func(a, b int) int { return e.fixedPos[a] - e.fixedPos[b] })
	default: // DeclareTie
		return [][]int{t}
	}
}

// headToHead repeatedly moves the candidate who beats all other remaining
// tied candidates pairwise to the top, and the one who loses to all others
// to the bottom. Candidates for whom neither holds stay tied in the middle.
func (e *election) headToHead(t []int) [][]int {
	rem := append([]int(nil), t...)
	var top, bottom [][]int
	for len(rem) > 1 {
		winner, loser := -1, -1
		for _, c := range rem {
			beatsAll, losesToAll := true, true
			for _, o := range rem {
				if o == c {
					continue
				}
				if e.d[c][o] <= e.d[o][c] {
					beatsAll = false
				}
				if e.d[c][o] >= e.d[o][c] {
					losesToAll = false
				}
			}
			if beatsAll {
				winner = c
			}
			if losesToAll {
				loser = c
			}
		}
		if winner < 0 && loser < 0 {
			break
		}
		if winner >= 0 {
			top = append(top, []int{winner})
			rem = remove(rem, winner)
		}
		if loser >= 0 {
			bottom = append(bottom, []int{loser})
			rem = remove(rem, loser)
		}
	}
	out := top
	if len(rem) > 0 {
		out = append(out, rem)
	}
	for i := len(bottom) - 1; i >= 0; i-- {
		out = append(out, bottom[i])
	}
	return out
}

func remove(cs []int, c int) []int {
	out := cs[:0:0]
	for _, x := range cs {
		if x != c {
			out = append(out, x)
		}
	}
	return out
}
