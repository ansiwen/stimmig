// Package tally computes ranked-choice election results.
//
// Every method is a pure function from a manifest and a list of ballots to a
// result with a full trace (SPEC.md section 8). The package does no I/O, uses
// only exact integer and rational arithmetic, and never depends on map
// iteration order or on the order of the ballots.
package tally

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

// Method names a tally method.
type Method string

// Tally methods of v1.
const (
	Schulze     Method = "schulze"
	RankedPairs Method = "ranked-pairs"
	Minimax     Method = "minimax"
	Copeland    Method = "copeland"
	IRV         Method = "irv"
	Borda       Method = "borda"
	STV         Method = "stv"
)

// TieBreakRule names one rule of the tie-break chain.
type TieBreakRule string

// Tie-break rules. None of them is random.
const (
	// FirstRanks prefers the candidate in the first rank group of the most
	// ballots, then compares second ranks, and so on down to max_ranks.
	FirstRanks TieBreakRule = "first-ranks"
	// HeadToHead prefers, among the tied candidates only, the one who beats
	// all others pairwise.
	HeadToHead TieBreakRule = "head-to-head"
	// BordaScore prefers the highest Borda score over all ballots.
	BordaScore TieBreakRule = "borda"
	// FixedOrder uses the candidate order listed in the manifest.
	FixedOrder TieBreakRule = "fixed-order"
	// DeclareTie leaves the tie standing and reports it.
	DeclareTie TieBreakRule = "declare-tie"
)

// Manifest holds the part of the election manifest that the tally needs.
type Manifest struct {
	// Candidates lists the candidate IDs. Their order is the canonical order
	// of the pairwise matrix and of candidates inside a tied group.
	Candidates []string `json:"candidates"`
	Method     Method   `json:"method"`
	// Seats is the number of winners. Zero means one. More than one seat is
	// supported by schulze (top places of the ranking) and stv.
	Seats int `json:"seats,omitempty"`
	// MaxRanks limits the number of rank groups on a ballot. Zero means the
	// number of candidates.
	MaxRanks int `json:"max_ranks,omitempty"`
	// NoEqualRanks forbids more than one candidate in a rank group.
	NoEqualRanks bool `json:"no_equal_ranks,omitempty"`
	// AllowEmpty makes an empty ballot a valid abstention.
	AllowEmpty bool `json:"allow_empty,omitempty"`
	// TieBreak is the ordered chain of rules. It must end with fixed-order
	// or declare-tie. Empty means first-ranks, then declare-tie.
	TieBreak []TieBreakRule `json:"tie_break,omitempty"`
	// FixedOrder lists all candidates, best first, for the fixed-order rule.
	FixedOrder []string `json:"fixed_order,omitempty"`
}

// Ballot is an ordered list of rank groups, best first. Each group holds one
// or more candidate IDs. Unranked candidates count as tied below all ranked.
type Ballot [][]string

// Result is the outcome of a tally.
type Result struct {
	Method     Method   `json:"method"`
	Seats      int      `json:"seats"`
	Candidates []string `json:"candidates"`
	// Ballots is the number of ballots given, Valid the number counted.
	Ballots int `json:"ballots"`
	Valid   int `json:"valid"`
	// Abstentions is the number of valid empty ballots.
	Abstentions int             `json:"abstentions"`
	Invalid     []InvalidBallot `json:"invalid,omitempty"`
	// Winners holds the candidates that definitely win a seat. It has fewer
	// than Seats entries exactly when Tie is set.
	Winners []string `json:"winners"`
	// Ranking lists all candidates in groups, best first. Candidates in one
	// group are tied.
	Ranking [][]string `json:"ranking"`
	// Tie is set when the tie-break chain left a tie that affects the
	// winners.
	Tie *Tie `json:"tie,omitempty"`
	// Pairwise[i][j] is the number of ballots that rank candidate i strictly
	// above candidate j, in manifest candidate order.
	Pairwise  [][]int         `json:"pairwise"`
	Trace     []Step          `json:"trace"`
	TieBreaks []TieBreakEvent `json:"tie_breaks,omitempty"`
}

// InvalidBallot reports a ballot that was not counted.
type InvalidBallot struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

// Tie reports an unresolved tie.
type Tie struct {
	// Context is "ranking", "elimination" or "pair-order".
	Context    string   `json:"context"`
	Round      int      `json:"round,omitempty"`
	Candidates []string `json:"candidates"`
}

// Step is one entry of the trace.
type Step struct {
	Op         string   `json:"op"`
	Round      int      `json:"round,omitempty"`
	Candidates []string `json:"candidates,omitempty"`
	Values     []Value  `json:"values,omitempty"`
	Matrix     [][]int  `json:"matrix,omitempty"`
	Note       string   `json:"note,omitempty"`
}

// Value is an exact number attached to a candidate, written as an integer or
// as a fraction "a/b".
type Value struct {
	Candidate string `json:"candidate"`
	Value     string `json:"value"`
}

// TieBreakEvent records one application of one tie-break rule.
type TieBreakEvent struct {
	Context string       `json:"context"`
	Round   int          `json:"round,omitempty"`
	Rule    TieBreakRule `json:"rule"`
	Tied    []string     `json:"tied"`
	// Order is the tied group after the rule, best first. A group with more
	// than one candidate is still tied.
	Order [][]string `json:"order"`
}

// group is a set of identical ballots.
type group struct {
	ranks [][]int // candidate indexes, each rank group sorted
	count int
}

type election struct {
	m        Manifest
	n        int
	seats    int
	maxRanks int
	chain    []TieBreakRule
	fixedPos []int // position of each candidate in the fixed order
	groups   []group
	d        [][]int // pairwise matrix
	first    [][]int // first[c][k]: ballots with candidate c in rank group k
	borda2   []int   // twice the Borda score
	res      *Result
}

// Tally computes the result of an election. Invalid ballots are not counted
// and are reported in the result. An error is returned only for an invalid
// manifest.
func Tally(m Manifest, ballots []Ballot) (*Result, error) {
	e, err := newElection(m)
	if err != nil {
		return nil, err
	}
	e.load(ballots)
	e.res.Trace = append(e.res.Trace, Step{Op: "pairwise", Matrix: e.d})
	switch m.Method {
	case Schulze:
		e.schulze()
	case RankedPairs:
		e.rankedPairs()
	case Minimax:
		e.minimax()
	case Copeland:
		e.copeland()
	case Borda:
		e.borda()
	case IRV, STV:
		e.transfer()
	}
	return e.res, nil
}

// Validate reports whether the manifest is usable for a tally.
func (m Manifest) Validate() error {
	_, err := newElection(m)
	return err
}

func newElection(m Manifest) (*election, error) {
	n := len(m.Candidates)
	if n == 0 {
		return nil, errors.New("tally: no candidates")
	}
	idx := make(map[string]int, n)
	for i, c := range m.Candidates {
		if c == "" {
			return nil, errors.New("tally: empty candidate ID")
		}
		if _, dup := idx[c]; dup {
			return nil, fmt.Errorf("tally: duplicate candidate %q", c)
		}
		idx[c] = i
	}
	e := &election{m: m, n: n, seats: m.Seats, maxRanks: m.MaxRanks}
	if e.seats == 0 {
		e.seats = 1
	}
	if e.seats < 1 || e.seats > n {
		return nil, fmt.Errorf("tally: seats must be between 1 and %d", n)
	}
	switch m.Method {
	case Schulze, STV:
	case RankedPairs, Minimax, Copeland, IRV, Borda:
		if e.seats > 1 {
			return nil, fmt.Errorf("tally: method %q supports one seat only", m.Method)
		}
	default:
		return nil, fmt.Errorf("tally: unknown method %q", m.Method)
	}
	if e.maxRanks == 0 {
		e.maxRanks = n
	}
	if e.maxRanks < 1 || e.maxRanks > n {
		return nil, fmt.Errorf("tally: max_ranks must be between 1 and %d", n)
	}
	e.chain = m.TieBreak
	if len(e.chain) == 0 {
		e.chain = []TieBreakRule{FirstRanks, DeclareTie}
	}
	seen := map[TieBreakRule]bool{}
	for i, r := range e.chain {
		last := i == len(e.chain)-1
		switch r {
		case FirstRanks, HeadToHead, BordaScore:
			if last {
				return nil, errors.New("tally: tie-break chain must end with fixed-order or declare-tie")
			}
		case FixedOrder, DeclareTie:
			if !last {
				return nil, fmt.Errorf("tally: tie-break rule %q must be last", r)
			}
		default:
			return nil, fmt.Errorf("tally: unknown tie-break rule %q", r)
		}
		if seen[r] {
			return nil, fmt.Errorf("tally: tie-break rule %q repeated", r)
		}
		seen[r] = true
	}
	if seen[FixedOrder] || len(m.FixedOrder) > 0 {
		if len(m.FixedOrder) != n {
			return nil, errors.New("tally: fixed_order must list every candidate once")
		}
		e.fixedPos = make([]int, n)
		used := make([]bool, n)
		for pos, c := range m.FixedOrder {
			i, ok := idx[c]
			if !ok || used[i] {
				return nil, errors.New("tally: fixed_order must list every candidate once")
			}
			used[i] = true
			e.fixedPos[i] = pos
		}
	}
	e.d = make([][]int, n)
	e.first = make([][]int, n)
	for i := range e.d {
		e.d[i] = make([]int, n)
		e.first[i] = make([]int, e.maxRanks)
	}
	e.borda2 = make([]int, n)
	e.res = &Result{
		Method:     m.Method,
		Seats:      e.seats,
		Candidates: append([]string(nil), m.Candidates...),
		Winners:    []string{},
		Pairwise:   e.d,
	}
	return e, nil
}

// PossibleBallots returns the number of different valid ballots of an
// election. If it exceeds the number of voters, a ranking can work as a
// fingerprint that identifies a ballot (SPEC.md section 2).
func (m Manifest) PossibleBallots() (*big.Int, error) {
	e, err := newElection(m)
	if err != nil {
		return nil, err
	}
	// ways[r] is the number of ways to fill the ranks counted so far when r
	// candidates are still unranked.
	ways := make([]*big.Int, e.n+1)
	for r := range ways {
		ways[r] = big.NewInt(1)
	}
	total := new(big.Int)
	if m.AllowEmpty {
		total.SetInt64(1)
	}
	for rank := 1; rank <= e.maxRanks; rank++ {
		next := make([]*big.Int, e.n+1)
		for r := range next {
			next[r] = new(big.Int)
			// The first of the ranks takes size candidates of the r.
			for size := 1; size <= r; size++ {
				if size > 1 && m.NoEqualRanks {
					break
				}
				c := new(big.Int).Binomial(int64(r), int64(size))
				next[r].Add(next[r], c.Mul(c, ways[r-size]))
			}
		}
		ways = next
		total.Add(total, ways[e.n])
	}
	return total, nil
}

// parse validates a ballot and converts it to candidate indexes.
func (e *election) parse(idx map[string]int, b Ballot) ([][]int, error) {
	if len(b) == 0 && !e.m.AllowEmpty {
		return nil, errors.New("empty ballot")
	}
	if len(b) > e.maxRanks {
		return nil, fmt.Errorf("%d ranks, maximum is %d", len(b), e.maxRanks)
	}
	used := make([]bool, e.n)
	ranks := make([][]int, len(b))
	for k, g := range b {
		if len(g) == 0 {
			return nil, fmt.Errorf("rank %d is empty", k+1)
		}
		if len(g) > 1 && e.m.NoEqualRanks {
			return nil, fmt.Errorf("rank %d holds %d candidates, equal ranks are disabled", k+1, len(g))
		}
		for _, c := range g {
			i, ok := idx[c]
			if !ok {
				return nil, fmt.Errorf("unknown candidate %q", c)
			}
			if used[i] {
				return nil, fmt.Errorf("candidate %q ranked twice", c)
			}
			used[i] = true
			ranks[k] = append(ranks[k], i)
		}
		sort.Ints(ranks[k])
	}
	return ranks, nil
}

// load validates and aggregates the ballots and computes the pairwise
// matrix, the rank counts and the Borda scores.
func (e *election) load(ballots []Ballot) {
	idx := make(map[string]int, e.n)
	for i, c := range e.m.Candidates {
		idx[c] = i
	}
	e.res.Ballots = len(ballots)
	byKey := map[string]int{}
	var keys []string
	for i, b := range ballots {
		ranks, err := e.parse(idx, b)
		if err != nil {
			e.res.Invalid = append(e.res.Invalid, InvalidBallot{Index: i, Reason: err.Error()})
			continue
		}
		e.res.Valid++
		if len(ranks) == 0 {
			e.res.Abstentions++
			continue
		}
		key := ballotKey(ranks)
		g, ok := byKey[key]
		if !ok {
			g = len(e.groups)
			byKey[key] = g
			keys = append(keys, key)
			e.groups = append(e.groups, group{ranks: ranks})
		}
		e.groups[g].count++
	}
	// Sort the groups so that nothing depends on the ballot order.
	sort.Strings(keys)
	sorted := make([]group, len(keys))
	for i, k := range keys {
		sorted[i] = e.groups[byKey[k]]
	}
	e.groups = sorted

	pos := make([]int, e.n)
	for _, g := range e.groups {
		for i := range pos {
			pos[i] = len(g.ranks) // unranked: below all ranked
		}
		for k, rank := range g.ranks {
			for _, c := range rank {
				pos[c] = k
				e.first[c][k] += g.count
			}
		}
		for i := 0; i < e.n; i++ {
			for j := 0; j < e.n; j++ {
				if pos[i] < pos[j] {
					e.d[i][j] += g.count
				}
			}
		}
	}
	// Borda: one point per candidate ranked below, half a point per
	// candidate tied with. Stored doubled to stay in integers.
	for i := 0; i < e.n; i++ {
		for j := 0; j < e.n; j++ {
			if i != j {
				ties := e.res.Valid - e.d[i][j] - e.d[j][i]
				e.borda2[i] += 2*e.d[i][j] + ties
			}
		}
	}
}

func ballotKey(ranks [][]int) string {
	var sb strings.Builder
	for _, rank := range ranks {
		for _, c := range rank {
			sb.WriteString(strconv.Itoa(c))
			sb.WriteByte(',')
		}
		sb.WriteByte('|')
	}
	return sb.String()
}

func (e *election) names(cs []int) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = e.m.Candidates[c]
	}
	return out
}

func (e *election) nameTiers(tiers [][]int) [][]string {
	out := make([][]string, len(tiers))
	for i, t := range tiers {
		out[i] = e.names(t)
	}
	return out
}

func (e *election) all() []int {
	cs := make([]int, e.n)
	for i := range cs {
		cs[i] = i
	}
	return cs
}

// tiersBy sorts candidates into groups, best first. cmp returns a negative
// number when a is better than b and zero when they are tied. cmp must be a
// weak order.
func tiersBy(cs []int, cmp func(a, b int) int) [][]int {
	s := append([]int(nil), cs...)
	sort.Ints(s)
	sort.SliceStable(s, func(i, j int) bool { return cmp(s[i], s[j]) < 0 })
	var out [][]int
	for i, c := range s {
		if i > 0 && cmp(s[i-1], c) == 0 {
			out[len(out)-1] = append(out[len(out)-1], c)
		} else {
			out = append(out, []int{c})
		}
	}
	return out
}

// finish breaks the ties inside the tiers of a ranking, stores the ranking
// and derives the winners from it.
func (e *election) finish(tiers [][]int) {
	var final [][]int
	for _, t := range tiers {
		if len(t) > 1 {
			final = append(final, e.breakTie(t, "ranking", 0)...)
		} else {
			final = append(final, t)
		}
	}
	e.res.Ranking = e.nameTiers(final)
	placed := 0
	for _, t := range final {
		if placed >= e.seats {
			break
		}
		if placed+len(t) > e.seats {
			e.res.Tie = &Tie{Context: "ranking", Candidates: e.names(t)}
			break
		}
		e.res.Winners = append(e.res.Winners, e.names(t)...)
		placed += len(t)
	}
}
