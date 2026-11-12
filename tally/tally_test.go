package tally

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type vector struct {
	Description string   `json:"description"`
	Manifest    Manifest `json:"manifest"`
	Ballots     []struct {
		Count   int    `json:"count"`
		Ranking Ballot `json:"ranking"`
	} `json:"ballots"`
	Expect struct {
		Winners       []string       `json:"winners"`
		Ranking       [][]string     `json:"ranking"`
		Tie           []string       `json:"tie"`
		Pairwise      [][]int        `json:"pairwise"`
		TieBreakRules []TieBreakRule `json:"tie_break_rules"`
	} `json:"expect"`
}

func TestVectors(t *testing.T) {
	files, err := filepath.Glob("testdata/vectors/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no vectors: %v", err)
	}
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".json"), func(t *testing.T) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var v vector
			dec := json.NewDecoder(strings.NewReader(string(data)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&v); err != nil {
				t.Fatal(err)
			}
			var ballots []Ballot
			for _, b := range v.Ballots {
				for i := 0; i < b.Count; i++ {
					ballots = append(ballots, b.Ranking)
				}
			}
			res, err := Tally(v.Manifest, ballots)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Invalid) > 0 {
				t.Errorf("invalid ballots: %v", res.Invalid)
			}
			if !reflect.DeepEqual(res.Winners, v.Expect.Winners) {
				t.Errorf("winners = %v, want %v", res.Winners, v.Expect.Winners)
			}
			if !reflect.DeepEqual(res.Ranking, v.Expect.Ranking) {
				t.Errorf("ranking = %v, want %v", res.Ranking, v.Expect.Ranking)
			}
			var tie []string
			if res.Tie != nil {
				tie = res.Tie.Candidates
			}
			if !reflect.DeepEqual(tie, v.Expect.Tie) {
				t.Errorf("tie = %v, want %v", tie, v.Expect.Tie)
			}
			if v.Expect.Pairwise != nil && !reflect.DeepEqual(res.Pairwise, v.Expect.Pairwise) {
				t.Errorf("pairwise = %v, want %v", res.Pairwise, v.Expect.Pairwise)
			}
			if v.Expect.TieBreakRules != nil {
				rules := []TieBreakRule{}
				for _, ev := range res.TieBreaks {
					rules = append(rules, ev.Rule)
				}
				if !reflect.DeepEqual(rules, v.Expect.TieBreakRules) {
					t.Errorf("tie-break rules = %v, want %v", rules, v.Expect.TieBreakRules)
				}
			}
		})
	}
}

var allMethods = []Method{Schulze, RankedPairs, Minimax, Copeland, IRV, Borda, STV}

// randomBallots builds valid ballots with equal ranks and truncation.
func randomBallots(r *rand.Rand, cands []string, maxRanks, count int) []Ballot {
	ballots := make([]Ballot, count)
	for i := range ballots {
		perm := r.Perm(len(cands))
		perm = perm[:1+r.Intn(len(cands))]
		var b Ballot
		for _, c := range perm {
			if len(b) > 0 && (len(b) == maxRanks || r.Intn(4) == 0) {
				b[len(b)-1] = append(b[len(b)-1], cands[c])
			} else {
				b = append(b, []string{cands[c]})
			}
		}
		ballots[i] = b
	}
	return ballots
}

func randomElection(r *rand.Rand) ([]string, int, []Ballot) {
	cands := []string{"A", "B", "C", "D", "E", "F"}[:2+r.Intn(5)]
	maxRanks := 1 + r.Intn(len(cands))
	return cands, maxRanks, randomBallots(r, cands, maxRanks, r.Intn(40))
}

// A Condorcet winner wins under every Condorcet method.
func TestCondorcetWinnerWins(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	found := 0
	for i := 0; i < 3000; i++ {
		cands, maxRanks, ballots := randomElection(r)
		for _, method := range []Method{Schulze, RankedPairs, Minimax, Copeland} {
			res, err := Tally(Manifest{Candidates: cands, Method: method, MaxRanks: maxRanks}, ballots)
			if err != nil {
				t.Fatal(err)
			}
			cw := -1
			for a := range cands {
				beatsAll := true
				for b := range cands {
					if a != b && res.Pairwise[a][b] <= res.Pairwise[b][a] {
						beatsAll = false
					}
				}
				if beatsAll {
					cw = a
				}
			}
			if cw < 0 {
				continue
			}
			found++
			if len(res.Winners) != 1 || res.Winners[0] != cands[cw] {
				t.Fatalf("%s: Condorcet winner %s, winners %v, ballots %v", method, cands[cw], res.Winners, ballots)
			}
			if len(res.TieBreaks) > 0 && res.TieBreaks[0].Context == "ranking" && contains(res.TieBreaks[0].Tied, cands[cw]) {
				t.Fatalf("%s: Condorcet winner %s needed a tie-break", method, cands[cw])
			}
		}
	}
	if found < 1000 {
		t.Fatalf("only %d cases with a Condorcet winner", found)
	}
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

// The order of the ballots never changes the result, and the result is
// well-formed.
func TestBallotOrderAndShape(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	chains := [][]TieBreakRule{
		nil,
		{HeadToHead, BordaScore, FirstRanks, DeclareTie},
		{BordaScore, FixedOrder},
		{FixedOrder},
	}
	for i := 0; i < 2000; i++ {
		cands, maxRanks, ballots := randomElection(r)
		m := Manifest{Candidates: cands, MaxRanks: maxRanks, AllowEmpty: true}
		m.Method = allMethods[r.Intn(len(allMethods))]
		m.TieBreak = chains[r.Intn(len(chains))]
		m.FixedOrder = cands
		if m.Method == Schulze || m.Method == STV {
			m.Seats = 1 + r.Intn(len(cands))
		}
		res, err := Tally(m, ballots)
		if err != nil {
			t.Fatal(err)
		}
		shuffled := append([]Ballot(nil), ballots...)
		r.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		res2, err := Tally(m, shuffled)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(res, res2) {
			t.Fatalf("%s: result depends on ballot order: %v", m.Method, ballots)
		}

		if res.Valid != len(ballots) {
			t.Fatalf("valid = %d, want %d: %v", res.Valid, len(ballots), res.Invalid)
		}
		seen := map[string]bool{}
		for _, tier := range res.Ranking {
			for _, c := range tier {
				if seen[c] {
					t.Fatalf("%s: %s ranked twice", m.Method, c)
				}
				seen[c] = true
			}
		}
		if len(seen) != len(cands) {
			t.Fatalf("%s: ranking %v does not cover %v", m.Method, res.Ranking, cands)
		}
		switch {
		case res.Tie == nil && len(res.Winners) != res.Seats:
			t.Fatalf("%s: %d winners for %d seats without a tie", m.Method, len(res.Winners), res.Seats)
		case res.Tie != nil && len(res.Winners) >= res.Seats:
			t.Fatalf("%s: tie reported with all seats filled", m.Method)
		case res.Tie != nil && m.TieBreak != nil && m.TieBreak[len(m.TieBreak)-1] == FixedOrder:
			t.Fatalf("%s: tie reported although the chain ends with fixed-order: %v", m.Method, ballots)
		}
	}
}

// With one seat, stv and irv elect the same candidate.
func TestSTVOneSeatMatchesIRV(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for i := 0; i < 1000; i++ {
		cands, maxRanks, ballots := randomElection(r)
		m := Manifest{Candidates: cands, MaxRanks: maxRanks, Method: IRV, TieBreak: []TieBreakRule{FixedOrder}, FixedOrder: cands}
		irv, _ := Tally(m, ballots)
		m.Method = STV
		stv, _ := Tally(m, ballots)
		if !reflect.DeepEqual(irv.Winners, stv.Winners) {
			t.Fatalf("irv %v, stv %v: %v", irv.Winners, stv.Winners, ballots)
		}
	}
}

func TestInvalidBallots(t *testing.T) {
	m := Manifest{Candidates: []string{"A", "B", "C"}, Method: Schulze, MaxRanks: 2, NoEqualRanks: true}
	ballots := []Ballot{
		{{"A"}, {"B"}},
		{},
		{{"A"}, {"B"}, {"C"}},
		{{"A", "B"}},
		{{"A"}, {"A"}},
		{{"X"}},
		{{"A"}, {}},
	}
	res, err := Tally(m, ballots)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ballots != 7 || res.Valid != 1 || len(res.Invalid) != 6 {
		t.Fatalf("ballots %d, valid %d, invalid %v", res.Ballots, res.Valid, res.Invalid)
	}
	for i, inv := range res.Invalid {
		if inv.Index != i+1 || inv.Reason == "" {
			t.Errorf("invalid[%d] = %+v", i, inv)
		}
	}
	m.AllowEmpty = true
	res, _ = Tally(m, ballots)
	if res.Valid != 2 || res.Abstentions != 1 {
		t.Fatalf("valid %d, abstentions %d", res.Valid, res.Abstentions)
	}
}

func TestInvalidManifests(t *testing.T) {
	ab := []string{"A", "B"}
	bad := []Manifest{
		{Method: Schulze},
		{Candidates: []string{"A", "A"}, Method: Schulze},
		{Candidates: []string{"A", ""}, Method: Schulze},
		{Candidates: ab},
		{Candidates: ab, Method: "plurality"},
		{Candidates: ab, Method: Schulze, Seats: 3},
		{Candidates: ab, Method: Schulze, Seats: -1},
		{Candidates: ab, Method: IRV, Seats: 2},
		{Candidates: ab, Method: Schulze, MaxRanks: 3},
		{Candidates: ab, Method: Schulze, TieBreak: []TieBreakRule{FirstRanks}},
		{Candidates: ab, Method: Schulze, TieBreak: []TieBreakRule{DeclareTie, FirstRanks}},
		{Candidates: ab, Method: Schulze, TieBreak: []TieBreakRule{FirstRanks, FirstRanks, DeclareTie}},
		{Candidates: ab, Method: Schulze, TieBreak: []TieBreakRule{"coin", DeclareTie}},
		{Candidates: ab, Method: Schulze, TieBreak: []TieBreakRule{FixedOrder}},
		{Candidates: ab, Method: Schulze, TieBreak: []TieBreakRule{FixedOrder}, FixedOrder: []string{"A", "A"}},
		{Candidates: ab, Method: Schulze, TieBreak: []TieBreakRule{FixedOrder}, FixedOrder: []string{"A", "C"}},
	}
	for i, m := range bad {
		if _, err := Tally(m, nil); err == nil {
			t.Errorf("manifest %d accepted: %+v", i, m)
		}
	}
	if err := (Manifest{Candidates: ab, Method: Schulze}).Validate(); err != nil {
		t.Error(err)
	}
	if (Manifest{Candidates: ab}).Validate() == nil {
		t.Error("Validate accepted a manifest without method")
	}
}

// Ranked pairs with equally strong wins that conflict: the three-way cycle
// A>B, B>C, C>A, each 2 to 1.
func TestRankedPairsPairOrder(t *testing.T) {
	cands := []string{"A", "B", "C"}
	ballots := []Ballot{
		{{"A"}, {"B"}, {"C"}},
		{{"B"}, {"C"}, {"A"}},
		{{"C"}, {"A"}, {"B"}},
	}
	res, _ := Tally(Manifest{Candidates: cands, Method: RankedPairs}, ballots)
	if res.Tie == nil || res.Tie.Context != "pair-order" || len(res.Winners) != 0 {
		t.Fatalf("want an unresolved pair-order tie, got winners %v, tie %+v", res.Winners, res.Tie)
	}
	// Order C, B, A: C>A is locked first, then B>C; A>B is skipped.
	res, _ = Tally(Manifest{
		Candidates: cands, Method: RankedPairs,
		TieBreak: []TieBreakRule{FixedOrder}, FixedOrder: []string{"C", "B", "A"},
	}, ballots)
	want := [][]string{{"B"}, {"C"}, {"A"}}
	if !reflect.DeepEqual(res.Ranking, want) || res.Tie != nil {
		t.Fatalf("ranking %v, want %v", res.Ranking, want)
	}
}

func FuzzTally(f *testing.F) {
	f.Add(`{"candidates":["A","B","C"],"method":"stv","seats":2}`, `[[["A"],["B","C"]],[["C"]],[]]`)
	f.Add(`{"candidates":["A","B"],"method":"ranked-pairs"}`, `[[["A"]],[["B"]]]`)
	f.Fuzz(func(t *testing.T, manifest, ballots string) {
		var m Manifest
		var b []Ballot
		if json.Unmarshal([]byte(manifest), &m) != nil || json.Unmarshal([]byte(ballots), &b) != nil {
			return
		}
		if len(m.Candidates) > 8 || len(b) > 50 {
			return
		}
		res, err := Tally(m, b)
		if err != nil {
			return
		}
		if res.Valid+len(res.Invalid) != len(b) {
			t.Fatalf("valid %d + invalid %d != %d", res.Valid, len(res.Invalid), len(b))
		}
	})
}
