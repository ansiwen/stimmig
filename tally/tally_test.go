package tally

import (
	"encoding/json"
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
