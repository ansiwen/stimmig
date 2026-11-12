package tally

import "testing"

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
