package client

import (
	"reflect"
	"testing"

	"github.com/ansiwen/stimmig/tally"
)

// The network flows are tested end to end in cmd/stimmig.

func TestParseRanking(t *testing.T) {
	cases := map[string]tally.Ballot{
		"":            {},
		"  ":          {},
		"A":           {{"A"}},
		"A>B":         {{"A"}, {"B"}},
		" A > B = C ": {{"A"}, {"B", "C"}},
		"A>>B":        {{"A"}, {""}, {"B"}}, // the tally rejects the empty candidate
	}
	for in, want := range cases {
		if got := ParseRanking(in); !reflect.DeepEqual(got, want) {
			t.Errorf("ParseRanking(%q) = %v, want %v", in, got, want)
		}
	}
}
