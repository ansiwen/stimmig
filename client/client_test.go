package client

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ansiwen/stimmig/api"
	"github.com/ansiwen/stimmig/election"
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

func TestSameRanking(t *testing.T) {
	a := tally.Ballot{{"A"}, {"B", "C"}}
	for _, c := range []struct {
		x, y tally.Ballot
		want bool
	}{
		{a, tally.Ballot{{"A"}, {"B", "C"}}, true},
		{nil, tally.Ballot{}, true},
		{a, tally.Ballot{{"A"}}, false},
		{a, tally.Ballot{{"A"}, {"C", "B"}}, false},
		{a, nil, false},
	} {
		if got := sameRanking(c.x, c.y); got != c.want {
			t.Errorf("sameRanking(%v, %v) = %v", c.x, c.y, got)
		}
	}
}

func TestCheckIssued(t *testing.T) {
	ref := bytes.Repeat([]byte{1}, 32)
	other := bytes.Repeat([]byte{2}, 32)
	rep := &election.Report{RollReferences: [][]byte{ref, other}, IssuedReferences: [][]byte{ref}}
	if err := checkIssued(rep, ref); err != nil {
		t.Fatal(err)
	}
	if err := checkIssued(rep, other); err == nil || !strings.Contains(err.Error(), "no issuance") {
		t.Fatalf("on the roll, not issued: %v", err)
	}
	if err := checkIssued(rep, bytes.Repeat([]byte{3}, 32)); err == nil || !strings.Contains(err.Error(), "not in the public roll") {
		t.Fatalf("not on the roll: %v", err)
	}
}

func TestRefused(t *testing.T) {
	for code, want := range map[int]bool{
		400: true, 403: true, 409: true, 410: true, 425: true, 404: true,
		408: false, 429: false, 500: false, 502: false, 503: false,
	} {
		if got := refused(&api.StatusError{Code: code}); got != want {
			t.Errorf("status %d: refused = %v", code, got)
		}
	}
	if refused(errors.New("connection reset")) || refused(nil) {
		t.Error("an error without an answer counts as a refusal")
	}
}
