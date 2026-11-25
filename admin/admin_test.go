package admin

import (
	"strings"
	"testing"

	"github.com/ansiwen/stimmig/tally"
)

func TestParseVotersRefusesWhatCannotLogIn(t *testing.T) {
	for _, line := range []string{"Ada <ada@example.org>", "a@example.org, b@example.org", "ada", "ada@"} {
		if _, err := ParseVoters("ok@example.org\n" + line + "\n"); err == nil || !strings.Contains(err.Error(), "line 2") {
			t.Errorf("%q: %v", line, err)
		}
	}
}

func TestParseVotersRefusesBadOIDCLines(t *testing.T) {
	for _, line := range []string{"oidc: https://idp.example#sub", "oidc:https://idp.example", "oidc:#sub", "oidc:https://idp.example#", "oidc:https://idp.example#a\tb"} {
		if _, err := ParseVoters(line + "\n"); err == nil || !strings.Contains(err.Error(), "line 1") {
			t.Errorf("%q: %v", line, err)
		}
	}
}

func TestParseVoters(t *testing.T) {
	roll, err := ParseVoters(" Ada@Example.org \n\noidc:https://idp.example#User-42\n")
	if err != nil || len(roll.Voters) != 2 {
		t.Fatalf("%+v, %v", roll, err)
	}
	if v := roll.Voters[0]; v.Provider != "email" || v.Subject != "ada@example.org" {
		t.Errorf("email voter: %+v", v)
	}
	// OpenID Connect subjects keep their case.
	if v := roll.Voters[1]; v.Provider != "oidc" || v.Subject != "https://idp.example#User-42" {
		t.Errorf("oidc voter: %+v", v)
	}
}

// Defaults that an admin writes out are left out of the manifest, which must
// have one encoding.
func TestPreviewAcceptsDefaultsWrittenOut(t *testing.T) {
	d := Definition{Title: "x", Tally: tally.Manifest{Candidates: []string{"A", "B"}, Method: tally.Schulze, Seats: 1, MaxRanks: 2,
		TieBreak: []tally.TieBreakRule{tally.FirstRanks, tally.DeclareTie}}}
	m, err := d.manifest()
	if err != nil || m.Tally.Seats != 0 || m.Tally.MaxRanks != 0 || m.Tally.TieBreak != nil {
		t.Fatalf("%+v, %v", m.Tally, err)
	}
}
