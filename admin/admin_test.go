package admin

import (
	"strings"
	"testing"
)

func TestParseVotersRefusesWhatCannotLogIn(t *testing.T) {
	for _, line := range []string{"Ada <ada@example.org>", "a@example.org, b@example.org", "ada", "ada@"} {
		if _, err := ParseVoters("ok@example.org\n" + line + "\n"); err == nil || !strings.Contains(err.Error(), "line 2") {
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
