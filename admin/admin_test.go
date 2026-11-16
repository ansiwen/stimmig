package admin

import "testing"

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
