package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// fakeIssuer is a minimal OpenID Connect identity provider.
type fakeIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	// The login that the next code stands for, as the authorization
	// endpoint would have recorded it.
	challenge, nonce string
	// What the next ID token claims; tests change it.
	audience, subject string
	signWith          *rsa.PrivateKey
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIssuer{key: key, signWith: key, audience: "stimmig", subject: "user-42"}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// PKCE: the verifier must hash to the challenge of the login.
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if r.PostFormValue("code") != "good-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.signWith},
			(&jose.SignerOptions{}).WithHeader("kid", "k1"))
		if err != nil {
			t.Error(err)
		}
		claims, _ := json.Marshal(map[string]any{
			"iss": f.srv.URL, "aud": f.audience, "sub": f.subject, "nonce": f.nonce,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
		})
		jws, err := signer.Sign(claims)
		if err != nil {
			t.Error(err)
		}
		idToken, _ := jws.CompactSerialize()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": idToken})
	})
	return f
}

func TestOIDC(t *testing.T) {
	ctx := context.Background()
	f := newFakeIssuer(t)
	o, err := NewOIDC(ctx, f.srv.URL, "stimmig", "client-secret", "https://registrar.example", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	var _ Provider = o

	// begin starts a login and lets the fake issuer record it, as its
	// authorization endpoint would.
	begin := func(state string) {
		t.Helper()
		raw, err := o.Begin(ctx, "election", state)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(raw)
		q := u.Query()
		if !strings.HasPrefix(raw, f.srv.URL+"/authorize?") || q.Get("state") != state || q.Get("client_id") != "stimmig" ||
			q.Get("redirect_uri") != "https://registrar.example/v1/callback/oidc" || q.Get("code_challenge_method") != "S256" ||
			q.Get("scope") != "openid" || q.Get("nonce") == "" || q.Get("code_challenge") == "" {
			t.Fatalf("login URL: %s", raw)
		}
		f.challenge, f.nonce = q.Get("code_challenge"), q.Get("nonce")
	}
	complete := func(query string) (Subject, error) {
		return o.Complete(ctx, httptest.NewRequest(http.MethodGet, "/v1/callback/oidc?"+query, nil))
	}

	begin("s1")
	sub, err := complete("state=s1&code=good-code")
	if err != nil || sub.Provider != "oidc" || sub.StableID != f.srv.URL+"#user-42" {
		t.Fatalf("subject %+v, %v", sub, err)
	}

	// Each case starts from a good login and breaks one thing.
	cases := map[string]struct {
		change func()
		query  string
	}{
		"wrong code":            {func() {}, "state=s1&code=other"},
		"refused by the issuer": {func() {}, "state=s1&error=access_denied"},
		// The code of login s1 presented with the state of another login:
		// the PKCE verifier does not fit.
		"code of another login": {func() {}, "state=s2&code=good-code"},
		// A token of another login of the same issuer: the nonce differs.
		"nonce of another login":   {func() { f.nonce = "other" }, "state=s1&code=good-code"},
		"token for another client": {func() { f.audience = "other-app" }, "state=s1&code=good-code"},
		"token without subject":    {func() { f.subject = "" }, "state=s1&code=good-code"},
		"token signed by another key": {func() {
			f.signWith, _ = rsa.GenerateKey(rand.Reader, 2048)
		}, "state=s1&code=good-code"},
	}
	for name, c := range cases {
		begin("s1")
		f.audience, f.subject, f.signWith = "stimmig", "user-42", f.key
		c.change()
		if sub, err := complete(c.query); err == nil {
			t.Errorf("%s: accepted as %+v", name, sub)
		}
	}

	// Two logins have different nonces and challenges.
	begin("s1")
	n1, c1 := f.nonce, f.challenge
	begin("s2")
	if n1 == f.nonce || c1 == f.challenge {
		t.Error("two logins share nonce or challenge")
	}
	if _, err := NewOIDC(ctx, f.srv.URL, "stimmig", "x", "https://registrar.example", nil); err == nil {
		t.Error("provider without secret created")
	}
	if _, err := NewOIDC(ctx, f.srv.URL+"/nothing", "stimmig", "x", "https://registrar.example", []byte("s")); err == nil {
		t.Error("discovery of a wrong issuer accepted")
	}
}
