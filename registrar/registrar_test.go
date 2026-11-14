package registrar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ansiwen/stimmig/api"
	"github.com/ansiwen/stimmig/credential"
	"github.com/ansiwen/stimmig/election"
	"github.com/ansiwen/stimmig/identity"
	"github.com/ansiwen/stimmig/internal/testdb"
	"github.com/ansiwen/stimmig/internal/testkit"
	"github.com/ansiwen/stimmig/logsvc"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/publog"
)

var ctx = context.Background()

var linkPattern = regexp.MustCompile(`http://\S+`)

type env struct {
	t         *testing.T
	admin     *api.Client // registrar, admin token
	voter     *api.Client // registrar, no token
	log       *api.Client // log service, no token
	mails     *bytes.Buffer
	manifest  publog.Manifest
	id        merkle.Hash
	electPath string
}

// setup starts a log service and a registrar and creates an election.
func setup(t *testing.T) *env {
	t.Helper()
	db := testdb.Open(t)
	store, err := logsvc.NewStore(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	logSrv := httptest.NewServer((&logsvc.Server{Store: store, AdminToken: "la", RegistrarToken: "lr"}).Handler())
	t.Cleanup(logSrv.Close)

	e := &env{t: t, mails: &bytes.Buffer{}, log: &api.Client{Base: logSrv.URL}}
	mux := http.NewServeMux()
	regSrv := httptest.NewServer(mux)
	t.Cleanup(regSrv.Close)
	srv := &Server{DB: db, Log: &api.Client{Base: logSrv.URL, Token: "lr"}, AdminToken: "ra", Secret: []byte("confirm secret")}
	srv.Providers = map[string]identity.Provider{"email": &identity.Email{
		BaseURL: regSrv.URL,
		Secret:  []byte("secret"),
		Mailer:  identity.LogMailer{W: e.mails},
		Allow: func(ctx context.Context, state, address string) bool {
			return srv.Eligible(ctx, state, "email", address)
		},
	}}
	if err := srv.Init(ctx); err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", srv.Handler())
	e.admin = &api.Client{Base: regSrv.URL, Token: "ra"}
	e.voter = &api.Client{Base: regSrv.URL}

	// Keys from both services, then the manifest.
	var logKey api.LogKey
	if err := (&api.Client{Base: logSrv.URL, Token: "la"}).Do(ctx, "POST", "/v1/keys", nil, &logKey); err != nil {
		t.Fatal(err)
	}
	var keys api.RegistrarKeys
	if err := e.voter.Do(ctx, "POST", "/v1/keys", nil, &keys); !api.IsStatus(err, http.StatusUnauthorized) {
		t.Fatalf("keys without admin token: %v", err)
	}
	if err := e.admin.Do(ctx, "POST", "/v1/keys", nil, &keys); err != nil {
		t.Fatal(err)
	}
	e.manifest = testkit.Manifest(logKey.LogKey, testkit.SharedKeys())
	e.manifest.IssuingKey, e.manifest.ElectionKey = keys.IssuingKey, keys.ElectionKey
	if err := (&api.Client{Base: logSrv.URL, Token: "la"}).Do(ctx, "POST", "/v1/elections", e.manifest, nil); err != nil {
		t.Fatal(err)
	}
	var created api.Created
	if err := e.admin.Do(ctx, "POST", "/v1/elections", e.manifest, &created); err != nil {
		t.Fatal(err)
	}
	e.id = merkle.Hash(created.ElectionID)
	e.electPath = api.ElectionPath(e.id)
	return e
}

// begin creates a credential request and a registration session.
func (e *env) begin() (*credential.Request, ed25519.PublicKey, api.Session, error) {
	e.t.Helper()
	issuingKey, err := credential.ParseIssuingKey(e.manifest.IssuingKey)
	if err != nil {
		e.t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	req, err := credential.NewRequest(rand.Reader, issuingKey, e.id, pub)
	if err != nil {
		e.t.Fatal(err)
	}
	var session api.Session
	err = e.voter.Do(ctx, "POST", e.electPath+"/sessions", api.SessionRequest{Blinded: req.Blinded}, &session)
	return req, pub, session, err
}

// login submits the address form and returns the mailed link, or "".
func (e *env) login(session api.Session, address string) string {
	e.t.Helper()
	e.mails.Reset()
	u, _ := url.Parse(session.URL)
	resp, err := http.PostForm(session.URL, url.Values{"state": {u.Query().Get("state")}, "address": {address}})
	if err != nil {
		e.t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("address form: %s", resp.Status)
	}
	return linkPattern.FindString(e.mails.String())
}

// open opens a login link and types a confirmation code.
func open(t *testing.T, link, code string) int {
	t.Helper()
	status, err := testkit.Login(link, code)
	if err != nil {
		t.Fatal(err)
	}
	return status
}

func (e *env) report() *election.Report {
	e.t.Helper()
	data, err := api.Export(ctx, e.log, e.id)
	if err != nil {
		e.t.Fatal(err)
	}
	rep, err := election.Verify(bytes.NewReader(data), nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return rep
}

func TestRegistration(t *testing.T) {
	e := setup(t)

	// The keys of a manifest serve one election.
	other := e.manifest
	other.Title = "Second election"
	if err := e.admin.Do(ctx, "POST", "/v1/elections", other, nil); !api.IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("keys used twice: %v", err)
	}
	// No registration before the roll.
	if _, _, _, err := e.begin(); !api.IsStatus(err, http.StatusConflict) {
		t.Fatalf("session before the roll: %v", err)
	}
	roll := api.Roll{Voters: []api.Voter{
		{Provider: "email", Subject: "ada@example.org"},
		{Provider: "email", Subject: "bob@example.org"},
		{Provider: "email", Subject: "ada@example.org"}, // listed twice
	}}
	if err := e.voter.Do(ctx, "PUT", e.electPath+"/roll", roll, nil); !api.IsStatus(err, http.StatusUnauthorized) {
		t.Fatalf("roll without admin token: %v", err)
	}
	bad := api.Roll{Voters: []api.Voter{{Provider: "passport", Subject: "x"}}}
	if err := e.admin.Do(ctx, "PUT", e.electPath+"/roll", bad, nil); !api.IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("roll with unknown provider: %v", err)
	}
	if err := e.admin.Do(ctx, "PUT", e.electPath+"/roll", roll, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Do(ctx, "PUT", e.electPath+"/roll", roll, nil); !api.IsStatus(err, http.StatusConflict) {
		t.Fatalf("second roll: %v", err)
	}
	if rep := e.report(); rep.Eligible != 2 || rep.Phase != election.PhaseRegistration {
		t.Fatalf("after the roll: %+v", rep)
	}

	// Ada registers.
	req, pub, session, err := e.begin()
	if err != nil {
		t.Fatal(err)
	}
	var cred api.Credential
	sessionPath := "/v1/sessions/" + session.Session
	if err := e.voter.Do(ctx, "GET", sessionPath, nil, &cred); !api.IsStatus(err, http.StatusNotFound) {
		t.Fatalf("credential before the login: %v", err)
	}
	if link := e.login(session, "eve@example.org"); link != "" {
		t.Fatal("mail to an address that is not on the roll")
	}
	link := e.login(session, "Ada@example.org")
	if link == "" {
		t.Fatalf("no mail: %s", e.mails.String())
	}
	if code := open(t, link+"0", session.Code); code != http.StatusForbidden {
		t.Fatalf("forged link: %d", code)
	}
	// The login alone issues nothing: the voter must type the code of
	// their own client. A wrong code is refused.
	if code := open(t, link, "0000 0000"); code != http.StatusForbidden {
		t.Fatalf("wrong confirmation code: %d", code)
	}
	if err := e.voter.Do(ctx, "GET", sessionPath, nil, &cred); !api.IsStatus(err, http.StatusNotFound) {
		t.Fatalf("credential after a wrong code: %v", err)
	}
	if code := open(t, link, session.Code); code != http.StatusOK {
		t.Fatalf("login link: %d", code)
	}
	if err := e.voter.Do(ctx, "GET", sessionPath, nil, &cred); err != nil {
		t.Fatal(err)
	}
	sig, err := req.Finalize(cred.BlindSignature)
	if err != nil {
		t.Fatal(err)
	}
	issuingKey, _ := credential.ParseIssuingKey(e.manifest.IssuingKey)
	if err := credential.Verify(issuingKey, e.id, pub, sig); err != nil {
		t.Fatal(err)
	}

	// Opening the link again changes nothing.
	if code := open(t, link, session.Code); code != http.StatusOK {
		t.Fatalf("login link again: %d", code)
	}
	// A second credential for Ada is refused, and nothing is logged.
	_, _, second, err := e.begin()
	if err != nil {
		t.Fatal(err)
	}
	if code := open(t, e.login(second, "ada@example.org"), second.Code); code != http.StatusConflict {
		t.Fatalf("second credential: %d", code)
	}
	if err := e.voter.Do(ctx, "GET", "/v1/sessions/"+second.Session, nil, &cred); !api.IsStatus(err, http.StatusNotFound) {
		t.Fatalf("credential of the refused session: %v", err)
	}
	rep := e.report()
	if rep.Issued != 1 || rep.Log.Entries != 3 {
		t.Fatalf("after the issuance: issued %d, %d entries", rep.Issued, rep.Log.Entries)
	}
	if !bytes.Equal(rep.Log.Final.ElectionID, e.id[:]) {
		t.Fatal("wrong election")
	}

	// Malformed requests.
	short := api.SessionRequest{Blinded: []byte{1, 2, 3}}
	if err := e.voter.Do(ctx, "POST", e.electPath+"/sessions", short, nil); !api.IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("short blinded value: %v", err)
	}
	unknown := api.ElectionPath(merkle.Hash{1})
	if err := e.voter.Do(ctx, "POST", unknown+"/sessions", short, nil); !api.IsStatus(err, http.StatusNotFound) {
		t.Fatalf("unknown election: %v", err)
	}
	if code := open(t, strings.Replace(link, "/callback/email", "/callback/passport", 1), session.Code); code != http.StatusNotFound {
		t.Fatalf("unknown provider: %d", code)
	}

	// The tally needs a closed voting.
	if err := e.admin.Do(ctx, "POST", e.electPath+"/tally", nil, nil); !api.IsStatus(err, http.StatusConflict) {
		t.Fatalf("early tally: %v", err)
	}
	// Close: Bob's open session can no longer be used.
	_, _, bob, err := e.begin()
	if err != nil {
		t.Fatal(err)
	}
	bobLink := e.login(bob, "bob@example.org")
	if err := e.voter.Do(ctx, "POST", e.electPath+"/close", nil, nil); !api.IsStatus(err, http.StatusUnauthorized) {
		t.Fatalf("close without admin token: %v", err)
	}
	if err := e.admin.Do(ctx, "POST", e.electPath+"/close", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Do(ctx, "POST", e.electPath+"/close", nil, nil); !api.IsStatus(err, http.StatusConflict) {
		t.Fatalf("second close: %v", err)
	}
	if code := open(t, bobLink, bob.Code); code != http.StatusConflict {
		t.Fatalf("login after the close: %d", code)
	}
	if _, _, _, err := e.begin(); !api.IsStatus(err, http.StatusConflict) {
		t.Fatalf("session after the close: %v", err)
	}
	if rep := e.report(); rep.Phase != election.PhaseRegistrationClosed || rep.Issued != 1 || rep.Eligible != 2 {
		t.Fatalf("after the close: %+v", rep)
	}
}

// Somebody who starts a registration and gets a voter to log in receives
// nothing without the code, and cannot guess it.
func TestConfirmationCode(t *testing.T) {
	e := setup(t)
	roll := api.Roll{Voters: []api.Voter{{Provider: "email", Subject: "ada@example.org"}}}
	if err := e.admin.Do(ctx, "PUT", e.electPath+"/roll", roll, nil); err != nil {
		t.Fatal(err)
	}
	_, _, session, err := e.begin()
	if err != nil {
		t.Fatal(err)
	}
	if len(session.Code) != 9 {
		t.Fatalf("code %q", session.Code)
	}
	link := e.login(session, "ada@example.org")
	for i := 0; i < MaxConfirmAttempts; i++ {
		if code := open(t, link, "1111 1111"); code != http.StatusForbidden {
			t.Fatalf("wrong code %d: %d", i, code)
		}
	}
	// After too many wrong codes even the right one is refused.
	if code := open(t, link, session.Code); code != http.StatusForbidden {
		t.Fatalf("right code after too many wrong ones: %d", code)
	}
	if rep := e.report(); rep.Issued != 0 {
		t.Fatalf("issued %d", rep.Issued)
	}
	// A forged confirmation is refused.
	resp, err := http.PostForm(e.voter.Base+"/v1/confirm", url.Values{"token": {"00.00"}, "code": {session.Code}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forged confirmation: %d", resp.StatusCode)
	}
	// The voter starts again and succeeds.
	_, _, again, err := e.begin()
	if err != nil {
		t.Fatal(err)
	}
	if code := open(t, e.login(again, "ada@example.org"), strings.ReplaceAll(again.Code, " ", "")); code != http.StatusOK {
		t.Fatalf("new session: %d", code)
	}
}
