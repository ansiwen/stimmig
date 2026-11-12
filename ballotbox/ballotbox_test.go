package ballotbox

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/ansiwen/stimmig/api"
	"github.com/ansiwen/stimmig/ballot"
	"github.com/ansiwen/stimmig/credential"
	"github.com/ansiwen/stimmig/election"
	"github.com/ansiwen/stimmig/internal/testdb"
	"github.com/ansiwen/stimmig/internal/testkit"
	"github.com/ansiwen/stimmig/logsvc"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/publog"
	"github.com/ansiwen/stimmig/tally"
)

var ctx = context.Background()

// credentialFor issues a credential with the test issuing key.
func credentialFor(t *testing.T, id merkle.Hash) (ed25519.PrivateKey, []byte) {
	t.Helper()
	k := testkit.SharedKeys()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	req, err := credential.NewRequest(rand.Reader, &k.Issuing.PublicKey, id, pub)
	if err != nil {
		t.Fatal(err)
	}
	blindSig, err := credential.Issue(k.Issuing, req.Blinded)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := req.Finalize(blindSig)
	if err != nil {
		t.Fatal(err)
	}
	return priv, sig
}

func TestBallotBox(t *testing.T) {
	db := testdb.Open(t)
	store, err := logsvc.NewStore(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	logSrv := httptest.NewServer((&logsvc.Server{Store: store, AdminToken: "la", RegistrarToken: "lr", BallotBoxToken: "lb"}).Handler())
	defer logSrv.Close()
	srv := &Server{DB: db, Log: &api.Client{Base: logSrv.URL, Token: "lb"}, AdminToken: "ba"}
	if err := srv.Init(ctx); err != nil {
		t.Fatal(err)
	}
	boxSrv := httptest.NewServer(srv.Handler())
	defer boxSrv.Close()
	admin, voter := &api.Client{Base: boxSrv.URL, Token: "ba"}, &api.Client{Base: boxSrv.URL}
	logAdmin, registrar := &api.Client{Base: logSrv.URL, Token: "la"}, &api.Client{Base: logSrv.URL, Token: "lr"}
	k := testkit.SharedKeys()

	// Create the election in the log and in the ballot box.
	var logKey api.LogKey
	if err := logAdmin.Do(ctx, "POST", "/v1/keys", nil, &logKey); err != nil {
		t.Fatal(err)
	}
	var boxKey api.BallotBoxKey
	if err := voter.Do(ctx, "POST", "/v1/keys", nil, &boxKey); !api.IsStatus(err, http.StatusUnauthorized) {
		t.Fatalf("key without admin token: %v", err)
	}
	if err := admin.Do(ctx, "POST", "/v1/keys", nil, &boxKey); err != nil {
		t.Fatal(err)
	}
	m := testkit.Manifest(logKey.LogKey, k)
	if err := admin.Do(ctx, "POST", "/v1/elections", m, nil); !api.IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("foreign receipt key: %v", err)
	}
	m.ReceiptKey = boxKey.ReceiptKey
	if err := logAdmin.Do(ctx, "POST", "/v1/elections", m, nil); err != nil {
		t.Fatal(err)
	}
	var created api.Created
	if err := admin.Do(ctx, "POST", "/v1/elections", m, &created); err != nil {
		t.Fatal(err)
	}
	if err := admin.Do(ctx, "POST", "/v1/elections", m, nil); err == nil {
		t.Fatal("election created twice")
	}
	id := merkle.Hash(created.ElectionID)
	path := api.ElectionPath(id)

	// The registrar's part of the log: a roll of two, two credentials.
	ref := func(i byte) []byte { h := sha256.Sum256([]byte{i}); return h[:] }
	roll, err := election.RollRecord([][]byte{ref(0), ref(1)})
	if err != nil {
		t.Fatal(err)
	}
	registration := []publog.Record{
		roll,
		{Type: publog.TypeIssuance, Body: election.Issuance{RollReference: ref(0), Sequence: 0}},
		{Type: publog.TypeIssuance, Body: election.Issuance{RollReference: ref(1), Sequence: 1}},
	}
	if _, err := api.AppendRecords(ctx, registrar, id, 1, registration); err != nil {
		t.Fatal(err)
	}
	key0, sig0 := credentialFor(t, id)
	key1, sig1 := credentialFor(t, id)
	cast := func(key ed25519.PrivateKey, sig []byte, ranking tally.Ballot) (election.Ballot, error) {
		b, err := election.Cast(rand.Reader, m, id, key, sig, ranking)
		if err != nil {
			t.Fatal(err)
		}
		return b, voter.Do(ctx, "POST", path+"/ballots", b, nil)
	}

	// Voting opens only after registration is closed in the log.
	if err := admin.Do(ctx, "POST", path+"/open", nil, nil); !api.IsStatus(err, http.StatusConflict) {
		t.Fatalf("open during registration: %v", err)
	}
	if _, err := cast(key0, sig0, tally.Ballot{{"A"}}); !api.IsStatus(err, http.StatusConflict) {
		t.Fatalf("ballot before the opening: %v", err)
	}
	closeReg := []publog.Record{{Type: publog.TypeRegistrationClose, Body: election.RegistrationClose{Issued: 2}}}
	if _, err := api.AppendRecords(ctx, registrar, id, 4, closeReg); err != nil {
		t.Fatal(err)
	}
	if err := voter.Do(ctx, "POST", path+"/open", nil, nil); !api.IsStatus(err, http.StatusUnauthorized) {
		t.Fatalf("open without admin token: %v", err)
	}
	if err := admin.Do(ctx, "POST", path+"/open", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := admin.Do(ctx, "POST", path+"/open", nil, nil); !api.IsStatus(err, http.StatusConflict) {
		t.Fatalf("second open: %v", err)
	}

	// A ballot is accepted once and answered with a valid receipt.
	b0, err := cast(key0, sig0, tally.Ballot{{"A"}, {"B"}})
	if err != nil {
		t.Fatal(err)
	}
	var receipt, again api.Receipt
	if err := voter.Do(ctx, "POST", path+"/ballots", b0, &receipt); err != nil {
		t.Fatalf("the same ballot again: %v", err)
	}
	leaf, _ := election.BallotLeaf(b0)
	if err := ballot.VerifyReceipt(m.ReceiptKey, id, leaf, receipt.Receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := cast(key0, sig0, tally.Ballot{{"C"}}); !api.IsStatus(err, http.StatusConflict) {
		t.Fatalf("second ballot of a credential: %v", err)
	}
	// Ballots without a credential of the registrar are refused.
	_, forged, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := cast(forged, sig0, tally.Ballot{{"A"}}); !api.IsStatus(err, http.StatusForbidden) {
		t.Fatalf("forged credential: %v", err)
	}
	tampered := b0
	tampered.Ciphertext = append([]byte{0}, b0.Ciphertext...)
	if err := voter.Do(ctx, "POST", path+"/ballots", tampered, &again); !api.IsStatus(err, http.StatusForbidden) {
		t.Fatalf("changed ciphertext: %v", err)
	}
	if err := voter.Do(ctx, "POST", api.ElectionPath(merkle.Hash{1})+"/ballots", b0, nil); !api.IsStatus(err, http.StatusNotFound) {
		t.Fatalf("unknown election: %v", err)
	}
	var st api.Status
	if err := voter.Do(ctx, "GET", path, nil, &st); err != nil || st.Phase != PhaseOpen || st.Cast != 1 {
		t.Fatalf("status %+v, %v", st, err)
	}
	// The ballots are not in the public log during the voting.
	export, _ := api.Export(ctx, registrar, id)
	if rep, err := election.Verify(bytes.NewReader(export), nil); err != nil || rep.Cast != 0 {
		t.Fatalf("log during the voting: %+v, %v", rep, err)
	}

	// Close: the ballots are published, later ballots are refused.
	if err := voter.Do(ctx, "POST", path+"/close", nil, nil); !api.IsStatus(err, http.StatusUnauthorized) {
		t.Fatalf("close without admin token: %v", err)
	}
	if err := admin.Do(ctx, "POST", path+"/close", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := cast(key1, sig1, tally.Ballot{{"B"}}); !api.IsStatus(err, http.StatusConflict) {
		t.Fatalf("ballot after the close: %v", err)
	}
	if err := admin.Do(ctx, "POST", path+"/close", nil, nil); !api.IsStatus(err, http.StatusConflict) {
		t.Fatalf("second close: %v", err)
	}
	if err := voter.Do(ctx, "GET", path, nil, &st); err != nil || st.Phase != PhasePublished || st.Cast != 1 {
		t.Fatalf("status %+v, %v", st, err)
	}
	export, _ = api.Export(ctx, registrar, id)
	rep, err := election.Verify(bytes.NewReader(export), nil)
	if err != nil || rep.Phase != election.PhaseVotingClosed || rep.Cast != 1 {
		t.Fatalf("log after the close: %+v, %v", rep, err)
	}

	// The tally completes the election.
	records, _, err := election.TallyRecords(m, id, k.ElectionPrivate, rep.Ballots, rep.BallotIndexes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.AppendRecords(ctx, registrar, id, rep.Log.Entries, records); err != nil {
		t.Fatal(err)
	}
	export, _ = api.Export(ctx, registrar, id)
	rep, err = election.Verify(bytes.NewReader(export), nil)
	if err != nil || rep.Phase != election.PhaseComplete || !reflect.DeepEqual(rep.Result.Winners, []string{"A"}) {
		t.Fatalf("final log: %+v, %v", rep, err)
	}
}

// A close that failed after the ballots were published can be repeated.
func TestCloseAfterPublish(t *testing.T) {
	db := testdb.Open(t)
	store, err := logsvc.NewStore(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	logSrv := httptest.NewServer((&logsvc.Server{Store: store, AdminToken: "la", RegistrarToken: "lr", BallotBoxToken: "lb"}).Handler())
	defer logSrv.Close()
	srv := &Server{DB: db, Log: &api.Client{Base: logSrv.URL, Token: "lb"}, AdminToken: "ba"}
	if err := srv.Init(ctx); err != nil {
		t.Fatal(err)
	}
	boxSrv := httptest.NewServer(srv.Handler())
	defer boxSrv.Close()
	admin := &api.Client{Base: boxSrv.URL, Token: "ba"}
	logAdmin, registrar := &api.Client{Base: logSrv.URL, Token: "la"}, &api.Client{Base: logSrv.URL, Token: "lr"}

	var logKey api.LogKey
	var boxKey api.BallotBoxKey
	if err := logAdmin.Do(ctx, "POST", "/v1/keys", nil, &logKey); err != nil {
		t.Fatal(err)
	}
	if err := admin.Do(ctx, "POST", "/v1/keys", nil, &boxKey); err != nil {
		t.Fatal(err)
	}
	m := testkit.Manifest(logKey.LogKey, testkit.SharedKeys())
	m.ReceiptKey = boxKey.ReceiptKey
	var created api.Created
	if err := logAdmin.Do(ctx, "POST", "/v1/elections", m, nil); err != nil {
		t.Fatal(err)
	}
	if err := admin.Do(ctx, "POST", "/v1/elections", m, &created); err != nil {
		t.Fatal(err)
	}
	id := merkle.Hash(created.ElectionID)
	roll, _ := election.RollRecord(nil)
	records := []publog.Record{roll, {Type: publog.TypeRegistrationClose, Body: election.RegistrationClose{}}}
	if _, err := api.AppendRecords(ctx, registrar, id, 1, records); err != nil {
		t.Fatal(err)
	}
	path := api.ElectionPath(id)
	if err := admin.Do(ctx, "POST", path+"/open", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := admin.Do(ctx, "POST", path+"/close", nil, nil); err != nil {
		t.Fatal(err)
	}
	// Simulate the failure: the log has the ballots, the phase was not
	// stored.
	if _, err := db.ExecContext(ctx, `UPDATE box_elections SET phase = $1`, PhaseClosed); err != nil {
		t.Fatal(err)
	}
	if err := admin.Do(ctx, "POST", path+"/close", nil, nil); err != nil {
		t.Fatal(err)
	}
	export, _ := api.Export(ctx, registrar, id)
	rep, err := election.Verify(bytes.NewReader(export), nil)
	if err != nil || rep.Phase != election.PhaseVotingClosed || rep.Log.Entries != 4 {
		t.Fatalf("log: %+v, %v", rep, err)
	}
}
