package logsvc

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ansiwen/stimmig/api"
	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/election"
	"github.com/ansiwen/stimmig/internal/testdb"
	"github.com/ansiwen/stimmig/internal/testkit"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/publog"
)

var ctx = context.Background()

func entry(t *testing.T, typ string, body any) canon.Raw {
	t.Helper()
	data, err := publog.EncodeEntry(typ, body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDatabaseErrorsAreNotShown(t *testing.T) {
	w := httptest.NewRecorder()
	fail(w, fmt.Errorf("query: %w", &pgconn.PgError{Message: "password for user stimmig failed"}))
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "stimmig") {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	fail(w, publog.ErrNotFound)
	if w.Code != http.StatusNotFound {
		t.Fatalf("%d", w.Code)
	}
}

func TestLogService(t *testing.T) {
	store, err := NewStore(ctx, testdb.Open(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(ctx, store.db); err != nil { // the schema applies twice
		t.Fatal(err)
	}
	srv := httptest.NewServer((&Server{Store: store, AdminToken: "a", RegistrarToken: "r", BallotBoxToken: "b"}).Handler())
	defer srv.Close()
	client := func(token string) *api.Client { return &api.Client{Base: srv.URL, Token: token} }
	admin, registrar, box, public := client("a"), client("r"), client("b"), client("")

	// Keys and elections need the admin token.
	var key api.LogKey
	for _, c := range []*api.Client{public, registrar, client("wrong")} {
		if err := c.Do(ctx, "POST", "/v1/keys", nil, &key); !api.IsStatus(err, http.StatusUnauthorized) {
			t.Fatalf("key without admin token: %v", err)
		}
	}
	if err := admin.Do(ctx, "POST", "/v1/keys", nil, &key); err != nil {
		t.Fatal(err)
	}
	m := testkit.Manifest(key.LogKey, testkit.SharedKeys())
	var head publog.TreeHead
	if err := registrar.Do(ctx, "POST", "/v1/elections", m, &head); !api.IsStatus(err, http.StatusUnauthorized) {
		t.Fatalf("election without admin token: %v", err)
	}
	if err := admin.Do(ctx, "POST", "/v1/elections", m, &head); err != nil {
		t.Fatal(err)
	}
	if head.Size != 1 || head.Verify(key.LogKey) != nil {
		t.Fatalf("first head: %+v", head)
	}
	// A log key serves one election, and a manifest needs a key of this
	// service.
	other := m
	other.Title = "Second election"
	if err := admin.Do(ctx, "POST", "/v1/elections", other, nil); err == nil {
		t.Fatal("log key used twice")
	}
	other.LogKey = bytes.Repeat([]byte{9}, 32)
	if err := admin.Do(ctx, "POST", "/v1/elections", other, nil); err == nil {
		t.Fatal("foreign log key accepted")
	}
	other.Version = 99
	if err := admin.Do(ctx, "POST", "/v1/elections", other, nil); !api.IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("invalid manifest: %v", err)
	}

	path := "/v1/elections/" + hex.EncodeToString(head.ElectionID)
	one := uint64(1)
	// A roll of 20 voters, in ascending order.
	refs := make([][]byte, 20)
	for i := range refs {
		refs[i] = bytes.Repeat([]byte{byte(i + 1)}, 32)
	}
	rollRecord, err := election.RollRecord(refs)
	if err != nil {
		t.Fatal(err)
	}
	roll := api.Append{Entries: []canon.Raw{entry(t, rollRecord.Type, rollRecord.Body)}, ExpectSize: &one}

	// Writers are limited to their entry types.
	if err := public.Do(ctx, "POST", path+"/entries", roll, nil); !api.IsStatus(err, http.StatusUnauthorized) {
		t.Fatalf("append without token: %v", err)
	}
	if err := admin.Do(ctx, "POST", path+"/entries", roll, nil); !api.IsStatus(err, http.StatusUnauthorized) {
		t.Fatalf("append with admin token: %v", err)
	}
	if err := box.Do(ctx, "POST", path+"/entries", roll, nil); !api.IsStatus(err, http.StatusForbidden) {
		t.Fatalf("roll from the ballot box: %v", err)
	}
	ballot := api.Append{Entries: []canon.Raw{entry(t, publog.TypeBallot, map[string]int{})}, ExpectSize: &one}
	if err := registrar.Do(ctx, "POST", path+"/entries", ballot, nil); !api.IsStatus(err, http.StatusForbidden) {
		t.Fatalf("ballot from the registrar: %v", err)
	}
	manifest := api.Append{Entries: []canon.Raw{entry(t, publog.TypeManifest, m)}, ExpectSize: &one}
	if err := registrar.Do(ctx, "POST", path+"/entries", manifest, nil); err == nil {
		t.Fatal("second manifest appended")
	}
	garbage := api.Append{Entries: []canon.Raw{{0x01}}, ExpectSize: &one}
	if err := registrar.Do(ctx, "POST", path+"/entries", garbage, nil); !api.IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("garbage entry: %v", err)
	}

	// The lifecycle order: after the manifest comes the roll, nothing else.
	for _, typ := range []string{publog.TypeIssuance, publog.TypeResult, publog.TypeRegistrationClose} {
		out := api.Append{Entries: []canon.Raw{entry(t, typ, map[string]int{})}, ExpectSize: &one}
		if err := registrar.Do(ctx, "POST", path+"/entries", out, nil); !api.IsStatus(err, http.StatusConflict) {
			t.Fatalf("%s after the manifest: %v", typ, err)
		}
	}
	// An append with the expected size works once.
	if err := registrar.Do(ctx, "POST", path+"/entries", roll, &head); err != nil || head.Size != 2 {
		t.Fatalf("append: %+v, %v", head, err)
	}
	if err := registrar.Do(ctx, "POST", path+"/entries", roll, nil); !api.IsStatus(err, http.StatusConflict) {
		t.Fatalf("repeated append: %v", err)
	}
	unknown := "/v1/elections/" + hex.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if err := registrar.Do(ctx, "POST", unknown+"/entries", roll, nil); !api.IsStatus(err, http.StatusNotFound) {
		t.Fatalf("unknown election: %v", err)
	}
	if err := public.Do(ctx, "GET", "/v1/elections/xyz/head", nil, nil); !api.IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("malformed election ID: %v", err)
	}

	// An append that does not say which size it expects is refused.
	issuance := func(ref []byte, sequence uint64) canon.Raw {
		return entry(t, publog.TypeIssuance, election.Issuance{RollReference: ref, Sequence: sequence})
	}
	two := uint64(2)
	if err := registrar.Do(ctx, "POST", path+"/entries", api.Append{Entries: []canon.Raw{issuance(refs[0], 0)}}, nil); !api.IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("append without expect_size: %v", err)
	}
	// An entry must be valid in this log, so that a leaked writer token cannot
	// make the log fail verification: a voter who is not on the roll, a wrong
	// sequence number, an entry that is not an issuance in disguise.
	for name, bad := range map[string]canon.Raw{
		"unknown voter":   issuance(bytes.Repeat([]byte{99}, 32), 0),
		"wrong sequence":  issuance(refs[0], 5),
		"empty issuance":  entry(t, publog.TypeIssuance, map[string]int{}),
		"short reference": issuance([]byte{1}, 0),
	} {
		if err := registrar.Do(ctx, "POST", path+"/entries", api.Append{Entries: []canon.Raw{bad}, ExpectSize: &two}, nil); !api.IsStatus(err, http.StatusUnprocessableEntity) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// An append without entries is refused and signs nothing.
	if err := registrar.Do(ctx, "POST", path+"/entries", api.Append{Entries: []canon.Raw{}, ExpectSize: &two}, nil); !api.IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("append without entries: %v", err)
	}
	// A batch is checked as a whole: the second entry reuses the voter.
	if err := registrar.Do(ctx, "POST", path+"/entries", api.Append{Entries: []canon.Raw{issuance(refs[0], 0), issuance(refs[0], 1)}, ExpectSize: &two}, nil); !api.IsStatus(err, http.StatusUnprocessableEntity) {
		t.Fatalf("second credential for a voter: %v", err)
	}
	if err := public.Do(ctx, "GET", path+"/head", nil, &head); err != nil || head.Size != 2 {
		t.Fatalf("refused entries changed the log: %+v, %v", head, err)
	}
	// Concurrent writers that retry on a conflict all land, in some order.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for attempt := 0; attempt < 200; attempt++ {
				var h publog.TreeHead
				if err := public.Do(ctx, "GET", path+"/head", nil, &h); err != nil {
					t.Error(err)
					return
				}
				// The log has the manifest and the roll, then one entry per credential.
				req := api.Append{Entries: []canon.Raw{issuance(refs[i], h.Size-2)}, ExpectSize: &h.Size}
				err := registrar.Do(ctx, "POST", path+"/entries", req, nil)
				if err == nil {
					return
				}
				if !api.IsStatus(err, http.StatusConflict) {
					t.Error(err)
					return
				}
			}
			t.Error("append did not succeed in 200 attempts")
		}()
	}
	wg.Wait()
	if err := public.Do(ctx, "GET", path+"/head", nil, &head); err != nil || head.Size != 22 {
		t.Fatalf("head: %+v, %v", head, err)
	}

	// The export verifies, and its final head is the served head.
	data, err := public.Raw(ctx, "GET", path+"/export", nil)
	if err != nil {
		t.Fatal(err)
	}
	var leaves []merkle.Hash
	rep, err := publog.Verify(bytes.NewReader(data), func(_ *publog.Report, _ uint64, typ string, body []byte) error {
		e, err := publog.EncodeEntry(typ, canon.Raw(body))
		leaves = append(leaves, merkle.LeafHash(e))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Entries != 22 || rep.TreeHeads != 22 || !bytes.Equal(rep.Final.Signature, head.Signature) {
		t.Fatalf("export: %d entries, %d heads", rep.Entries, rep.TreeHeads)
	}

	// Proofs.
	root := merkle.Hash(head.Root)
	for i, leaf := range leaves {
		var proof api.Proof
		q := fmt.Sprintf("%s/inclusion?leaf=%x&size=22", path, leaf[:])
		if err := public.Do(ctx, "GET", q, nil, &proof); err != nil {
			t.Fatal(err)
		}
		hs := make([]merkle.Hash, len(proof.Hashes))
		for j, h := range proof.Hashes {
			hs[j] = merkle.Hash(h)
		}
		if proof.Index != uint64(i) || merkle.VerifyInclusion(leaf, proof.Index, 22, hs, root) != nil {
			t.Fatalf("inclusion proof of entry %d", i)
		}
	}
	missing := fmt.Sprintf("%s/inclusion?leaf=%x&size=22", path, bytes.Repeat([]byte{1}, 32))
	if err := public.Do(ctx, "GET", missing, nil, nil); !api.IsStatus(err, http.StatusNotFound) {
		t.Fatalf("proof for a missing leaf: %v", err)
	}
	if err := public.Do(ctx, "GET", path+"/inclusion?leaf=00&size=22", nil, nil); !api.IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("malformed leaf: %v", err)
	}
	if err := public.Do(ctx, "GET", fmt.Sprintf("%s/inclusion?leaf=%x&size=99", path, leaves[0][:]), nil, nil); err == nil {
		t.Fatal("proof beyond the log")
	}
	var proof api.Proof
	if err := public.Do(ctx, "GET", path+"/consistency?old=2&new=22", nil, &proof); err != nil {
		t.Fatal(err)
	}
	hs := make([]merkle.Hash, len(proof.Hashes))
	for j, h := range proof.Hashes {
		hs[j] = merkle.Hash(h)
	}
	if err := merkle.VerifyConsistency(2, 22, merkle.Root(leaves[:2]), root, hs); err != nil {
		t.Fatal(err)
	}
	if err := public.Do(ctx, "GET", path+"/consistency?old=x&new=22", nil, nil); !api.IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("malformed sizes: %v", err)
	}

	// Another replica, with its own memory of the log, appends. This one
	// catches up from the store and still refuses what does not fit.
	other2 := httptest.NewServer((&Server{Store: store, AdminToken: "a", RegistrarToken: "r", BallotBoxToken: "b"}).Handler())
	defer other2.Close()
	registrar2 := &api.Client{Base: other2.URL, Token: "r"}
	size := uint64(22)
	closeAt := func(c *api.Client, issued uint64) error {
		return c.Do(ctx, "POST", path+"/entries", api.Append{Entries: []canon.Raw{entry(t, publog.TypeRegistrationClose, election.RegistrationClose{Issued: issued})}, ExpectSize: &size}, nil)
	}
	if err := closeAt(registrar2, 19); !api.IsStatus(err, http.StatusUnprocessableEntity) {
		t.Fatalf("wrong issued count at the second replica: %v", err)
	}
	if err := closeAt(registrar2, 20); err != nil {
		t.Fatal(err)
	}
	size = 23
	votingClose := func(cast uint64) error {
		return box.Do(ctx, "POST", path+"/entries", api.Append{Entries: []canon.Raw{entry(t, publog.TypeVotingClose, election.VotingClose{Cast: cast})}, ExpectSize: &size}, nil)
	}
	if err := votingClose(1); !api.IsStatus(err, http.StatusUnprocessableEntity) {
		t.Fatalf("wrong cast count: %v", err)
	}
	if err := votingClose(0); err != nil {
		t.Fatal(err)
	}
}

// Several replicas that start at once create the tables without failing.
func TestConcurrentStart(t *testing.T) {
	db := testdb.Open(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := NewStore(ctx, db); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
