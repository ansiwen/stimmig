package logsvc

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ansiwen/stimmig/api"
	"github.com/ansiwen/stimmig/canon"
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
	roll := api.Append{Entries: []canon.Raw{entry(t, publog.TypeRollCommit, map[string]int{})}, ExpectSize: &one}

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
	ballot := api.Append{Entries: []canon.Raw{entry(t, publog.TypeBallot, map[string]int{})}}
	if err := registrar.Do(ctx, "POST", path+"/entries", ballot, nil); !api.IsStatus(err, http.StatusForbidden) {
		t.Fatalf("ballot from the registrar: %v", err)
	}
	manifest := api.Append{Entries: []canon.Raw{entry(t, publog.TypeManifest, m)}}
	if err := registrar.Do(ctx, "POST", path+"/entries", manifest, nil); err == nil {
		t.Fatal("second manifest appended")
	}
	garbage := api.Append{Entries: []canon.Raw{{0x01}}}
	if err := registrar.Do(ctx, "POST", path+"/entries", garbage, nil); !api.IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("garbage entry: %v", err)
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

	// Concurrent appends from several writers all land, in some order.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := api.Append{Entries: []canon.Raw{entry(t, publog.TypeIssuance, map[string]int{"sequence": i})}}
			if err := registrar.Do(ctx, "POST", path+"/entries", req, nil); err != nil {
				t.Error(err)
			}
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
}
