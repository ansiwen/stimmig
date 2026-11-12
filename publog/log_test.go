package publog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/ansiwen/stimmig/merkle"
)

var ctx = context.Background()

// testClock advances one minute on every call.
func testClock() func() time.Time {
	t := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	return func() time.Time {
		t = t.Add(time.Minute)
		return t
	}
}

// testLog builds a log with n entries after the manifest and a tree head
// after every second entry and at the end.
func testLog(t *testing.T, n int) *Log {
	t.Helper()
	l, err := New(testKey(), testManifest(), testClock())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		typ := TypeIssuance
		if i%3 == 2 {
			typ = TypeBallot
		}
		if _, err := l.Append(ctx, typ, map[string]int{"sequence": i}); err != nil {
			t.Fatal(err)
		}
		if i%2 == 1 || i == n-1 {
			if _, err := l.Head(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	return l
}

func hash(b []byte) merkle.Hash { return merkle.Hash(b) }

func TestLogProofs(t *testing.T) {
	l := testLog(t, 11)
	pub := testKey().Public().(ed25519.PublicKey)
	if size, _ := l.Size(ctx); size != 12 {
		t.Fatalf("size %d", size)
	}
	heads, err := l.Heads(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first := heads[0]
	if first.Size != 1 || !bytes.Equal(first.ElectionID, l.id[:]) {
		t.Fatalf("first head: %+v", first)
	}
	for i, h := range heads {
		if err := h.Verify(pub); err != nil {
			t.Fatal(err)
		}
		// Every entry under the head has an inclusion proof.
		for idx := uint64(0); idx < h.Size; idx++ {
			data, _ := l.Entry(ctx, idx)
			proof, err := l.InclusionProof(ctx, idx, h.Size)
			if err != nil {
				t.Fatal(err)
			}
			if err := merkle.VerifyInclusion(merkle.LeafHash(data), idx, h.Size, proof, hash(h.Root)); err != nil {
				t.Fatalf("head %d, entry %d: %v", i, idx, err)
			}
		}
		// Every head is consistent with every later head.
		for _, later := range heads[i:] {
			proof, err := l.ConsistencyProof(ctx, h.Size, later.Size)
			if err != nil {
				t.Fatal(err)
			}
			if err := merkle.VerifyConsistency(h.Size, later.Size, hash(h.Root), hash(later.Root), proof); err != nil {
				t.Fatalf("heads %d and %d: %v", h.Size, later.Size, err)
			}
		}
		if i > 0 && h.Timestamp < heads[i-1].Timestamp {
			t.Fatal("timestamp decreased")
		}
	}
	if _, err := l.InclusionProof(ctx, 0, 13); err == nil {
		t.Error("proof beyond the log")
	}
	if _, err := l.ConsistencyProof(ctx, 1, 13); err == nil {
		t.Error("proof beyond the log")
	}
	if _, err := l.Entry(ctx, 12); err == nil {
		t.Error("entry beyond the log")
	}
}

func TestLogRejects(t *testing.T) {
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	if _, err := New(other, testManifest(), nil); err == nil {
		t.Error("signer without the log key accepted")
	}
	m := testManifest()
	m.Version = 0
	if _, err := New(testKey(), m, nil); err == nil {
		t.Error("invalid manifest accepted")
	}
	l := testLog(t, 0)
	if _, err := l.Append(ctx, TypeManifest, testManifest()); err == nil {
		t.Error("second manifest accepted")
	}
	if _, err := l.Append(ctx, "unknown", map[string]int{}); err == nil {
		t.Error("unknown type accepted")
	}
	if size, _ := l.Size(ctx); size != 1 {
		t.Errorf("size %d after rejected appends", size)
	}
}

// A clock that jumps back does not make timestamps decrease.
func TestLogClockJump(t *testing.T) {
	times := []int64{2000, 1000}
	l, err := New(testKey(), testManifest(), func() time.Time {
		t := time.Unix(times[0], 0)
		if len(times) > 1 {
			times = times[1:]
		}
		return t
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := l.Head(ctx)
	if err != nil || h.Timestamp != 2000 {
		t.Fatalf("timestamp %d, %v", h.Timestamp, err)
	}
}

func TestAppendAll(t *testing.T) {
	l := testLog(t, 0)
	recs := []Record{{TypeIssuance, map[string]int{"sequence": 0}}, {TypeIssuance, map[string]int{"sequence": 1}}}
	h, err := l.AppendAll(ctx, 1, recs)
	if err != nil || h.Size != 3 {
		t.Fatalf("head %+v, %v", h, err)
	}
	// Repeating the append with the old expected size changes nothing.
	if _, err := l.AppendAll(ctx, 1, recs); !errors.Is(err, ErrSize) {
		t.Fatalf("got %v, want ErrSize", err)
	}
	// A batch with a bad record is not applied in part.
	bad := []Record{{TypeIssuance, map[string]int{}}, {"unknown", map[string]int{}}}
	if _, err := l.AppendAll(ctx, -1, bad); err == nil {
		t.Fatal("bad batch accepted")
	}
	if size, _ := l.Size(ctx); size != 3 {
		t.Fatalf("size %d", size)
	}
	// A log opened without a signer can be read but not signed.
	ro := Open(l.store, l.id, nil, nil)
	if _, err := ro.Head(ctx); err == nil {
		t.Fatal("head signed without a signer")
	}
	if last, err := ro.LastHead(ctx); err != nil || last.Size != 3 {
		t.Fatalf("last head %+v, %v", last, err)
	}
	if _, err := Open(l.store, merkle.Hash{}, nil, nil).Size(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown election: %v", err)
	}
	if _, err := Create(ctx, l.store, testKey(), testManifest(), nil); !errors.Is(err, ErrExists) {
		t.Fatalf("second create: %v", err)
	}
}
