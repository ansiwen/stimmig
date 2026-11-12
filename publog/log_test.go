package publog

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/ansiwen/stimmig/merkle"
)

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
		if _, err := l.Append(typ, map[string]int{"sequence": i}); err != nil {
			t.Fatal(err)
		}
		if i%2 == 1 || i == n-1 {
			if _, err := l.Head(); err != nil {
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
	if l.Size() != 12 {
		t.Fatalf("size %d", l.Size())
	}
	first := l.heads[0]
	if first.Size != 1 || !bytes.Equal(first.ElectionID, l.id[:]) {
		t.Fatalf("first head: %+v", first)
	}
	for i, h := range l.heads {
		if err := h.Verify(pub); err != nil {
			t.Fatal(err)
		}
		// Every entry under the head has an inclusion proof.
		for idx := uint64(0); idx < h.Size; idx++ {
			data, _ := l.Entry(idx)
			proof, err := l.InclusionProof(idx, h.Size)
			if err != nil {
				t.Fatal(err)
			}
			if err := merkle.VerifyInclusion(merkle.LeafHash(data), idx, h.Size, proof, hash(h.Root)); err != nil {
				t.Fatalf("head %d, entry %d: %v", i, idx, err)
			}
		}
		// Every head is consistent with every later head.
		for _, later := range l.heads[i:] {
			proof, err := l.ConsistencyProof(h.Size, later.Size)
			if err != nil {
				t.Fatal(err)
			}
			if err := merkle.VerifyConsistency(h.Size, later.Size, hash(h.Root), hash(later.Root), proof); err != nil {
				t.Fatalf("heads %d and %d: %v", h.Size, later.Size, err)
			}
		}
		if i > 0 && h.Timestamp < l.heads[i-1].Timestamp {
			t.Fatal("timestamp decreased")
		}
	}
	if _, err := l.InclusionProof(0, 13); err == nil {
		t.Error("proof beyond the log")
	}
	if _, err := l.ConsistencyProof(1, 13); err == nil {
		t.Error("proof beyond the log")
	}
	if _, err := l.Entry(12); err == nil {
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
	if _, err := l.Append(TypeManifest, testManifest()); err == nil {
		t.Error("second manifest accepted")
	}
	if _, err := l.Append("unknown", map[string]int{}); err == nil {
		t.Error("unknown type accepted")
	}
	if l.Size() != 1 {
		t.Errorf("size %d after rejected appends", l.Size())
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
	h, err := l.Head()
	if err != nil || h.Timestamp != 2000 {
		t.Fatalf("timestamp %d, %v", h.Timestamp, err)
	}
}
