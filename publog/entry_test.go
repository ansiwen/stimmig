package publog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/ansiwen/stimmig/ballot"
	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/credential"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/tally"
)

// testKey returns a fixed key, so that test outputs are reproducible.
func testKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
}

// testKeys creates the slow keys once per test run.
var testKeys = sync.OnceValue(func() (k struct{ issuing, election, electionPrivate []byte }) {
	sk, err := credential.GenerateIssuingKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	if k.issuing, err = credential.MarshalIssuingKey(&sk.PublicKey); err != nil {
		panic(err)
	}
	if k.election, k.electionPrivate, err = ballot.GenerateElectionKey(); err != nil {
		panic(err)
	}
	return k
})

func testManifest() Manifest {
	return Manifest{
		Version: ManifestVersion,
		Title:   "Board election",
		Nonce:   bytes.Repeat([]byte{1}, 16),
		Tally: tally.Manifest{
			Candidates: []string{"A", "B", "C"},
			Method:     tally.Schulze,
			MaxRanks:   2,
		},
		Algorithms:  DefaultAlgorithms(ReceiptFull),
		ReceiptMode: ReceiptFull,
		LogKey:      testKey().Public().(ed25519.PublicKey),
		IssuingKey:  testKeys().issuing,
		ElectionKey: testKeys().election,
		ReceiptKey:  testKey().Public().(ed25519.PublicKey),
	}
}

func TestManifestValidate(t *testing.T) {
	if err := testManifest().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*Manifest){
		"version":      func(m *Manifest) { m.Version = 2 },
		"nonce":        func(m *Manifest) { m.Nonce = m.Nonce[:15] },
		"log hash":     func(m *Manifest) { m.Algorithms.LogHash = "sha1" },
		"tree head":    func(m *Manifest) { m.Algorithms.TreeHead = "ed25519-v2" },
		"log key":      func(m *Manifest) { m.LogKey = m.LogKey[:31] },
		"tally":        func(m *Manifest) { m.Tally.Method = "plurality" },
		"no tally":     func(m *Manifest) { m.Tally = tally.Manifest{} },
		"no algorithm": func(m *Manifest) { m.Algorithms = Algorithms{} },
		"credential":   func(m *Manifest) { m.Algorithms.Credential = "blind-schnorr-v1" },
		"encryption":   func(m *Manifest) { m.Algorithms.BallotEncryption = "none" },
		"signature":    func(m *Manifest) { m.Algorithms.BallotSignature = "ml-dsa-v1" },
		"receipt mode": func(m *Manifest) { m.ReceiptMode = "maybe" },
		"receipt alg":  func(m *Manifest) { m.Algorithms.ReceiptSignature = "" },
		"receipt key":  func(m *Manifest) { m.ReceiptKey = nil },
		"client hash":  func(m *Manifest) { m.ClientHash = []byte{1, 2, 3} },
		"issuing key":  func(m *Manifest) { m.IssuingKey = m.IssuingKey[1:] },
		"election key": func(m *Manifest) { m.ElectionKey = m.ElectionKey[:64] },
		"none with receipt key": func(m *Manifest) {
			m.ReceiptMode = ReceiptNone
			m.Algorithms = DefaultAlgorithms(ReceiptNone)
		},
	}
	for name, change := range bad {
		m := testManifest()
		change(&m)
		if m.Validate() == nil {
			t.Errorf("%s: invalid manifest accepted", name)
		}
	}
	none := testManifest()
	none.ReceiptMode = ReceiptNone
	none.Algorithms = DefaultAlgorithms(ReceiptNone)
	none.ReceiptKey = nil
	if err := none.Validate(); err != nil {
		t.Errorf("receipt mode none: %v", err)
	}
}

func TestEntryRoundTrip(t *testing.T) {
	data, err := EncodeEntry(TypeManifest, testManifest())
	if err != nil {
		t.Fatal(err)
	}
	typ, body, err := DecodeEntry(data)
	if err != nil || typ != TypeManifest {
		t.Fatalf("type %q, %v", typ, err)
	}
	var m Manifest
	if err := canon.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if m.Title != "Board election" || m.Tally.MaxRanks != 2 || len(m.Tally.Candidates) != 3 {
		t.Fatalf("manifest: %+v", m)
	}
	// The tally manifest uses its JSON field names in the encoding.
	if !bytes.Contains(body, []byte("max_ranks")) {
		t.Error("tally manifest field names are not the JSON names")
	}
	if ElectionID(data) != merkle.LeafHash(data) {
		t.Error("election ID is not the leaf hash of the manifest entry")
	}
}

func TestEntryRejects(t *testing.T) {
	if _, err := EncodeEntry("unknown", map[string]int{}); err == nil {
		t.Error("unknown type encoded")
	}
	if _, err := EncodeEntry(TypeBallot, []int{1}); err == nil {
		t.Error("array body encoded")
	}
	bad := map[string]any{
		"unknown type":  []any{"unknown", map[string]int{}},
		"array body":    []any{TypeBallot, []int{1}},
		"three items":   []any{TypeBallot, map[string]int{}, 1},
		"one item":      []any{TypeBallot},
		"not an array":  map[string]int{"a": 1},
		"type not text": []any{1, map[string]int{}},
	}
	for name, v := range bad {
		data, err := canon.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := DecodeEntry(data); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	// Not canonical: the integer 1 in two bytes inside a valid entry.
	data, _ := hex.DecodeString("82" + "6662616c6c6f74" + "a1" + "6161" + "1801")
	if _, _, err := DecodeEntry(data); err == nil {
		t.Error("non-canonical entry decoded")
	}
}

func TestTreeHead(t *testing.T) {
	key := testKey()
	pub := key.Public().(ed25519.PublicKey)
	id := merkle.LeafHash([]byte("manifest"))
	root := merkle.LeafHash([]byte("root"))
	h, err := SignTreeHead(key, id, 5, root, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(pub); err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*TreeHead){
		"size":        func(h *TreeHead) { h.Size++ },
		"timestamp":   func(h *TreeHead) { h.Timestamp++ },
		"root":        func(h *TreeHead) { h.Root = id[:] },
		"election ID": func(h *TreeHead) { h.ElectionID = root[:] },
		"signature":   func(h *TreeHead) { h.Signature = append([]byte{h.Signature[0] ^ 1}, h.Signature[1:]...) },
		"short root":  func(h *TreeHead) { h.Root = h.Root[:31] },
	}
	for name, change := range changes {
		c := h
		change(&c)
		if c.Verify(pub) == nil {
			t.Errorf("%s: changed tree head verifies", name)
		}
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	if h.Verify(other.Public().(ed25519.PublicKey)) == nil {
		t.Error("tree head verifies with another key")
	}
	// The encoding round-trips.
	data, err := canon.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var back TreeHead
	if err := canon.Unmarshal(data, &back); err != nil || back.Verify(pub) != nil {
		t.Fatalf("round trip: %v", err)
	}
}
