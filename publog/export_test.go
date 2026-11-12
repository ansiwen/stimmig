package publog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/merkle"
)

func export(t *testing.T, l *Log) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := l.Export(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExportVerify(t *testing.T) {
	l := testLog(t, 11)
	data := export(t, l)
	var seen []string
	rep, err := Verify(bytes.NewReader(data), func(rep *Report, index uint64, typ string, body []byte) error {
		want, _ := l.Entry(index)
		if !bytes.HasSuffix(want, body) || rep.ElectionID != l.ElectionID() {
			t.Errorf("entry %d differs", index)
		}
		seen = append(seen, typ)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ElectionID != l.ElectionID() || rep.Entries != 12 || len(seen) != 12 {
		t.Fatalf("report: %+v", rep)
	}
	// Manifest, 8 issuances, 3 ballots; 7 tree heads.
	if rep.Counts[0] != 1 || rep.Counts[2] != 8 || rep.Counts[4] != 3 || rep.TreeHeads != 7 {
		t.Fatalf("counts %v, tree heads %d", rep.Counts, rep.TreeHeads)
	}
	if rep.Final.Size != 12 || rep.Manifest.Title != "Board election" {
		t.Fatalf("final head %+v", rep.Final)
	}
}

func TestExportNeedsFinalHead(t *testing.T) {
	l := testLog(t, 2)
	if _, err := l.Append(TypeBallot, map[string]int{}); err != nil {
		t.Fatal(err)
	}
	if err := l.Export(io.Discard); err == nil {
		t.Fatal("export without a final tree head")
	}
}

// An error from the visitor stops the verification.
func TestVerifyVisitError(t *testing.T) {
	data := export(t, testLog(t, 3))
	calls := 0
	_, err := Verify(bytes.NewReader(data), func(_ *Report, index uint64, _ string, _ []byte) error {
		calls++
		if index == 2 {
			return errors.New("stop here")
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "entry 2 (issuance): stop here") || calls != 3 {
		t.Fatalf("calls %d, error %v", calls, err)
	}
}

// items splits an export into its top-level items.
func items(t *testing.T, data []byte) [][]byte {
	t.Helper()
	seq := canon.NewSequenceReader(bytes.NewReader(data))
	var out [][]byte
	for {
		item, err := seq.Next()
		if err == io.EOF { //nolint:errorlint // Next returns io.EOF itself
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, append([]byte(nil), item...))
	}
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := canon.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func entryRecord(t *testing.T, typ string, body any) []byte {
	t.Helper()
	e, err := EncodeEntry(typ, body)
	if err != nil {
		t.Fatal(err)
	}
	return marshal(t, record{Kind: recordEntry, Value: e})
}

func headRecord(t *testing.T, h TreeHead) []byte {
	t.Helper()
	return marshal(t, record{Kind: recordTreeHead, Value: marshal(t, h)})
}

func TestVerifyRejects(t *testing.T) {
	// Items: header, manifest, head 1, entry, entry, head 3, entry, entry,
	// head 5.
	l := testLog(t, 4)
	good := items(t, export(t, l))
	if len(good) != 9 {
		t.Fatalf("%d items", len(good))
	}
	id := l.ElectionID()
	key := testKey()
	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	root := func(n int) merkle.Hash { return merkle.Root(l.leaves[:n]) }
	sign := func(k ed25519.PrivateKey, id merkle.Hash, size uint64, root merkle.Hash, ts uint64) []byte {
		h, err := SignTreeHead(k, id, size, root, ts)
		if err != nil {
			t.Fatal(err)
		}
		return headRecord(t, h)
	}
	lastTS := l.heads[len(l.heads)-1].Timestamp
	with := func(i int, item ...[]byte) [][]byte { // replace item i
		out := append([][]byte(nil), good[:i]...)
		out = append(out, item...)
		return append(out, good[i+1:]...)
	}
	badManifest := testManifest()
	badManifest.LogKey = badManifest.LogKey[:31]
	otherManifest := testManifest()
	otherManifest.Title = "Another election"

	// Entries 1 and 2 swapped: items 3 and 4.
	swapped := append([][]byte(nil), good...)
	swapped[3], swapped[4] = good[4], good[3]

	cases := map[string]struct {
		items [][]byte
		want  string
	}{
		"empty":               {nil, "export header"},
		"wrong format":        {with(0, marshal(t, exportHeader{Format: "v0"})), "unknown format"},
		"header only":         {good[:1], "no entries"},
		"no final head":       {good[:8], "does not end with a tree head"},
		"entry removed":       {with(3), "follows 2 entries"},
		"entry changed":       {with(3, entryRecord(t, TypeIssuance, map[string]int{"sequence": 99})), "root does not match"},
		"entries swapped":     {swapped, "root does not match"},
		"entry added":         {with(8, entryRecord(t, TypeBallot, map[string]int{}), good[8]), "follows 6 entries"},
		"second manifest":     {with(3, entryRecord(t, TypeManifest, testManifest())), "manifest must be entry 0"},
		"no manifest":         {with(1, good[3]), "manifest must be entry 0"},
		"invalid manifest":    {with(1, entryRecord(t, TypeManifest, badManifest)), "log key has the wrong size"},
		"other manifest":      {with(1, entryRecord(t, TypeManifest, otherManifest)), "for another election"},
		"head before entries": {with(1, good[2], good[1]), "before the manifest"},
		"head wrong key":      {with(8, sign(otherKey, id, 5, root(5), lastTS)), "signature is invalid"},
		"head wrong root":     {with(8, sign(key, id, 5, root(4), lastTS)), "root does not match"},
		"head wrong size":     {with(8, sign(key, id, 4, root(4), lastTS)), "follows 5 entries"},
		"head wrong election": {with(8, sign(key, root(2), 5, root(5), lastTS)), "for another election"},
		"head back in time":   {with(8, sign(key, id, 5, root(5), lastTS-1000)), "before the previous tree head"},
		"unknown record kind": {with(3, marshal(t, record{Kind: "note", Value: marshal(t, 1)})), "unknown kind"},
		"unknown entry type":  {with(3, marshal(t, record{Kind: recordEntry, Value: marshal(t, []any{"vote", map[string]int{}})})), "unknown entry type"},
		"not canonical":       {with(3, []byte{0x18, 0x01}), "not canonical"},
		"truncated":           {with(8, good[8][:len(good[8])-1]), "record 8"},
		"trailing bytes":      {append(with(8, good[8]), []byte{0xff}), "record 9"},
	}
	for name, c := range cases {
		_, err := Verify(bytes.NewReader(bytes.Join(c.items, nil)), nil)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not contain %q", name, err, c.want)
		}
	}
	// A repeated tree head of the same size is allowed.
	repeated := with(8, good[8], sign(key, id, 5, root(5), lastTS+60))
	if _, err := Verify(bytes.NewReader(bytes.Join(repeated, nil)), nil); err != nil {
		t.Errorf("repeated tree head: %v", err)
	}
}

func FuzzVerify(f *testing.F) {
	l, err := New(testKey(), testManifest(), testClock())
	if err != nil {
		f.Fatal(err)
	}
	if _, err := l.Append(TypeBallot, map[string]int{"sequence": 1}); err != nil {
		f.Fatal(err)
	}
	if _, err := l.Head(); err != nil {
		f.Fatal(err)
	}
	var buf bytes.Buffer
	if err := l.Export(&buf); err != nil {
		f.Fatal(err)
	}
	f.Add(buf.Bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		rep, err := Verify(bytes.NewReader(data), nil)
		if err == nil && (rep.Entries == 0 || rep.Final.Size != rep.Entries) {
			t.Fatalf("accepted export without a covering tree head: %+v", rep)
		}
	})
}
