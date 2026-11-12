package publog

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/merkle"
)

// ExportFormat identifies the export format.
const ExportFormat = "stimmig-log-export-v1"

// An export is a sequence of canonical items (RFC 8742). The first item is
// the header. Every further item is a record: an array of a kind and a
// value. An "entry" record holds a log entry, a "tree_head" record a signed
// tree head. Entries appear in log order, and every tree head follows
// directly after the last entry it covers. The last record is a tree head,
// so every entry is covered.
const (
	recordEntry    = "entry"
	recordTreeHead = "tree_head"
)

type exportHeader struct {
	Format string `cbor:"format"`
}

type record struct {
	_     struct{} `cbor:",toarray"`
	Kind  string
	Value canon.Raw
}

// Export writes the complete log. It fails if entries were appended after
// the last tree head; call Head first.
func (l *Log) Export(w io.Writer) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n := len(l.heads); n == 0 || l.heads[n-1].Size != uint64(len(l.entries)) {
		return errors.New("publog: the last tree head does not cover all entries")
	}
	write := func(v any) error {
		data, err := canon.Marshal(v)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	if err := write(exportHeader{Format: ExportFormat}); err != nil {
		return err
	}
	next := 0 // next tree head to write
	size := uint64(0)
	for _, e := range l.entries {
		if err := write(record{Kind: recordEntry, Value: e}); err != nil {
			return err
		}
		size++
		for ; next < len(l.heads) && l.heads[next].Size == size; next++ {
			raw, err := canon.Marshal(l.heads[next])
			if err != nil {
				return err
			}
			if err := write(record{Kind: recordTreeHead, Value: raw}); err != nil {
				return err
			}
		}
	}
	return nil
}

// Report describes a verified export.
type Report struct {
	ElectionID merkle.Hash
	Manifest   Manifest
	// Entries is the number of log entries, Counts the number per type in
	// the order of Types.
	Entries   uint64
	Counts    []uint64
	TreeHeads uint64
	// Final is the last tree head. It covers all entries.
	Final TreeHead
}

// Verify checks the structure of an export:
//
//   - the header names a known format and every item is canonical;
//   - entry 0 is the only manifest, it is valid and uses known algorithms;
//   - every entry has a known type and a map as body;
//   - every tree head is for this election, covers exactly the entries
//     before it, carries the root recomputed from those entries and a valid
//     signature of the log key, and its timestamp does not decrease;
//   - the last record is a tree head.
//
// Recomputing every root from the entries proves that all tree heads are
// consistent with each other. The bodies of entries other than the manifest
// are checked by later verification steps.
//
// visit, if not nil, is called for every entry after it passed its checks.
func Verify(r io.Reader, visit func(index uint64, typ string, entry []byte)) (*Report, error) {
	seq := canon.NewSequenceReader(r)
	item, err := seq.Next()
	if err != nil {
		return nil, fmt.Errorf("export header: %w", err)
	}
	var header exportHeader
	if err := canon.Unmarshal(item, &header); err != nil {
		return nil, fmt.Errorf("export header: %w", err)
	}
	if header.Format != ExportFormat {
		return nil, fmt.Errorf("export header: unknown format %q", header.Format)
	}

	rep := &Report{Counts: make([]uint64, len(Types))}
	var tree merkle.Tree
	covered := true // no entry after the last tree head
	for n := 1; ; n++ {
		item, err := seq.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", n, err)
		}
		var rec record
		if err := canon.Unmarshal(item, &rec); err != nil {
			return nil, fmt.Errorf("record %d: %w", n, err)
		}
		switch rec.Kind {
		case recordEntry:
			index := tree.Size()
			typ, body, err := DecodeEntry(rec.Value)
			if err != nil {
				return nil, fmt.Errorf("entry %d: %w", index, err)
			}
			if (index == 0) != (typ == TypeManifest) {
				return nil, fmt.Errorf("entry %d: the manifest must be entry 0 and nothing else", index)
			}
			if index == 0 {
				if err := canon.Unmarshal(body, &rep.Manifest); err != nil {
					return nil, fmt.Errorf("manifest: %w", err)
				}
				if err := rep.Manifest.Validate(); err != nil {
					return nil, fmt.Errorf("manifest: %w", err)
				}
				rep.ElectionID = ElectionID(rec.Value)
			}
			tree.Append(merkle.LeafHash(rec.Value))
			for i, t := range Types {
				if t == typ {
					rep.Counts[i]++
				}
			}
			covered = false
			if visit != nil {
				visit(index, typ, rec.Value)
			}
		case recordTreeHead:
			var h TreeHead
			if err := canon.Unmarshal(rec.Value, &h); err != nil {
				return nil, fmt.Errorf("record %d: tree head: %w", n, err)
			}
			if err := checkHead(h, rep, &tree); err != nil {
				return nil, fmt.Errorf("record %d: tree head of size %d: %w", n, h.Size, err)
			}
			rep.Final = h
			rep.TreeHeads++
			covered = true
		default:
			return nil, fmt.Errorf("record %d: unknown kind %q", n, rec.Kind)
		}
	}
	rep.Entries = tree.Size()
	if rep.Entries == 0 {
		return nil, errors.New("export has no entries")
	}
	if !covered {
		return nil, errors.New("export does not end with a tree head that covers all entries")
	}
	return rep, nil
}

func checkHead(h TreeHead, rep *Report, tree *merkle.Tree) error {
	if tree.Size() == 0 {
		return errors.New("before the manifest")
	}
	if !bytes.Equal(h.ElectionID, rep.ElectionID[:]) {
		return errors.New("for another election")
	}
	if h.Size != tree.Size() {
		return fmt.Errorf("follows %d entries", tree.Size())
	}
	if root := tree.Root(); !bytes.Equal(h.Root, root[:]) {
		return errors.New("root does not match the entries")
	}
	if h.Timestamp < rep.Final.Timestamp {
		return errors.New("timestamp is before the previous tree head")
	}
	return h.Verify(rep.Manifest.LogKey)
}
