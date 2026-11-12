package publog

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/ansiwen/stimmig/merkle"
)

// ErrSize reports an append that expected another log size. The writer
// lost a race or repeats an append that was already done.
var ErrSize = errors.New("publog: the log does not have the expected size")

// Log is the append-only log of one election on top of a Store. It is safe
// for concurrent use.
type Log struct {
	store  Store
	id     merkle.Hash
	signer crypto.Signer
	now    func() time.Time
}

// Record is a log entry before it is encoded: its type and its body.
type Record struct {
	Type string
	Body any
}

// Create starts the log of a new election in the store. The manifest
// becomes entry 0 and the first tree head is signed. The signer must hold
// the log key named in the manifest. now may be nil for the system clock.
func Create(ctx context.Context, store Store, signer crypto.Signer, m Manifest, now func() time.Time) (*Log, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, m.LogKey) {
		return nil, errors.New("publog: signer does not hold the log key of the manifest")
	}
	data, err := EncodeEntry(TypeManifest, m)
	if err != nil {
		return nil, err
	}
	l := Open(store, ElectionID(data), signer, now)
	if err := store.Create(ctx, l.id); err != nil {
		return nil, err
	}
	if _, err := l.appendEncoded(ctx, -1, [][]byte{data}, true); err != nil {
		return nil, err
	}
	return l, nil
}

// Open returns the log of an existing election. The signer may be nil for
// a log that is only read. now may be nil for the system clock.
func Open(store Store, id merkle.Hash, signer crypto.Signer, now func() time.Time) *Log {
	if now == nil {
		now = time.Now
	}
	return &Log{store: store, id: id, signer: signer, now: now}
}

// New creates the log of a new election in memory.
func New(signer crypto.Signer, m Manifest, now func() time.Time) (*Log, error) {
	return Create(context.Background(), NewMemStore(), signer, m, now)
}

// ElectionID returns the ID of the election.
func (l *Log) ElectionID() merkle.Hash { return l.id }

// Append adds one entry without signing a tree head, and returns its
// index. The body must encode as a map.
func (l *Log) Append(ctx context.Context, typ string, body any) (uint64, error) {
	data, err := encodeRecord(Record{typ, body})
	if err != nil {
		return 0, err
	}
	size, err := l.appendEncoded(ctx, -1, [][]byte{data}, false)
	if err != nil {
		return 0, err
	}
	return size - 1, nil
}

// AppendAll adds the records atomically and signs a tree head over them.
// If expectSize is not negative, the log must have exactly that many
// entries before, or ErrSize is returned and nothing is appended. Writers
// use this to make their appends safe to repeat.
func (l *Log) AppendAll(ctx context.Context, expectSize int64, records []Record) (TreeHead, error) {
	encoded := make([][]byte, len(records))
	for i, r := range records {
		data, err := encodeRecord(r)
		if err != nil {
			return TreeHead{}, err
		}
		encoded[i] = data
	}
	var head TreeHead
	err := l.store.Update(ctx, l.id, func(st State) error {
		if err := l.appendTo(st, expectSize, encoded); err != nil {
			return err
		}
		var err error
		head, err = l.signHead(st)
		return err
	})
	return head, err
}

// A log has exactly one manifest, so the manifest type is rejected.
func encodeRecord(r Record) ([]byte, error) {
	if r.Type == TypeManifest {
		return nil, errors.New("publog: the manifest is entry 0 and cannot be appended")
	}
	return EncodeEntry(r.Type, r.Body)
}

func (l *Log) appendEncoded(ctx context.Context, expectSize int64, encoded [][]byte, sign bool) (size uint64, err error) {
	err = l.store.Update(ctx, l.id, func(st State) error {
		if err := l.appendTo(st, expectSize, encoded); err != nil {
			return err
		}
		tree, err := st.Tree()
		if err != nil {
			return err
		}
		size = tree.Size()
		if sign {
			_, err = l.signHead(st)
		}
		return err
	})
	return size, err
}

func (l *Log) appendTo(st State, expectSize int64, encoded [][]byte) error {
	tree, err := st.Tree()
	if err != nil {
		return err
	}
	if expectSize >= 0 && tree.Size() != uint64(expectSize) {
		return fmt.Errorf("%w: %d entries, expected %d", ErrSize, tree.Size(), expectSize)
	}
	for _, data := range encoded {
		leaf := merkle.LeafHash(data)
		tree.Append(leaf)
		if err := st.Append(data, leaf, tree); err != nil {
			return err
		}
	}
	return nil
}

// signHead signs and stores a tree head over the current tree. Timestamps
// never decrease from one tree head to the next.
func (l *Log) signHead(st State) (TreeHead, error) {
	if l.signer == nil {
		return TreeHead{}, errors.New("publog: the log was opened without a signer")
	}
	tree, err := st.Tree()
	if err != nil {
		return TreeHead{}, err
	}
	last, err := st.LastHead()
	if err != nil {
		return TreeHead{}, err
	}
	ts := uint64(max(l.now().Unix(), 0)) //nolint:gosec // not negative
	if last != nil && last.Timestamp > ts {
		ts = last.Timestamp
	}
	h, err := SignTreeHead(l.signer, l.id, tree.Size(), tree.Root(), ts)
	if err != nil {
		return TreeHead{}, err
	}
	return h, st.AddHead(h)
}

// Head signs and records a tree head over all current entries.
func (l *Log) Head(ctx context.Context) (head TreeHead, err error) {
	err = l.store.Update(ctx, l.id, func(st State) error {
		head, err = l.signHead(st)
		return err
	})
	return head, err
}

// Size returns the number of entries.
func (l *Log) Size(ctx context.Context) (uint64, error) {
	return l.store.Size(ctx, l.id)
}

// Entry returns the encoded entry at index.
func (l *Log) Entry(ctx context.Context, index uint64) ([]byte, error) {
	entries, err := l.Entries(ctx, index, index+1)
	if err != nil {
		return nil, err
	}
	return entries[0], nil
}

// Entries returns the encoded entries from index from up to, but not
// including, index to.
func (l *Log) Entries(ctx context.Context, from, to uint64) ([][]byte, error) {
	return l.store.Entries(ctx, l.id, from, to)
}

// Heads returns all tree heads in the order they were signed.
func (l *Log) Heads(ctx context.Context) ([]TreeHead, error) {
	return l.store.Heads(ctx, l.id)
}

// LastHead returns the newest tree head.
func (l *Log) LastHead(ctx context.Context) (TreeHead, error) {
	heads, err := l.Heads(ctx)
	if err != nil {
		return TreeHead{}, err
	}
	if len(heads) == 0 {
		return TreeHead{}, errors.New("publog: the log has no tree head")
	}
	return heads[len(heads)-1], nil
}

// InclusionProof returns the proof that the entry at index is in the tree
// of the first size entries.
func (l *Log) InclusionProof(ctx context.Context, index, size uint64) ([]merkle.Hash, error) {
	leaves, err := l.store.Leaves(ctx, l.id, size)
	if err != nil {
		return nil, err
	}
	return merkle.InclusionProof(leaves, index)
}

// ConsistencyProof returns the proof that the tree of the first oldSize
// entries is a prefix of the tree of the first newSize entries.
func (l *Log) ConsistencyProof(ctx context.Context, oldSize, newSize uint64) ([]merkle.Hash, error) {
	leaves, err := l.store.Leaves(ctx, l.id, newSize)
	if err != nil {
		return nil, err
	}
	return merkle.ConsistencyProof(leaves, oldSize)
}
