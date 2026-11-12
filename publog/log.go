package publog

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/ansiwen/stimmig/merkle"
)

// Log is an append-only log of one election, held in memory. It is safe for
// concurrent use. Persistent storage arrives with the services.
type Log struct {
	mu      sync.Mutex
	signer  crypto.Signer
	now     func() time.Time
	id      merkle.Hash
	entries [][]byte
	leaves  []merkle.Hash
	tree    merkle.Tree
	heads   []TreeHead
}

// New creates the log of a new election. The manifest becomes entry 0 and
// the first tree head is signed. The signer must hold the log key named in
// the manifest. now may be nil for the system clock.
func New(signer crypto.Signer, m Manifest, now func() time.Time) (*Log, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, m.LogKey) {
		return nil, errors.New("publog: signer does not hold the log key of the manifest")
	}
	if now == nil {
		now = time.Now
	}
	data, err := EncodeEntry(TypeManifest, m)
	if err != nil {
		return nil, err
	}
	l := &Log{signer: signer, now: now, id: ElectionID(data)}
	l.add(data)
	if _, err := l.Head(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) add(data []byte) {
	leaf := merkle.LeafHash(data)
	l.entries = append(l.entries, data)
	l.leaves = append(l.leaves, leaf)
	l.tree.Append(leaf)
}

// ElectionID returns the ID of the election.
func (l *Log) ElectionID() merkle.Hash { return l.id }

// Append adds an entry and returns its index. The body must encode as a
// map. A log has exactly one manifest, so the manifest type is rejected.
func (l *Log) Append(typ string, body any) (uint64, error) {
	if typ == TypeManifest {
		return 0, errors.New("publog: the manifest is entry 0 and cannot be appended")
	}
	data, err := EncodeEntry(typ, body)
	if err != nil {
		return 0, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.add(data)
	return l.tree.Size() - 1, nil
}

// Size returns the number of entries.
func (l *Log) Size() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.entries))
}

// Entry returns the encoded entry at index.
func (l *Log) Entry(index uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index >= uint64(len(l.entries)) {
		return nil, errors.New("publog: entry index out of range")
	}
	return l.entries[index], nil
}

// Head signs and records a tree head over all current entries. Timestamps
// never decrease from one tree head to the next.
func (l *Log) Head() (TreeHead, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := uint64(max(l.now().Unix(), 0)) //nolint:gosec // not negative
	if n := len(l.heads); n > 0 && l.heads[n-1].Timestamp > ts {
		ts = l.heads[n-1].Timestamp
	}
	h, err := SignTreeHead(l.signer, l.id, l.tree.Size(), l.tree.Root(), ts)
	if err != nil {
		return TreeHead{}, err
	}
	l.heads = append(l.heads, h)
	return h, nil
}

// InclusionProof returns the proof that the entry at index is in the tree
// of the first size entries.
func (l *Log) InclusionProof(index, size uint64) ([]merkle.Hash, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if size > uint64(len(l.leaves)) {
		return nil, errors.New("publog: tree size out of range")
	}
	return merkle.InclusionProof(l.leaves[:size], index)
}

// ConsistencyProof returns the proof that the tree of the first oldSize
// entries is a prefix of the tree of the first newSize entries.
func (l *Log) ConsistencyProof(oldSize, newSize uint64) ([]merkle.Hash, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if newSize > uint64(len(l.leaves)) {
		return nil, errors.New("publog: tree size out of range")
	}
	return merkle.ConsistencyProof(l.leaves[:newSize], oldSize)
}
