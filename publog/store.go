package publog

import (
	"context"
	"errors"
	"sync"

	"github.com/ansiwen/stimmig/merkle"
)

// ErrNotFound reports an election that the store does not hold.
var ErrNotFound = errors.New("publog: election not found")

// ErrExists reports an attempt to create a log that exists already.
var ErrExists = errors.New("publog: election exists already")

// Store keeps the logs of elections. Implementations must be safe for
// concurrent use, also by several processes.
type Store interface {
	// Create adds an empty log.
	Create(ctx context.Context, id merkle.Hash) error
	// Update runs fn with exclusive write access to one log. Everything fn
	// does through State is applied atomically, or not at all if fn returns
	// an error.
	Update(ctx context.Context, id merkle.Hash, fn func(State) error) error
	// Size returns the number of entries.
	Size(ctx context.Context, id merkle.Hash) (uint64, error)
	// Entries returns the encoded entries from index from up to, but not
	// including, index to.
	Entries(ctx context.Context, id merkle.Hash, from, to uint64) ([][]byte, error)
	// Leaves returns the leaf hashes of the first size entries.
	Leaves(ctx context.Context, id merkle.Hash, size uint64) ([]merkle.Hash, error)
	// Heads returns all tree heads in the order they were signed.
	Heads(ctx context.Context, id merkle.Hash) ([]TreeHead, error)
}

// State is the write access to one log inside Store.Update.
type State interface {
	// Tree returns the Merkle tree state over all entries.
	Tree() (merkle.Tree, error)
	// LastHead returns the newest tree head, or nil if there is none.
	LastHead() (*TreeHead, error)
	// Append stores the next entry with its leaf hash, and the tree state
	// that includes it.
	Append(entry []byte, leaf merkle.Hash, tree merkle.Tree) error
	// AddHead stores a tree head.
	AddHead(h TreeHead) error
}

// MemStore is a Store in memory, for tests and development.
type MemStore struct {
	mu   sync.Mutex
	logs map[merkle.Hash]*memLog
}

type memLog struct {
	entries [][]byte
	leaves  []merkle.Hash
	tree    merkle.Tree
	heads   []TreeHead
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{logs: map[merkle.Hash]*memLog{}}
}

// Create implements Store.
func (s *MemStore) Create(_ context.Context, id merkle.Hash) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.logs[id]; ok {
		return ErrExists
	}
	s.logs[id] = &memLog{}
	return nil
}

// memState collects the changes of one update.
type memState struct {
	log     *memLog
	entries [][]byte
	leaves  []merkle.Hash
	tree    merkle.Tree
	heads   []TreeHead
}

func (st *memState) Tree() (merkle.Tree, error) { return st.tree, nil }

func (st *memState) LastHead() (*TreeHead, error) {
	if n := len(st.heads); n > 0 {
		return &st.heads[n-1], nil
	}
	if n := len(st.log.heads); n > 0 {
		h := st.log.heads[n-1]
		return &h, nil
	}
	return nil, nil //nolint:nilnil // no head is not an error
}

func (st *memState) Append(entry []byte, leaf merkle.Hash, tree merkle.Tree) error {
	st.entries = append(st.entries, entry)
	st.leaves = append(st.leaves, leaf)
	st.tree = tree
	return nil
}

func (st *memState) AddHead(h TreeHead) error {
	st.heads = append(st.heads, h)
	return nil
}

// Update implements Store.
func (s *MemStore) Update(_ context.Context, id merkle.Hash, fn func(State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	log, ok := s.logs[id]
	if !ok {
		return ErrNotFound
	}
	st := &memState{log: log, tree: log.tree}
	if err := fn(st); err != nil {
		return err
	}
	log.entries = append(log.entries, st.entries...)
	log.leaves = append(log.leaves, st.leaves...)
	log.tree = st.tree
	log.heads = append(log.heads, st.heads...)
	return nil
}

func (s *MemStore) read(id merkle.Hash, fn func(*memLog) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	log, ok := s.logs[id]
	if !ok {
		return ErrNotFound
	}
	return fn(log)
}

// Size implements Store.
func (s *MemStore) Size(_ context.Context, id merkle.Hash) (size uint64, err error) {
	err = s.read(id, func(l *memLog) error {
		size = l.tree.Size()
		return nil
	})
	return size, err
}

// Entries implements Store.
func (s *MemStore) Entries(_ context.Context, id merkle.Hash, from, to uint64) (out [][]byte, err error) {
	err = s.read(id, func(l *memLog) error {
		if from > to || to > l.tree.Size() {
			return errors.New("publog: entry range out of bounds")
		}
		out = append(out, l.entries[from:to]...)
		return nil
	})
	return out, err
}

// Leaves implements Store.
func (s *MemStore) Leaves(_ context.Context, id merkle.Hash, size uint64) (out []merkle.Hash, err error) {
	err = s.read(id, func(l *memLog) error {
		if size > l.tree.Size() {
			return errors.New("publog: tree size out of range")
		}
		out = append(out, l.leaves[:size]...)
		return nil
	})
	return out, err
}

// Heads implements Store.
func (s *MemStore) Heads(_ context.Context, id merkle.Hash) (out []TreeHead, err error) {
	err = s.read(id, func(l *memLog) error {
		out = append(out, l.heads...)
		return nil
	})
	return out, err
}
