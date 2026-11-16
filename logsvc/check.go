package logsvc

import (
	"context"
	"fmt"

	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/election"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/publog"
)

// maxCheckers bounds the elections whose checking state is kept in memory.
const maxCheckers = 16

// checker returns the checker of an election, positioned after the first
// size entries of its log. The caller holds s.mu. The state is kept between
// appends; if it is missing, or another replica has appended since, it is
// rebuilt from the entries of the log, which costs one verification of the log.
func (s *Server) checker(ctx context.Context, id merkle.Hash, size uint64) (*election.Checker, error) {
	c := s.checkers[id]
	if c != nil && c.Size() > size {
		c = nil // the log is shorter than what the checker saw
	}
	from := uint64(1)
	if c != nil {
		from = c.Size()
	}
	entries, err := s.Store.Entries(ctx, id, 0, size)
	if err != nil {
		return nil, err
	}
	if uint64(len(entries)) != size {
		return nil, fmt.Errorf("the log has %d entries, not %d", len(entries), size)
	}
	if c == nil {
		typ, body, err := publog.DecodeEntry(entries[0])
		if err != nil || typ != publog.TypeManifest {
			return nil, fmt.Errorf("the first entry is not a manifest")
		}
		var m publog.Manifest
		if err := canon.UnmarshalStrict(body, &m); err != nil {
			return nil, err
		}
		if c, err = election.NewChecker(publog.ElectionID(entries[0]), m); err != nil {
			return nil, err
		}
	}
	for _, e := range entries[from:] {
		typ, body, err := publog.DecodeEntry(e)
		if err == nil {
			err = c.Check(merkle.LeafHash(e), typ, body)
		}
		if err != nil {
			return nil, fmt.Errorf("the log is invalid: %w", err)
		}
	}
	if s.checkers == nil || len(s.checkers) >= maxCheckers {
		s.checkers = map[merkle.Hash]*election.Checker{}
	}
	s.checkers[id] = c
	return c, nil
}
