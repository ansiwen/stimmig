// Package logsvc implements the log service: the public log of every
// election in PostgreSQL behind an HTTP API (SPEC.md sections 7 and 10).
package logsvc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	_ "embed" // for the schema
	"errors"

	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/keystore"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/publog"
)

//go:embed schema.sql
var schema string

// Store keeps logs and log keys in PostgreSQL. It implements publog.Store.
// Appends to one log are serialised by a row lock, so any number of service
// replicas can write.
//
// shortcut: proofs read all leaf hashes up to the tree size, which is fine for thousands of entries; store the inner Merkle nodes when logs get large.
type Store struct {
	db *sql.DB
	// Keys encrypts the private log keys at rest. Nil stores them in clear.
	Keys keystore.Sealer
}

// sealer returns the key store, or the unencrypted one if none is set.
func (s *Store) sealer() keystore.Sealer {
	if s.Keys == nil {
		return keystore.Plain{}
	}
	return s.Keys
}

// NewStore creates the tables if they are missing.
func NewStore(ctx context.Context, db *sql.DB) (*Store, error) {
	_, err := db.ExecContext(ctx, schema)
	return &Store{db: db}, err
}

// NewKey creates a log key and returns its public key. The private key
// stays in the database, sealed by the key store.
func (s *Store) NewKey(ctx context.Context) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sealed, err := s.sealer().Seal(priv, pub)
	if err != nil {
		return nil, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO log_keys (public, private) VALUES ($1, $2)`, []byte(pub), sealed)
	return pub, err
}

// Bind ties an unused log key to its election and returns the private key.
// A log key serves exactly one election.
func (s *Store) Bind(ctx context.Context, public []byte, id merkle.Hash) (ed25519.PrivateKey, error) {
	var priv []byte
	err := s.db.QueryRowContext(ctx,
		`UPDATE log_keys SET election = $2 WHERE public = $1 AND election IS NULL RETURNING private`, public, id[:]).Scan(&priv)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("logsvc: the log key is unknown or already in use")
	}
	if err != nil {
		return nil, err
	}
	return s.sealer().Open(priv, public)
}

// Signer returns the log key of an election.
func (s *Store) Signer(ctx context.Context, id merkle.Hash) (ed25519.PrivateKey, error) {
	var public, priv []byte
	err := s.db.QueryRowContext(ctx, `SELECT public, private FROM log_keys WHERE election = $1`, id[:]).Scan(&public, &priv)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, publog.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.sealer().Open(priv, public)
}

// Create implements publog.Store.
func (s *Store) Create(ctx context.Context, id merkle.Hash) error {
	var empty merkle.Tree
	tree, _ := empty.MarshalBinary()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO log_elections (id, tree) VALUES ($1, $2) ON CONFLICT DO NOTHING`, id[:], tree)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return publog.ErrExists
	}
	return nil
}

type state struct {
	ctx  context.Context //nolint:containedctx // lives for one Update call
	tx   *sql.Tx
	id   merkle.Hash
	tree merkle.Tree
}

func (st *state) Tree() (merkle.Tree, error) { return st.tree, nil }

func (st *state) LastHead() (*publog.TreeHead, error) {
	var raw []byte
	err := st.tx.QueryRowContext(st.ctx,
		`SELECT head FROM log_heads WHERE election = $1 ORDER BY seq DESC LIMIT 1`, st.id[:]).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // no head is not an error
	}
	if err != nil {
		return nil, err
	}
	var h publog.TreeHead
	return &h, canon.Unmarshal(raw, &h)
}

func (st *state) Append(entry []byte, leaf merkle.Hash, tree merkle.Tree) error {
	_, err := st.tx.ExecContext(st.ctx,
		`INSERT INTO log_entries (election, idx, entry, leaf) VALUES ($1, $2, $3, $4)`,
		st.id[:], int64(tree.Size()-1), entry, leaf[:]) //nolint:gosec // log sizes fit in int64
	st.tree = tree
	return err
}

func (st *state) AddHead(h publog.TreeHead) error {
	raw, err := canon.Marshal(h)
	if err != nil {
		return err
	}
	_, err = st.tx.ExecContext(st.ctx, `INSERT INTO log_heads (election, head) VALUES ($1, $2)`, st.id[:], raw)
	return err
}

// Update implements publog.Store.
func (s *Store) Update(ctx context.Context, id merkle.Hash, fn func(publog.State) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT tree FROM log_elections WHERE id = $1 FOR UPDATE`, id[:]).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return publog.ErrNotFound
	}
	if err != nil {
		return err
	}
	st := &state{ctx: ctx, tx: tx, id: id}
	if err := st.tree.UnmarshalBinary(raw); err != nil {
		return err
	}
	if err := fn(st); err != nil {
		return err
	}
	if raw, err = st.tree.MarshalBinary(); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE log_elections SET tree = $2 WHERE id = $1`, id[:], raw); err != nil {
		return err
	}
	return tx.Commit()
}

// Size implements publog.Store.
func (s *Store) Size(ctx context.Context, id merkle.Hash) (uint64, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT tree FROM log_elections WHERE id = $1`, id[:]).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, publog.ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	var tree merkle.Tree
	err = tree.UnmarshalBinary(raw)
	return tree.Size(), err
}

// column runs a query for one bytea column of the entries from index from up to, but
// not including, index to, and fails if any is missing.
func (s *Store) column(ctx context.Context, query string, id merkle.Hash, from, to uint64) ([][]byte, error) {
	if from > to {
		return nil, errors.New("logsvc: entry range out of bounds")
	}
	rows, err := s.db.QueryContext(ctx, query, id[:], int64(from), int64(to)) //nolint:gosec // log sizes fit in int64
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if uint64(len(out)) != to-from {
		if _, err := s.Size(ctx, id); err != nil {
			return nil, err // unknown election
		}
		return nil, errors.New("logsvc: entry range out of bounds")
	}
	return out, nil
}

// Entries implements publog.Store.
func (s *Store) Entries(ctx context.Context, id merkle.Hash, from, to uint64) ([][]byte, error) {
	return s.column(ctx, `SELECT entry FROM log_entries WHERE election = $1 AND idx >= $2 AND idx < $3 ORDER BY idx`, id, from, to)
}

// Leaves implements publog.Store.
func (s *Store) Leaves(ctx context.Context, id merkle.Hash, size uint64) ([]merkle.Hash, error) {
	raw, err := s.column(ctx, `SELECT leaf FROM log_entries WHERE election = $1 AND idx >= $2 AND idx < $3 ORDER BY idx`, id, 0, size)
	if err != nil {
		return nil, err
	}
	out := make([]merkle.Hash, len(raw))
	for i, b := range raw {
		out[i] = merkle.Hash(b)
	}
	return out, nil
}

// Heads implements publog.Store.
func (s *Store) Heads(ctx context.Context, id merkle.Hash) ([]publog.TreeHead, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT head FROM log_heads WHERE election = $1 ORDER BY seq`, id[:])
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []publog.TreeHead
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var h publog.TreeHead
		if err := canon.Unmarshal(raw, &h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
