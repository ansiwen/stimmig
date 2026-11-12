// Package ballotbox implements the ballot box service: it accepts anonymous
// signed ballots, answers with receipts, and publishes all ballots at the
// close (SPEC.md sections 5.2, 5.3 and 10).
//
// The ballot box needs no login and writes no client identifiers anywhere.
// A valid credential signature is its abuse control.
package ballotbox

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed" // for the schema
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ansiwen/stimmig/api"
	"github.com/ansiwen/stimmig/ballot"
	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/election"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/publog"
)

//go:embed schema.sql
var schema string

// Phases of an election in the ballot box.
const (
	PhaseSetup     = "setup"     // voting has not opened
	PhaseOpen      = "open"      // ballots are accepted
	PhaseClosed    = "closed"    // no more ballots; not yet in the log
	PhasePublished = "published" // all ballots are in the log
)

// Server is the HTTP API of the ballot box.
//
//	POST /v1/keys                    admin   create a receipt key
//	POST /v1/elections               admin   register an election by its manifest
//	POST /v1/elections/{id}/open     admin   open the voting
//	POST /v1/elections/{id}/close    admin   close the voting, publish the ballots
//	POST /v1/elections/{id}/ballots  voter   cast a ballot
//	GET  /v1/elections/{id}          public  phase and number of ballots cast
//	GET  /v1/client                  public  hash of the voting client's bundle
//	GET  /                           public  the voting client
type Server struct {
	DB *sql.DB
	// Log is the log service, with the ballot box's writer token.
	Log        *api.Client
	AdminToken string
	// ClientDir is the directory with the voting client's static bundle.
	// If it is set, the ballot box serves the bundle at / and its hash at
	// GET /v1/client.
	ClientDir string
}

// Init creates the tables if they are missing.
func (s *Server) Init(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, schema)
	return err
}

// Handler returns the routes of the service.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/keys", api.Admin(s.AdminToken, s.newKey))
	mux.HandleFunc("POST /v1/elections", api.Admin(s.AdminToken, s.create))
	mux.HandleFunc("POST /v1/elections/{id}/open", api.Admin(s.AdminToken, s.open))
	mux.HandleFunc("POST /v1/elections/{id}/close", api.Admin(s.AdminToken, s.close))
	mux.HandleFunc("POST /v1/elections/{id}/ballots", api.Handle(s.cast))
	mux.HandleFunc("GET /v1/elections/{id}", api.Handle(s.status))
	if s.ClientDir != "" {
		mux.HandleFunc("GET /v1/client", api.Handle(func(http.ResponseWriter, *http.Request) (any, error) {
			hash, err := ClientHash(s.ClientDir)
			return api.ClientBundle{Hash: hash}, err
		}))
		files := http.FileServer(http.Dir(s.ClientDir))
		mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The page holds the credential: it may load code only from
			// this origin, and it may not be framed.
			w.Header().Set("Content-Security-Policy",
				"default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src https: http:; "+
					"base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Cache-Control", "no-cache")
			files.ServeHTTP(w, r)
		}))
	}
	return api.CORS(mux)
}

func electionID(r *http.Request) (merkle.Hash, error) {
	id, err := api.ElectionID(r)
	if err != nil {
		return id, api.Errorf(http.StatusBadRequest, "election ID: %v", err)
	}
	return id, nil
}

// newKey creates a receipt key.
//
// shortcut: private keys are stored in the database in clear; M6 moves them behind the HSM interface.
func (s *Server) newKey(_ http.ResponseWriter, r *http.Request) (any, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_, err = s.DB.ExecContext(r.Context(), `INSERT INTO box_keys (public, private) VALUES ($1, $2)`, []byte(pub), []byte(priv))
	return api.BallotBoxKey{ReceiptKey: pub}, err
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) (any, error) {
	var m publog.Manifest
	if err := api.Read(w, r, &m); err != nil {
		return nil, api.Errorf(http.StatusBadRequest, "%v", err)
	}
	if err := m.Validate(); err != nil {
		return nil, api.Errorf(http.StatusBadRequest, "%v", err)
	}
	entry, err := publog.EncodeEntry(publog.TypeManifest, m)
	if err != nil {
		return nil, err
	}
	id := publog.ElectionID(entry)
	raw, err := canon.Marshal(m)
	if err != nil {
		return nil, err
	}
	ctx := r.Context()
	err = api.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		if m.ReceiptMode == publog.ReceiptFull {
			res, err := tx.ExecContext(ctx,
				`UPDATE box_keys SET election = $2 WHERE public = $1 AND election IS NULL`, m.ReceiptKey, id[:])
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return api.Errorf(http.StatusBadRequest, "the receipt key of the manifest is unknown or already in use")
			}
		}
		res, err := tx.ExecContext(ctx,
			`INSERT INTO box_elections (id, manifest, phase) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, id[:], raw, PhaseSetup)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return api.Errorf(http.StatusConflict, "the election exists already")
		}
		return nil
	})
	return api.Created{ElectionID: id[:]}, err
}

// logReport fetches the public log and verifies it.
func (s *Server) logReport(ctx context.Context, id merkle.Hash) (*election.Report, error) {
	export, err := api.Export(ctx, s.Log, id)
	if err != nil {
		return nil, fmt.Errorf("log: %w", err)
	}
	rep, err := election.Verify(bytes.NewReader(export), nil)
	if err != nil {
		return nil, fmt.Errorf("the log does not verify: %w", err)
	}
	return rep, nil
}

// setPhase moves an election from one of the given phases to another.
func (s *Server) setPhase(ctx context.Context, id merkle.Hash, to string, from ...string) error {
	return api.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		var phase string
		// The lock waits for the casts that are in flight.
		err := tx.QueryRowContext(ctx, `SELECT phase FROM box_elections WHERE id = $1 FOR UPDATE`, id[:]).Scan(&phase)
		if errors.Is(err, sql.ErrNoRows) {
			return api.Errorf(http.StatusNotFound, "election not found")
		}
		if err != nil {
			return err
		}
		for _, f := range from {
			if phase == f {
				_, err := tx.ExecContext(ctx, `UPDATE box_elections SET phase = $2 WHERE id = $1`, id[:], to)
				return err
			}
		}
		return api.Errorf(http.StatusConflict, "the election is in phase %q", phase)
	})
}

// open opens the voting. Registration must be closed in the public log:
// voting after registration removes the timing link between the two.
func (s *Server) open(_ http.ResponseWriter, r *http.Request) (any, error) {
	id, err := electionID(r)
	if err != nil {
		return nil, err
	}
	rep, err := s.logReport(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if rep.Phase != election.PhaseRegistrationClosed {
		return nil, api.Errorf(http.StatusConflict, "registration is not closed; the log is in phase %q", rep.Phase)
	}
	return nil, s.setPhase(r.Context(), id, PhaseOpen, PhaseSetup)
}

// close stops accepting ballots and publishes them in the log, ordered by
// leaf hash. It can be repeated until the ballots are published.
func (s *Server) close(_ http.ResponseWriter, r *http.Request) (any, error) {
	id, err := electionID(r)
	if err != nil {
		return nil, err
	}
	ctx := r.Context()
	if err := s.setPhase(ctx, id, PhaseClosed, PhaseOpen, PhaseClosed); err != nil {
		return nil, err
	}
	rep, err := s.logReport(ctx, id)
	if err != nil {
		return nil, err
	}
	// If an earlier close published the ballots and failed afterwards, the
	// log is already past the registration.
	if rep.Phase == election.PhaseRegistrationClosed {
		rows, err := s.DB.QueryContext(ctx, `SELECT ballot FROM box_ballots WHERE election = $1`, id[:])
		if err != nil {
			return nil, err
		}
		defer func() { _ = rows.Close() }()
		var ballots []election.Ballot
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return nil, err
			}
			var b election.Ballot
			if err := canon.Unmarshal(raw, &b); err != nil {
				return nil, err
			}
			ballots = append(ballots, b)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		records, err := election.BallotRecords(ballots)
		if err != nil {
			return nil, err
		}
		if _, err := api.AppendRecords(ctx, s.Log, id, rep.Log.Entries, records); err != nil {
			return nil, fmt.Errorf("log: %w", err)
		}
	}
	return nil, s.setPhase(ctx, id, PhasePublished, PhaseClosed)
}

func (s *Server) cast(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := electionID(r)
	if err != nil {
		return nil, err
	}
	var b election.Ballot
	if err := api.Read(w, r, &b); err != nil {
		return nil, api.Errorf(http.StatusBadRequest, "%v", err)
	}
	raw, err := canon.Marshal(b)
	if err != nil {
		return nil, err
	}
	ctx := r.Context()
	var receipt api.Receipt
	err = api.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		var phase string
		var rawManifest []byte
		// The shared lock keeps the phase until this ballot is stored.
		err := tx.QueryRowContext(ctx, `SELECT phase, manifest FROM box_elections WHERE id = $1 FOR SHARE`, id[:]).
			Scan(&phase, &rawManifest)
		if errors.Is(err, sql.ErrNoRows) {
			return api.Errorf(http.StatusNotFound, "election not found")
		}
		if err != nil {
			return err
		}
		if phase != PhaseOpen {
			return api.Errorf(http.StatusConflict, "the voting is not open")
		}
		var m publog.Manifest
		if err := canon.Unmarshal(rawManifest, &m); err != nil {
			return err
		}
		if err := election.CheckBallot(m, id, b); err != nil {
			return api.Errorf(http.StatusForbidden, "%v", err)
		}
		res, err := tx.ExecContext(ctx,
			`INSERT INTO box_ballots (election, credential, ballot) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			id[:], b.CredentialKey, raw)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			// The same ballot again gets its receipt again, so that a voter
			// whose connection broke can retry. Another ballot is refused.
			var stored []byte
			if err := tx.QueryRowContext(ctx,
				`SELECT ballot FROM box_ballots WHERE election = $1 AND credential = $2`, id[:], b.CredentialKey).Scan(&stored); err != nil {
				return err
			}
			if !bytes.Equal(stored, raw) {
				return api.Errorf(http.StatusConflict, "this credential has already voted")
			}
		}
		if m.ReceiptMode != publog.ReceiptFull {
			return nil
		}
		var private []byte
		if err := tx.QueryRowContext(ctx, `SELECT private FROM box_keys WHERE election = $1`, id[:]).Scan(&private); err != nil {
			return err
		}
		leaf, err := election.BallotLeaf(b)
		if err != nil {
			return err
		}
		receipt.Receipt, err = ballot.SignReceipt(ed25519.PrivateKey(private), id, leaf)
		return err
	})
	return receipt, err
}

func (s *Server) status(_ http.ResponseWriter, r *http.Request) (any, error) {
	id, err := electionID(r)
	if err != nil {
		return nil, err
	}
	var st api.Status
	err = s.DB.QueryRowContext(r.Context(),
		`SELECT e.phase, (SELECT count(*) FROM box_ballots b WHERE b.election = e.id) FROM box_elections e WHERE e.id = $1`, id[:]).
		Scan(&st.Phase, &st.Cast)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, api.Errorf(http.StatusNotFound, "election not found")
	}
	return st, err
}

// ClientHash returns the hash of a client bundle: SHA-256 over the
// canonical encoding of the array of [name, SHA-256 of the content] of all
// files of the directory, sorted by name. The manifest publishes it, so
// that anyone can compare the served client with a reproducible build.
func ClientHash(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir) // sorted by name
	if err != nil {
		return nil, err
	}
	var files []any
	for _, e := range entries {
		if e.IsDir() {
			return nil, fmt.Errorf("ballotbox: the client bundle must be flat, but %s is a directory", e.Name())
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // the directory is set by the operator
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		files = append(files, []any{e.Name(), sum[:]})
	}
	encoded, err := canon.Marshal(files)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(encoded)
	return sum[:], nil
}
