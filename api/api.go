// Package api holds what the HTTP services and their clients share: the
// request and response bodies, and helpers to send them. All bodies are
// canonical CBOR (SPEC.md section 7); errors are plain text.
package api

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/merkle"
)

// ContentType is the media type of all request and response bodies.
const ContentType = "application/cbor"

// MaxBody limits the bodies of requests from the operator and from the
// other services, and the bodies of responses.
// shortcut: the ballots of a close go in one request, so this bounds an election to about 100000 ballots; send the close in chunks when that is not enough.
const MaxBody = 256 << 20

// MaxVoterBody limits the bodies of requests that anybody can send: a
// session request, a ballot or a confirmation. The largest is a ballot of
// about a kilobyte; the margin is for long ballots of large elections.
const MaxVoterBody = 64 << 10

// Read decodes the body of a request from the operator or another service.
func Read(w http.ResponseWriter, r *http.Request, v any) error {
	return ReadLimit(w, r, v, MaxBody)
}

// ReadLimit decodes the body of a request that is at most limit bytes long.
func ReadLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) error {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return err
	}
	return canon.Unmarshal(data, v)
}

// Write sends a response body.
func Write(w http.ResponseWriter, v any) {
	data, err := canon.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	_, _ = w.Write(data)
}

// Authorized reports whether the request carries the bearer token. An empty
// token authorizes nobody.
func Authorized(r *http.Request, token string) bool {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && token != "" && subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

// ElectionID parses the {id} path value of a request.
func ElectionID(r *http.Request) (merkle.Hash, error) {
	return ParseHash(r.PathValue("id"))
}

// ParseHash decodes a hash in hexadecimal.
func ParseHash(s string) (merkle.Hash, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != merkle.HashSize {
		return merkle.Hash{}, errors.New("not a 32-byte hexadecimal value")
	}
	return merkle.Hash(b), nil
}

// StatusError is an error response of a service.
type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%d %s: %s", e.Code, http.StatusText(e.Code), e.Message)
}

// IsStatus reports whether err is an error response with the given code.
func IsStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == code
}

// Client calls one service.
type Client struct {
	// Base is the URL of the service without a trailing slash.
	Base string
	// Token is the bearer token, if the calls need one.
	Token string
	// HTTP may be nil for http.DefaultClient.
	HTTP *http.Client
}

// Do sends a request. in is encoded as the body unless it is nil; the
// response is decoded into out unless it is nil. A response with an error
// status is returned as *StatusError.
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	body, err := c.Raw(ctx, method, path, in)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return canon.Unmarshal(body, out)
}

// Raw is Do without decoding the response.
func (c *Client) Raw(ctx context.Context, method, path string, in any) ([]byte, error) {
	var reqBody io.Reader
	if in != nil {
		data, err := canon.Marshal(in)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, reqBody)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", ContentType)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, &StatusError{Code: resp.StatusCode, Message: strings.TrimSpace(string(body))}
	}
	return body, nil
}

// httpError is an error with its response status.
type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return e.msg }

// Errorf returns an error that Handle answers with the given status and
// message.
func Errorf(code int, format string, a ...any) error {
	return &httpError{code, fmt.Sprintf(format, a...)}
}

// Handle turns a function that returns a response body or an error into a
// handler. Errors that were not made with Errorf are internal: they are
// answered with status 500 and not shown.
func Handle(fn func(w http.ResponseWriter, r *http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out, err := fn(w, r)
		var he *httpError
		switch {
		case errors.As(err, &he):
			http.Error(w, he.msg, he.code)
		case err != nil:
			http.Error(w, "internal error", http.StatusInternalServerError)
		case out != nil:
			Write(w, out)
		}
	}
}

// Admin is Handle for requests that need the admin token.
func Admin(token string, fn func(w http.ResponseWriter, r *http.Request) (any, error)) http.HandlerFunc {
	return Handle(func(w http.ResponseWriter, r *http.Request) (any, error) {
		if !Authorized(r, token) {
			return nil, Errorf(http.StatusUnauthorized, "admin token required")
		}
		return fn(w, r)
	})
}

// InTx runs fn in a database transaction.
func InTx(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// CORS lets pages of other origins call the service. The voting client is
// served from the ballot box and calls the registrar and the log. Requests
// carry no cookies, and the Authorization header is not allowed, so the
// admin calls stay closed to browsers.
func CORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Migrate applies the steps of a service's schema that the database has not
// seen yet, in order, and records them. Step 1 is the first schema; add a
// later change as a new last step and never edit a step that was released.
// Each step is a script of several statements and runs once. A database
// lock makes it safe when several replicas start at once.
func Migrate(ctx context.Context, db *sql.DB, name string, steps []string) error {
	return InTx(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7846446)`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`CREATE TABLE IF NOT EXISTS schema_migrations (name text NOT NULL, version int NOT NULL, PRIMARY KEY (name, version))`); err != nil {
			return err
		}
		for i, step := range steps {
			var done bool
			err := tx.QueryRowContext(ctx, `SELECT true FROM schema_migrations WHERE name = $1 AND version = $2`, name, i+1).Scan(&done)
			if err == nil {
				continue
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if _, err := tx.ExecContext(ctx, step); err != nil { //nolint:gosec // the steps are embedded in the binary
				return fmt.Errorf("api: migration %s %d: %w", name, i+1, err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (name, version) VALUES ($1, $2)`, name, i+1); err != nil {
				return err
			}
		}
		return nil
	})
}
