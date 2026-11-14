// Package registrar implements the registrar service: it authenticates
// voters through identity providers and blind-signs one credential per
// roll entry (SPEC.md sections 5.1 and 10). It also holds the election
// private key until the close and runs the tally.
//
// The registrar never learns which credential it signs, and it stores no
// link between a voter and a ballot.
package registrar

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	_ "embed" // for the schema
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ansiwen/stimmig/api"
	"github.com/ansiwen/stimmig/ballot"
	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/credential"
	"github.com/ansiwen/stimmig/election"
	"github.com/ansiwen/stimmig/identity"
	"github.com/ansiwen/stimmig/keystore"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/publog"
)

//go:embed schema.sql
var schema string

// SessionValidity is how long a voter has to log in.
const SessionValidity = time.Hour

const (
	phaseSetup  = "setup"  // no roll yet
	phaseOpen   = "open"   // credentials are issued
	phaseClosed = "closed" // registration is closed
)

// Server is the HTTP API of the registrar.
//
//	POST /v1/keys                     admin   create the keys of an election
//	POST /v1/elections                admin   register an election by its manifest
//	PUT  /v1/elections/{id}/roll      admin   publish the roll, open registration
//	POST /v1/elections/{id}/close     admin   close registration
//	POST /v1/elections/{id}/tally     admin   publish key, plaintexts and result
//	POST /v1/elections/{id}/sessions  voter   start a registration
//	GET  /v1/callback/{provider}      voter   return from the identity provider; asks for the code
//	POST /v1/confirm                  voter   check the code, issue the credential
//	GET  /v1/sessions/{session}       voter   fetch the blind signature
type Server struct {
	DB *sql.DB
	// Log is the log service, with the registrar's writer token.
	Log        *api.Client
	AdminToken string
	// Providers are the identity providers by their ID.
	Providers map[string]identity.Provider
	// Keys encrypts the private keys at rest. Nil stores them in clear.
	Keys keystore.Sealer
	// Secret authenticates the step between login and confirmation. All
	// replicas share it.
	Secret []byte
}

// sealer returns the key store, or the unencrypted one if none is set.
func (s *Server) sealer() keystore.Sealer {
	if s.Keys == nil {
		return keystore.Plain{}
	}
	return s.Keys
}

// Init creates the tables if they are missing.
func (s *Server) Init(ctx context.Context) error {
	return api.Migrate(ctx, s.DB, schema)
}

// Handler returns the routes of the service.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/keys", s.admin(s.newKeys))
	mux.HandleFunc("POST /v1/elections", s.admin(s.create))
	mux.HandleFunc("PUT /v1/elections/{id}/roll", s.admin(s.roll))
	mux.HandleFunc("POST /v1/elections/{id}/close", s.admin(s.close))
	mux.HandleFunc("POST /v1/elections/{id}/tally", s.admin(s.tally))
	mux.HandleFunc("POST /v1/elections/{id}/sessions", api.Handle(s.newSession))
	mux.HandleFunc("GET /v1/callback/{provider}", s.callback)
	mux.HandleFunc("POST /v1/confirm", s.confirm)
	mux.HandleFunc("GET /v1/sessions/{session}", api.Handle(s.credential))
	for id, p := range s.Providers {
		if h, ok := p.(http.Handler); ok {
			mux.Handle("/v1/identity/"+id, h)
		}
	}
	return api.CORS(mux)
}

func (s *Server) admin(fn func(w http.ResponseWriter, r *http.Request) (any, error)) http.HandlerFunc {
	return api.Admin(s.AdminToken, fn)
}

func electionID(r *http.Request) (merkle.Hash, error) {
	id, err := api.ElectionID(r)
	if err != nil {
		return id, api.Errorf(http.StatusBadRequest, "election ID: %v", err)
	}
	return id, nil
}

// newKeys creates the issuing key and the election key of one election.
// An issuing key must not serve two elections: the registrar signs blindly
// and could not tell for which election a credential is.
func (s *Server) newKeys(_ http.ResponseWriter, r *http.Request) (any, error) {
	issuing, err := credential.GenerateIssuingKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	issuingPublic, err := credential.MarshalIssuingKey(&issuing.PublicKey)
	if err != nil {
		return nil, err
	}
	electionPublic, electionPrivate, err := ballot.GenerateElectionKey()
	if err != nil {
		return nil, err
	}
	issuingSealed, err := s.sealer().Seal(x509.MarshalPKCS1PrivateKey(issuing), issuingPublic)
	if err != nil {
		return nil, err
	}
	electionSealed, err := s.sealer().Seal(electionPrivate, electionPublic)
	if err != nil {
		return nil, err
	}
	_, err = s.DB.ExecContext(r.Context(),
		`INSERT INTO reg_keys (issuing_public, issuing_private, election_public, election_private) VALUES ($1, $2, $3, $4)`,
		issuingPublic, issuingSealed, electionPublic, electionSealed)
	return api.RegistrarKeys{IssuingKey: issuingPublic, ElectionKey: electionPublic}, err
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
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	err = api.InTx(r.Context(), s.DB, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(r.Context(),
			`UPDATE reg_keys SET election = $3 WHERE issuing_public = $1 AND election_public = $2 AND election IS NULL`,
			m.IssuingKey, m.ElectionKey, id[:])
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return api.Errorf(http.StatusBadRequest, "the keys of the manifest are unknown or already in use")
		}
		_, err = tx.ExecContext(r.Context(),
			`INSERT INTO reg_elections (id, manifest, salt, phase) VALUES ($1, $2, $3, $4)`, id[:], raw, salt, phaseSetup)
		return err
	})
	return api.Created{ElectionID: id[:]}, err
}

// rollReference is the pseudonym of a voter in the public roll. The salt
// is secret, so that nobody can test whether a known address is on the
// roll.
func rollReference(salt []byte, provider, subject string) []byte {
	msg, _ := canon.Marshal([]any{"stimmig-roll-v1", salt, provider, subject})
	h := sha256.Sum256(msg)
	return h[:]
}

// state is the row of an election, locked for the transaction.
type state struct {
	id      merkle.Hash
	salt    []byte
	phase   string
	issued  uint64
	logSize uint64
}

// lock reads the election row and locks it until the transaction ends.
// The lock serialises everything that appends to the log.
func lock(ctx context.Context, tx *sql.Tx, id merkle.Hash) (state, error) {
	st := state{id: id}
	err := tx.QueryRowContext(ctx,
		`SELECT salt, phase, issued, log_size FROM reg_elections WHERE id = $1 FOR UPDATE`, id[:]).
		Scan(&st.salt, &st.phase, &st.issued, &st.logSize)
	if errors.Is(err, sql.ErrNoRows) {
		return st, api.Errorf(http.StatusNotFound, "election not found")
	}
	return st, err
}

// logAppend appends records to the public log and stores the new state.
//
// shortcut: if the log append succeeds and this transaction then fails to commit, the stored log size is behind the log and every later append is refused with a conflict until an operator repairs the row; nothing wrong is ever logged. Reconcile with the log automatically when this happens in practice.
func (s *Server) logAppend(ctx context.Context, tx *sql.Tx, st state, records ...publog.Record) error {
	if _, err := api.AppendRecords(ctx, s.Log, st.id, st.logSize, records); err != nil {
		return fmt.Errorf("log: %w", err)
	}
	_, err := tx.ExecContext(ctx, `UPDATE reg_elections SET phase = $2, issued = $3, log_size = $4 WHERE id = $1`,
		st.id[:], st.phase, int64(st.issued), int64(st.logSize)+int64(len(records))) //nolint:gosec // counts fit in int64
	return err
}

func (s *Server) roll(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := electionID(r)
	if err != nil {
		return nil, err
	}
	var roll api.Roll
	if err := api.Read(w, r, &roll); err != nil {
		return nil, api.Errorf(http.StatusBadRequest, "%v", err)
	}
	ctx := r.Context()
	return nil, api.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		st, err := lock(ctx, tx, id)
		if err != nil {
			return err
		}
		if st.phase != phaseSetup {
			return api.Errorf(http.StatusConflict, "the roll is already published")
		}
		var refs [][]byte
		for _, v := range roll.Voters {
			if _, ok := s.Providers[v.Provider]; !ok || v.Subject == "" {
				return api.Errorf(http.StatusBadRequest, "voter with unknown provider %q or empty subject", v.Provider)
			}
			ref := rollReference(st.salt, v.Provider, v.Subject)
			res, err := tx.ExecContext(ctx,
				`INSERT INTO reg_roll (election, ref) VALUES ($1, $2) ON CONFLICT DO NOTHING`, id[:], ref)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 1 { // a voter listed twice counts once
				refs = append(refs, ref)
			}
		}
		st.phase = phaseOpen
		rec, err := election.RollRecord(refs)
		if err != nil {
			return err
		}
		return s.logAppend(ctx, tx, st, rec)
	})
}

func (s *Server) close(_ http.ResponseWriter, r *http.Request) (any, error) {
	id, err := electionID(r)
	if err != nil {
		return nil, err
	}
	ctx := r.Context()
	return nil, api.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		st, err := lock(ctx, tx, id)
		if err != nil {
			return err
		}
		if st.phase != phaseOpen {
			return api.Errorf(http.StatusConflict, "registration is not open")
		}
		st.phase = phaseClosed
		return s.logAppend(ctx, tx, st, publog.Record{
			Type: publog.TypeRegistrationClose, Body: election.RegistrationClose{Issued: st.issued},
		})
	})
}

// tally verifies the public log, decrypts the ballots and appends the key,
// the plaintexts and the result. Repeating it returns the logged result.
func (s *Server) tally(_ http.ResponseWriter, r *http.Request) (any, error) {
	id, err := electionID(r)
	if err != nil {
		return nil, err
	}
	ctx := r.Context()
	export, err := api.Export(ctx, s.Log, id)
	if err != nil {
		return nil, fmt.Errorf("log: %w", err)
	}
	rep, err := election.Verify(bytes.NewReader(export), nil)
	if err != nil {
		return nil, fmt.Errorf("the log does not verify: %w", err)
	}
	switch rep.Phase {
	case election.PhaseComplete:
		return rep.Result, nil
	case election.PhaseVotingClosed:
	default:
		return nil, api.Errorf(http.StatusConflict, "the voting is not closed; the log is in phase %q", rep.Phase)
	}
	var public, sealed []byte
	err = s.DB.QueryRowContext(ctx, `SELECT election_public, election_private FROM reg_keys WHERE election = $1`, id[:]).Scan(&public, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, api.Errorf(http.StatusNotFound, "election not found")
	}
	if err != nil {
		return nil, err
	}
	private, err := s.sealer().Open(sealed, public)
	if err != nil {
		return nil, err
	}
	records, res, err := election.TallyRecords(rep.Log.Manifest, id, private, rep.Ballots, rep.BallotIndexes)
	if err != nil {
		return nil, err
	}
	if _, err := api.AppendRecords(ctx, s.Log, id, rep.Log.Entries, records); err != nil {
		return nil, fmt.Errorf("log: %w", err)
	}
	return res, nil
}

func (s *Server) newSession(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := electionID(r)
	if err != nil {
		return nil, err
	}
	var req api.SessionRequest
	if err := api.Read(w, r, &req); err != nil {
		return nil, api.Errorf(http.StatusBadRequest, "%v", err)
	}
	if req.Provider == "" && len(s.Providers) == 1 {
		for p := range s.Providers {
			req.Provider = p
		}
	}
	provider, ok := s.Providers[req.Provider]
	if !ok {
		return nil, api.Errorf(http.StatusBadRequest, "unknown identity provider %q", req.Provider)
	}
	ctx := r.Context()
	var phase string
	var issuingPublic []byte
	err = s.DB.QueryRowContext(ctx,
		`SELECT e.phase, k.issuing_public FROM reg_elections e JOIN reg_keys k ON k.election = e.id WHERE e.id = $1`, id[:]).
		Scan(&phase, &issuingPublic)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, api.Errorf(http.StatusNotFound, "election not found")
	}
	if err != nil {
		return nil, err
	}
	if phase != phaseOpen {
		return nil, api.Errorf(http.StatusConflict, "registration is not open")
	}
	key, err := credential.ParseIssuingKey(issuingPublic)
	if err != nil {
		return nil, err
	}
	if len(req.Blinded) != key.Size() {
		return nil, api.Errorf(http.StatusBadRequest, "the blinded value must have %d bytes", key.Size())
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	session := hex.EncodeToString(token)
	n, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
	if err != nil {
		return nil, err
	}
	code := fmt.Sprintf("%08d", n)
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO reg_sessions (id, election, blinded, code, expires) VALUES ($1, $2, $3, $4, $5)`,
		session, id[:], req.Blinded, code, time.Now().Add(SessionValidity)); err != nil {
		return nil, err
	}
	url, err := provider.Begin(ctx, hex.EncodeToString(id[:]), session)
	if err != nil {
		return nil, err
	}
	return api.Session{Session: session, URL: url, Code: code[:4] + " " + code[4:]}, nil
}

// session returns the election and the blinded value of a live session.
func (s *Server) session(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, session string) (id merkle.Hash, blinded []byte, err error) {
	var rawID []byte
	err = q.QueryRowContext(ctx,
		`SELECT election, blinded FROM reg_sessions WHERE id = $1 AND expires > now()`, session).Scan(&rawID, &blinded)
	if errors.Is(err, sql.ErrNoRows) {
		return id, nil, api.Errorf(http.StatusNotFound, "the session is unknown or has expired")
	}
	if err != nil {
		return id, nil, err
	}
	return merkle.Hash(rawID), blinded, nil
}

// Eligible reports whether a subject is on the roll of the election of a
// session, while registration is open. Identity providers use it to decide
// whether to contact a subject.
func (s *Server) Eligible(ctx context.Context, session, provider, subject string) bool {
	id, _, err := s.session(ctx, s.DB, session)
	if err != nil {
		return false
	}
	var salt []byte
	var phase string
	if err := s.DB.QueryRowContext(ctx, `SELECT salt, phase FROM reg_elections WHERE id = $1`, id[:]).Scan(&salt, &phase); err != nil || phase != phaseOpen {
		return false
	}
	var found bool
	err = s.DB.QueryRowContext(ctx, `SELECT true FROM reg_roll WHERE election = $1 AND ref = $2`,
		id[:], rollReference(salt, provider, subject)).Scan(&found)
	return err == nil && found
}

// ConfirmValidity is how long the voter has to type the code after the
// login.
const ConfirmValidity = 10 * time.Minute

// MaxConfirmAttempts is the number of codes a session may try.
const MaxConfirmAttempts = 5

// confirmToken carries an authenticated login from the callback to the
// confirmation.
type confirmToken struct {
	_        struct{} `cbor:",toarray"`
	Context  string
	Session  string
	Provider string
	Subject  string
	Expires  int64
}

const confirmContext = "stimmig-confirm-v1"

func (s *Server) mac(msg []byte) []byte {
	h := hmac.New(sha256.New, s.Secret)
	h.Write(msg)
	return h.Sum(nil)
}

var pages = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Voting credential</title></head><body>
{{if .Token}}<h1>Enter your confirmation code</h1>
<p>You are logged in. Your voting client shows a confirmation code of 8 digits. Enter it to receive your voting credential in that client.</p>
<p><strong>If you did not start this in a voting client of your own, close this page.</strong> Somebody else may be trying to obtain your credential.</p>
<form method="post" action="/v1/confirm">
<input type="hidden" name="token" value="{{.Token}}">
<label for="code">Confirmation code</label>
<input id="code" name="code" inputmode="numeric" autocomplete="off" required>
<button type="submit">Receive credential</button>
</form>
{{else}}<h1>Your voting credential is issued</h1>
<p role="status">Return to your voting client.</p>
<p>Your entry in the public electoral roll is <code>{{.Ref}}</code>.</p>
{{end}}</body></html>`))

func page(w http.ResponseWriter, data map[string]string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'")
	_ = pages.Execute(w, data)
}

// callback completes the login. It does not issue the credential yet: the
// voter must type the code that their own voting client shows. Otherwise
// somebody could start a registration, send the login link to a voter and
// receive that voter's credential.
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	api.Handle(func(w http.ResponseWriter, r *http.Request) (any, error) {
		provider, ok := s.Providers[r.PathValue("provider")]
		if !ok {
			return nil, api.Errorf(http.StatusNotFound, "unknown identity provider")
		}
		subject, err := provider.Complete(r.Context(), r)
		if err != nil {
			return nil, api.Errorf(http.StatusForbidden, "%v", err)
		}
		session := r.URL.Query().Get("state")
		if _, _, err := s.session(r.Context(), s.DB, session); err != nil {
			return nil, err
		}
		msg, err := canon.Marshal(confirmToken{
			Context: confirmContext, Session: session, Provider: subject.Provider, Subject: subject.StableID,
			Expires: time.Now().Add(ConfirmValidity).Unix(),
		})
		if err != nil {
			return nil, err
		}
		page(w, map[string]string{"Token": hex.EncodeToString(msg) + "." + hex.EncodeToString(s.mac(msg))})
		return nil, nil
	})(w, r)
}

// confirm checks the code and issues the credential.
func (s *Server) confirm(w http.ResponseWriter, r *http.Request) {
	api.Handle(func(w http.ResponseWriter, r *http.Request) (any, error) {
		rawMsg, rawMAC, _ := strings.Cut(r.PostFormValue("token"), ".")
		msg, err1 := hex.DecodeString(rawMsg)
		mac, err2 := hex.DecodeString(rawMAC)
		var token confirmToken
		if err1 != nil || err2 != nil || len(s.Secret) == 0 || !hmac.Equal(mac, s.mac(msg)) ||
			canon.Unmarshal(msg, &token) != nil || token.Context != confirmContext {
			return nil, api.Errorf(http.StatusForbidden, "invalid confirmation")
		}
		if time.Now().Unix() > token.Expires {
			return nil, api.Errorf(http.StatusForbidden, "the confirmation has expired; log in again")
		}
		// Count the attempt first, so that codes cannot be guessed.
		var code string
		err := s.DB.QueryRowContext(r.Context(),
			`UPDATE reg_sessions SET attempts = attempts + 1 WHERE id = $1 AND attempts < $2 AND expires > now() RETURNING code`,
			token.Session, MaxConfirmAttempts).Scan(&code)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, api.Errorf(http.StatusForbidden, "too many wrong codes, or the session has expired; start again in your voting client")
		}
		if err != nil {
			return nil, err
		}
		typed := strings.Join(strings.Fields(r.PostFormValue("code")), "")
		if subtle.ConstantTimeCompare([]byte(typed), []byte(code)) != 1 {
			return nil, api.Errorf(http.StatusForbidden, "wrong confirmation code; go back and enter the code that your voting client shows")
		}
		ref, err := s.issue(r.Context(), token.Session, identity.Subject{Provider: token.Provider, StableID: token.Subject})
		if err != nil {
			return nil, err
		}
		page(w, map[string]string{"Ref": hex.EncodeToString(ref)})
		return nil, nil
	})(w, r)
}

// issue blind-signs the credential of a session for an authenticated
// subject and logs the issuance. It issues one credential per roll entry;
// repeating it for the same session changes nothing.
func (s *Server) issue(ctx context.Context, session string, subject identity.Subject) (ref []byte, err error) {
	err = api.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		id, blinded, err := s.session(ctx, tx, session)
		if err != nil {
			return err
		}
		st, err := lock(ctx, tx, id)
		if err != nil {
			return err
		}
		if st.phase != phaseOpen {
			return api.Errorf(http.StatusConflict, "registration is not open")
		}
		ref = rollReference(st.salt, subject.Provider, subject.StableID)
		var seq sql.NullInt64
		var issuedFor []byte
		err = tx.QueryRowContext(ctx, `SELECT seq, blinded FROM reg_roll WHERE election = $1 AND ref = $2`, id[:], ref).
			Scan(&seq, &issuedFor)
		if errors.Is(err, sql.ErrNoRows) {
			return api.Errorf(http.StatusForbidden, "you are not on the electoral roll of this election")
		}
		if err != nil {
			return err
		}
		if seq.Valid {
			if !bytes.Equal(issuedFor, blinded) {
				// Lost credentials are not reissued (SPEC.md section 5.1).
				return api.Errorf(http.StatusConflict, "a credential was already issued for you")
			}
		} else {
			var public, sealed []byte
			if err := tx.QueryRowContext(ctx, `SELECT issuing_public, issuing_private FROM reg_keys WHERE election = $1`, id[:]).Scan(&public, &sealed); err != nil {
				return err
			}
			private, err := s.sealer().Open(sealed, public)
			if err != nil {
				return err
			}
			key, err := x509.ParsePKCS1PrivateKey(private)
			if err != nil {
				return err
			}
			sig, err := credential.Issue(key, blinded)
			if err != nil {
				return api.Errorf(http.StatusBadRequest, "%v", err)
			}
			if _, err := tx.ExecContext(ctx,
				`UPDATE reg_roll SET seq = $3, blinded = $4, blind_sig = $5 WHERE election = $1 AND ref = $2`,
				id[:], ref, int64(st.issued), blinded, sig); err != nil { //nolint:gosec // counts fit in int64
				return err
			}
			rec := publog.Record{Type: publog.TypeIssuance, Body: election.Issuance{RollReference: ref, Sequence: st.issued}}
			st.issued++
			if err := s.logAppend(ctx, tx, st, rec); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE reg_sessions SET ref = $2 WHERE id = $1`, session, ref)
		return err
	})
	return ref, err
}

// credential returns the blind signature of a session after the login.
func (s *Server) credential(_ http.ResponseWriter, r *http.Request) (any, error) {
	var c api.Credential
	err := s.DB.QueryRowContext(r.Context(),
		`SELECT r.blind_sig, r.ref FROM reg_sessions s
		 JOIN reg_roll r ON r.election = s.election AND r.ref = s.ref AND r.blinded = s.blinded
		 WHERE s.id = $1 AND s.expires > now()`, r.PathValue("session")).Scan(&c.BlindSignature, &c.RollReference)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, api.Errorf(http.StatusNotFound, "no credential yet: the login is not complete, or the session is unknown")
	}
	return c, err
}
