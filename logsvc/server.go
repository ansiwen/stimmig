package logsvc

import (
	"bytes"
	"errors"
	"net/http"
	"strconv"

	"github.com/ansiwen/stimmig/api"
	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/publog"
)

// Server is the HTTP API of the log service.
//
//	POST /v1/keys                          admin      create a log key
//	POST /v1/elections                     admin      create a log from a manifest
//	POST /v1/elections/{id}/entries        writers    append entries, sign a tree head
//	GET  /v1/elections/{id}/head           public     newest tree head
//	GET  /v1/elections/{id}/export         public     the complete log
//	GET  /v1/elections/{id}/inclusion      public     ?leaf=<hex>&size=<n>
//	GET  /v1/elections/{id}/consistency    public     ?old=<n>&new=<n>
type Server struct {
	Store *Store
	// AdminToken creates keys and elections.
	AdminToken string
	// RegistrarToken appends the entries of the registration and of the
	// tally, BallotBoxToken those of the voting.
	RegistrarToken string
	BallotBoxToken string
}

// writers lists the entry types that each writer may append.
var writers = map[string][]string{
	"registrar": {
		publog.TypeRollCommit, publog.TypeIssuance, publog.TypeRegistrationClose,
		publog.TypeElectionKey, publog.TypeBallotPlain, publog.TypeResult,
	},
	"ballotbox": {publog.TypeBallot, publog.TypeVotingClose},
}

// Handler returns the routes of the service.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/keys", s.newKey)
	mux.HandleFunc("POST /v1/elections", s.create)
	mux.HandleFunc("POST /v1/elections/{id}/entries", s.appendEntries)
	mux.HandleFunc("GET /v1/elections/{id}/head", s.head)
	mux.HandleFunc("GET /v1/elections/{id}/export", s.export)
	mux.HandleFunc("GET /v1/elections/{id}/inclusion", s.inclusion)
	mux.HandleFunc("GET /v1/elections/{id}/consistency", s.consistency)
	return api.CORS(mux)
}

// fail maps an error to a response.
func fail(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	switch {
	case errors.Is(err, publog.ErrNotFound):
		code = http.StatusNotFound
	case errors.Is(err, publog.ErrSize), errors.Is(err, publog.ErrExists):
		code = http.StatusConflict
	}
	http.Error(w, err.Error(), code)
}

func (s *Server) newKey(w http.ResponseWriter, r *http.Request) {
	if !api.Authorized(r, s.AdminToken) {
		http.Error(w, "admin token required", http.StatusUnauthorized)
		return
	}
	pub, err := s.Store.NewKey(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	api.Write(w, api.LogKey{LogKey: pub})
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	if !api.Authorized(r, s.AdminToken) {
		http.Error(w, "admin token required", http.StatusUnauthorized)
		return
	}
	var m publog.Manifest
	if err := api.Read(w, r, &m); err != nil {
		fail(w, err)
		return
	}
	if err := m.Validate(); err != nil {
		fail(w, err)
		return
	}
	entry, err := publog.EncodeEntry(publog.TypeManifest, m)
	if err != nil {
		fail(w, err)
		return
	}
	key, err := s.Store.Bind(r.Context(), m.LogKey, publog.ElectionID(entry))
	if err != nil {
		fail(w, err)
		return
	}
	l, err := publog.Create(r.Context(), s.Store, key, m, nil)
	if err != nil {
		fail(w, err)
		return
	}
	s.writeHead(w, r, l)
}

func (s *Server) writeHead(w http.ResponseWriter, r *http.Request, l *publog.Log) {
	h, err := l.LastHead(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	api.Write(w, h)
}

// open returns the log named in the path, without a signer.
func (s *Server) open(w http.ResponseWriter, r *http.Request) (*publog.Log, bool) {
	id, err := api.ElectionID(r)
	if err != nil {
		http.Error(w, "election ID: "+err.Error(), http.StatusBadRequest)
		return nil, false
	}
	return publog.Open(s.Store, id, nil, nil), true
}

func (s *Server) appendEntries(w http.ResponseWriter, r *http.Request) {
	var allowed []string
	switch {
	case api.Authorized(r, s.RegistrarToken):
		allowed = writers["registrar"]
	case api.Authorized(r, s.BallotBoxToken):
		allowed = writers["ballotbox"]
	default:
		http.Error(w, "writer token required", http.StatusUnauthorized)
		return
	}
	id, err := api.ElectionID(r)
	if err != nil {
		http.Error(w, "election ID: "+err.Error(), http.StatusBadRequest)
		return
	}
	var req api.Append
	if err := api.Read(w, r, &req); err != nil {
		fail(w, err)
		return
	}
	records := make([]publog.Record, len(req.Entries))
	for i, e := range req.Entries {
		typ, body, err := publog.DecodeEntry(e)
		if err != nil {
			fail(w, err)
			return
		}
		ok := false
		for _, t := range allowed {
			ok = ok || t == typ
		}
		if !ok {
			http.Error(w, "this writer must not append "+typ+" entries", http.StatusForbidden)
			return
		}
		records[i] = publog.Record{Type: typ, Body: canon.Raw(body)}
	}
	signer, err := s.Store.Signer(r.Context(), id)
	if err != nil {
		fail(w, err)
		return
	}
	expect := int64(-1)
	if req.ExpectSize != nil {
		expect = int64(*req.ExpectSize) //nolint:gosec // log sizes fit in int64
	}
	h, err := publog.Open(s.Store, id, signer, nil).AppendAll(r.Context(), expect, records)
	if err != nil {
		fail(w, err)
		return
	}
	api.Write(w, h)
}

func (s *Server) head(w http.ResponseWriter, r *http.Request) {
	if l, ok := s.open(w, r); ok {
		s.writeHead(w, r, l)
	}
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	l, ok := s.open(w, r)
	if !ok {
		return
	}
	// Buffered, so that an error does not leave a broken export behind.
	var buf bytes.Buffer
	if err := l.Export(r.Context(), &buf); err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("Content-Type", api.ContentType)
	_, _ = w.Write(buf.Bytes())
}

func hashes(hs []merkle.Hash) [][]byte {
	out := make([][]byte, len(hs))
	for i, h := range hs {
		out[i] = h[:]
	}
	return out
}

func (s *Server) inclusion(w http.ResponseWriter, r *http.Request) {
	l, ok := s.open(w, r)
	if !ok {
		return
	}
	leaf, err := api.ParseHash(r.URL.Query().Get("leaf"))
	if err != nil {
		http.Error(w, "leaf: "+err.Error(), http.StatusBadRequest)
		return
	}
	size, err := strconv.ParseUint(r.URL.Query().Get("size"), 10, 64)
	if err != nil {
		http.Error(w, "size: "+err.Error(), http.StatusBadRequest)
		return
	}
	leaves, err := s.Store.Leaves(r.Context(), l.ElectionID(), size)
	if err != nil {
		fail(w, err)
		return
	}
	for i, h := range leaves {
		if h == leaf {
			proof, err := merkle.InclusionProof(leaves, uint64(i)) //nolint:gosec // i is not negative
			if err != nil {
				fail(w, err)
				return
			}
			api.Write(w, api.Proof{Index: uint64(i), Hashes: hashes(proof)}) //nolint:gosec // i is not negative
			return
		}
	}
	http.Error(w, "no entry with this leaf hash", http.StatusNotFound)
}

func (s *Server) consistency(w http.ResponseWriter, r *http.Request) {
	l, ok := s.open(w, r)
	if !ok {
		return
	}
	oldSize, err1 := strconv.ParseUint(r.URL.Query().Get("old"), 10, 64)
	newSize, err2 := strconv.ParseUint(r.URL.Query().Get("new"), 10, 64)
	if err1 != nil || err2 != nil {
		http.Error(w, "old and new must be tree sizes", http.StatusBadRequest)
		return
	}
	proof, err := l.ConsistencyProof(r.Context(), oldSize, newSize)
	if err != nil {
		fail(w, err)
		return
	}
	api.Write(w, api.Proof{Hashes: hashes(proof)})
}
