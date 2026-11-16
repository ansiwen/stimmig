package admin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strings"

	"github.com/ansiwen/stimmig/api"
	"github.com/ansiwen/stimmig/merkle"
)

//go:embed static
var staticFiles embed.FS

// maxBody limits what the page can send: a roll of some hundred thousand
// voters fits.
const maxBody = 16 << 20

// Handler serves the admin web page and its JSON interface. The page is
// public (it holds no secret); every call of the interface needs the token of
// the admin web page in an Authorization header. The tokens of the three
// services stay with the server. A page that sends the token only in a
// header, and no cookie, cannot be driven by another site.
func (c *Client) Handler(token string) http.Handler {
	want := sha256.Sum256([]byte(token))
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFiles, "static")
	mux.Handle("GET /", http.FileServerFS(static))

	// api registers a JSON call. fn returns the response, or an error that
	// carries its status.
	call := func(pattern string, fn func(r *http.Request) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			got := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
			if token == "" || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "wrong or missing token"})
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
			res, err := fn(r)
			if err != nil {
				var se *api.StatusError
				code := http.StatusBadGateway
				switch {
				case errors.As(err, &se) && se.Code != http.StatusUnauthorized && se.Code != http.StatusForbidden:
					// 401 and 403 of a service mean a wrong service token, which is
					// not the page user's mistake.
					code = se.Code
				case errors.As(err, new(badRequest)):
					code = http.StatusBadRequest
				}
				writeJSON(w, code, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, res)
		})
	}
	election := func(r *http.Request) (merkle.Hash, error) {
		id, err := api.ParseHash(r.PathValue("id"))
		if err != nil {
			return id, badRequest{err}
		}
		return id, nil
	}
	body := func(r *http.Request, v any) error {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			return badRequest{err}
		}
		return nil
	}

	call("GET /api/elections", func(r *http.Request) (any, error) {
		list, err := c.List(r.Context())
		return map[string]any{"elections": list}, err
	})
	call("POST /api/preview", func(r *http.Request) (any, error) {
		var def Definition
		if err := body(r, &def); err != nil {
			return nil, err
		}
		possible, err := Preview(def)
		if err != nil {
			return nil, badRequest{err}
		}
		return map[string]string{"possible_ballots": possible.String()}, nil
	})
	call("POST /api/elections", func(r *http.Request) (any, error) {
		var def Definition
		if err := body(r, &def); err != nil {
			return nil, err
		}
		if _, err := Preview(def); err != nil {
			return nil, badRequest{err}
		}
		id, err := c.Create(r.Context(), def)
		return map[string]string{"id": hexID(id)}, err
	})
	call("GET /api/elections/{id}", func(r *http.Request) (any, error) {
		id, err := election(r)
		if err != nil {
			return nil, err
		}
		return c.Status(r.Context(), id)
	})
	call("PUT /api/elections/{id}/roll", func(r *http.Request) (any, error) {
		id, err := election(r)
		if err != nil {
			return nil, err
		}
		var in struct {
			Voters string `json:"voters"`
		}
		if err := body(r, &in); err != nil {
			return nil, err
		}
		roll, err := ParseVoters(in.Voters)
		if err != nil {
			return nil, badRequest{err}
		}
		if len(roll.Voters) == 0 {
			return nil, badRequest{errors.New("the roll needs at least one voter, one per line")}
		}
		warning, err := c.Roll(r.Context(), id, roll)
		return map[string]any{"voters": len(roll.Voters), "warning": warning}, err
	})
	steps := map[string]func(context.Context, merkle.Hash) error{
		"close-registration": c.CloseRegistration,
		"open-voting":        c.OpenVoting,
		"close-voting":       c.CloseVoting,
	}
	call("POST /api/elections/{id}/tally", func(r *http.Request) (any, error) {
		id, err := election(r)
		if err != nil {
			return nil, err
		}
		return c.Tally(r.Context(), id)
	})
	call("POST /api/elections/{id}/{step}", func(r *http.Request) (any, error) {
		id, err := election(r)
		if err != nil {
			return nil, err
		}
		step, ok := steps[r.PathValue("step")]
		if !ok {
			return nil, badRequest{errors.New("unknown step")}
		}
		return struct{}{}, step(r.Context(), id)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

// badRequest marks an error as the mistake of the caller.
type badRequest struct{ error }

func (b badRequest) Unwrap() error { return b.error }

func hexID(id merkle.Hash) string { return hex.EncodeToString(id[:]) }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
