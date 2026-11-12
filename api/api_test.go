package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORS(t *testing.T) {
	h := CORS(Admin("secret", func(http.ResponseWriter, *http.Request) (any, error) {
		return map[string]int{"ok": 1}, nil
	}))
	// Preflight: any origin, but no Authorization header.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodOptions, "/", nil))
	if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != "*" ||
		w.Header().Get("Access-Control-Allow-Headers") != "Content-Type" {
		t.Fatalf("preflight: %d %v", w.Code, w.Header())
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	ctx := context.Background()
	var out map[string]int
	if err := (&Client{Base: srv.URL, Token: "secret"}).Do(ctx, "GET", "/", nil, &out); err != nil || out["ok"] != 1 {
		t.Fatalf("with token: %v, %v", out, err)
	}
	for _, token := range []string{"", "wrong"} {
		if err := (&Client{Base: srv.URL, Token: token}).Do(ctx, "GET", "/", nil, nil); !IsStatus(err, http.StatusUnauthorized) {
			t.Fatalf("token %q: %v", token, err)
		}
	}
	// An empty configured token authorizes nobody, not even an empty one.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer ")
	if Authorized(r, "") {
		t.Fatal("empty token authorized")
	}
}

func TestHandleHidesInternalErrors(t *testing.T) {
	w := httptest.NewRecorder()
	Handle(func(http.ResponseWriter, *http.Request) (any, error) {
		return nil, context.DeadlineExceeded
	})(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusInternalServerError || w.Body.String() != "internal error\n" {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	Handle(func(http.ResponseWriter, *http.Request) (any, error) {
		return nil, Errorf(http.StatusConflict, "phase %q", "open")
	})(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusConflict || w.Body.String() != "phase \"open\"\n" {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
}
