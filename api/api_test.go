package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/internal/testdb"
)

var ctx = context.Background()

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

func TestMigrate(t *testing.T) {
	db := testdb.Open(t)
	steps := []string{`CREATE TABLE IF NOT EXISTS t (a int); INSERT INTO t VALUES (1)`}
	count := func() (n int) {
		if err := db.QueryRow(`SELECT count(*) FROM t`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if err := Migrate(ctx, db, "svc", steps); err != nil {
		t.Fatal(err)
	}
	// A step runs once, however often the service starts.
	if err := Migrate(ctx, db, "svc", steps); err != nil || count() != 1 {
		t.Fatalf("second start: %d rows, %v", count(), err)
	}
	// A later step runs once, after the first.
	steps = append(steps, `ALTER TABLE t ADD COLUMN b text NOT NULL DEFAULT 'x'; INSERT INTO t (a, b) VALUES (2, 'y')`)
	for i := 0; i < 2; i++ {
		if err := Migrate(ctx, db, "svc", steps); err != nil || count() != 2 {
			t.Fatalf("start %d: %d rows, %v", i, count(), err)
		}
	}
	// Services have their own version numbers.
	if err := Migrate(ctx, db, "other", []string{`CREATE TABLE IF NOT EXISTS u (a int)`}); err != nil {
		t.Fatal(err)
	}
	// A failing step changes nothing and is not recorded.
	bad := append(append([]string{}, steps...), `INSERT INTO t (a) VALUES (3); SELECT * FROM missing_table`)
	if err := Migrate(ctx, db, "svc", bad); err == nil {
		t.Fatal("failing step accepted")
	}
	if count() != 2 {
		t.Fatal("a failed step left changes behind")
	}
	// Starting together is safe.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Migrate(ctx, db, "parallel", []string{`CREATE TABLE IF NOT EXISTS p (a int); INSERT INTO p VALUES (1)`}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM p`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("parallel start: %d rows, %v", n, err)
	}
}

func TestReadLimit(t *testing.T) {
	var out map[string]int
	small, _ := canon.Marshal(map[string]int{"a": 1})
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(small))
	if err := ReadLimit(httptest.NewRecorder(), r, &out, 64); err != nil || out["a"] != 1 {
		t.Fatalf("small body: %v, %v", out, err)
	}
	r = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, 65)))
	if err := ReadLimit(httptest.NewRecorder(), r, &out, 64); err == nil {
		t.Fatal("body over the limit accepted")
	}
}
