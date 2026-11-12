// Package testdb gives tests a PostgreSQL database.
package testdb

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx"
)

// Env names the environment variable with the URL of the test database,
// for example postgres://stimmig:stimmig@localhost/stimmig_test.
const Env = "STIMMIG_TEST_DATABASE_URL"

// Open returns a database handle that works in a fresh schema, which is
// dropped when the test ends. It skips the test if Env is not set.
func Open(t *testing.T) *sql.DB {
	t.Helper()
	base := os.Getenv(Env)
	if base == "" {
		t.Skipf("%s is not set", Env)
	}
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	schema := "test_" + hex.EncodeToString(b[:])
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE")
		_ = admin.Close()
	})
	return db
}
