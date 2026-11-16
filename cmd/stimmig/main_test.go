package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTallyCommand(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "m.json")
	ballots := filepath.Join(dir, "b.json")
	if err := os.WriteFile(manifest, []byte(`{"candidates":["A","B"],"method":"schulze"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ballots, []byte(`[[["A"],["B"]],[["A"]],[["B"]]]`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"tally", "-manifest", manifest, "-ballots", ballots}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"winners": [`) || !strings.Contains(out.String(), `"A"`) {
		t.Errorf("output: %s", out.String())
	}
	if code := run([]string{"nonsense"}, &out, &errOut); code != 2 {
		t.Errorf("exit %d for an unknown command", code)
	}
	if code := run(nil, &out, &errOut); code != 2 {
		t.Errorf("exit %d without a command", code)
	}
}

const goldenExport = "../../election/testdata/election-v1.cbor"

func TestVerifyCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"verify", "-json", goldenExport}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{
		"entries      25",
		"ballot               6",
		"phase        complete",
		"eligible     8",
		"issued       7",
		"cast         6",
		"counted      4 (not decryptable 1, against the ballot rules 1, abstentions 0)",
		"winners      A",
		"OK: the log is valid and the recomputed tally equals the logged result.",
		"entry 0 (manifest): {",
		`"title": "Board election"`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestVerifyCommandFails(t *testing.T) {
	data, err := os.ReadFile(goldenExport)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 1
	bad := filepath.Join(t.TempDir(), "bad.cbor")
	if err := os.WriteFile(bad, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"verify", bad}, &out, &errOut); code != 1 {
		t.Fatalf("exit %d for a changed export", code)
	}
	if !strings.Contains(errOut.String(), "FAILED") || strings.Contains(out.String(), "OK") {
		t.Errorf("stdout %q, stderr %q", out.String(), errOut.String())
	}
	if code := run([]string{"verify"}, &out, &errOut); code != 2 {
		t.Errorf("exit %d without a file", code)
	}
	if code := run([]string{"verify", filepath.Join(t.TempDir(), "missing")}, &out, &errOut); code != 1 {
		t.Errorf("exit %d for a missing file", code)
	}
}

func TestReadVoters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "voters.txt")
	content := " Ada@Example.org \n\noidc:https://idp.example#User-42\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	roll, err := readVoters(path)
	if err != nil || len(roll.Voters) != 2 {
		t.Fatalf("%+v, %v", roll, err)
	}
	if v := roll.Voters[0]; v.Provider != "email" || v.Subject != "ada@example.org" {
		t.Errorf("email voter: %+v", v)
	}
	// OpenID Connect subjects keep their case.
	if v := roll.Voters[1]; v.Provider != "oidc" || v.Subject != "https://idp.example#User-42" {
		t.Errorf("oidc voter: %+v", v)
	}
}

func TestServiceTokensMustDiffer(t *testing.T) {
	t.Setenv("STIMMIG_DATABASE_URL", "postgres://unused")
	t.Setenv("STIMMIG_ADMIN_TOKEN", "same")
	t.Setenv("STIMMIG_REGISTRAR_TOKEN", "same")
	t.Setenv("STIMMIG_BALLOTBOX_TOKEN", "other")
	var out, errOut bytes.Buffer
	if code := run([]string{"log"}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "must be different") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
}

func TestListenAndServeFinishesRequestsInFlight(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	srv := &http.Server{
		Addr: "127.0.0.1:0",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(started)
			<-release
			_, _ = w.Write([]byte("done"))
		}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- listenAndServeOn(ctx, srv, ln, 5*time.Second) }()

	body := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String()) //nolint:noctx // test
		if err != nil {
			body <- err.Error()
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		body <- string(b)
	}()
	<-started
	cancel() // SIGTERM
	select {
	case err := <-served:
		t.Fatalf("stopped with a request in flight: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if got := <-body; got != "done" {
		t.Fatalf("response %q", got)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
}
