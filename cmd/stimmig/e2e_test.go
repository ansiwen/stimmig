package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ansiwen/stimmig/api"
	"github.com/ansiwen/stimmig/ballotbox"
	"github.com/ansiwen/stimmig/client"
	"github.com/ansiwen/stimmig/identity"
	"github.com/ansiwen/stimmig/internal/testdb"
	"github.com/ansiwen/stimmig/logsvc"
	"github.com/ansiwen/stimmig/registrar"
)

// outbox collects the mails of the registrar.
type outbox struct {
	mu    sync.Mutex
	links map[string]string // address to login link
}

var linkPattern = regexp.MustCompile(`http://\S+`)

func (o *outbox) Send(_ context.Context, to, _, body string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.links[to] = linkPattern.FindString(body)
	return nil
}

// take waits for the login link mailed to an address.
func (o *outbox) take(t *testing.T, address string) string {
	t.Helper()
	for i := 0; i < 500; i++ {
		o.mu.Lock()
		link := o.links[address]
		delete(o.links, address)
		o.mu.Unlock()
		if link != "" {
			return link
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no mail for %s", address)
	return ""
}

// stimmig runs the command and returns its output. It fails the test
// unless the exit code is the wanted one.
func stimmig(t *testing.T, wantCode int, args ...string) string {
	t.Helper()
	var out, errOut bytes.Buffer
	if code := run(args, &out, &errOut); code != wantCode {
		t.Fatalf("stimmig %s: exit %d, want %d\n%s%s", strings.Join(args, " "), code, wantCode, out.String(), errOut.String())
	}
	return out.String() + errOut.String()
}

// TestElectionFromCommandLine runs complete elections against the three
// services with the admin and client commands.
func TestElectionFromCommandLine(t *testing.T) {
	ctx := context.Background()
	db := testdb.Open(t)
	client.PollInterval = 10 * time.Millisecond

	store, err := logsvc.NewStore(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	logSrv := httptest.NewServer((&logsvc.Server{Store: store, AdminToken: "la", RegistrarToken: "lr", BallotBoxToken: "lb"}).Handler())
	defer logSrv.Close()

	mails := &outbox{links: map[string]string{}}
	regMux := http.NewServeMux()
	regSrv := httptest.NewServer(regMux)
	defer regSrv.Close()
	reg := &registrar.Server{DB: db, Log: &api.Client{Base: logSrv.URL, Token: "lr"}, AdminToken: "ra"}
	reg.Providers = map[string]identity.Provider{"email": &identity.Email{
		BaseURL: regSrv.URL, Secret: []byte("secret"), Mailer: mails,
		Allow: func(ctx context.Context, state, address string) bool {
			return reg.Eligible(ctx, state, "email", address)
		},
	}}
	if err := reg.Init(ctx); err != nil {
		t.Fatal(err)
	}
	regMux.Handle("/", reg.Handler())

	box := &ballotbox.Server{DB: db, Log: &api.Client{Base: logSrv.URL, Token: "lb"}, AdminToken: "ba"}
	if err := box.Init(ctx); err != nil {
		t.Fatal(err)
	}
	boxSrv := httptest.NewServer(box.Handler())
	defer boxSrv.Close()

	t.Setenv("STIMMIG_LOG_URL", logSrv.URL)
	t.Setenv("STIMMIG_REGISTRAR_URL", regSrv.URL)
	t.Setenv("STIMMIG_BALLOTBOX_URL", boxSrv.URL)
	t.Setenv("STIMMIG_LOG_ADMIN_TOKEN", "la")
	t.Setenv("STIMMIG_REGISTRAR_ADMIN_TOKEN", "ra")
	t.Setenv("STIMMIG_BALLOTBOX_ADMIN_TOKEN", "ba")

	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	voters := write("voters.txt", "ada@example.org\nBob@example.org\n\ncleo@example.org\n")

	// register obtains a credential for an address: the client waits while
	// the voter opens the mailed link.
	register := func(id, address string) string {
		state := filepath.Join(dir, id[:8]+address+".json")
		done := make(chan string)
		go func() {
			done <- stimmig(t, 0, "client", "register", "-state", state, "-election", id,
				"-log", logSrv.URL, "-registrar", regSrv.URL, "-ballotbox", boxSrv.URL, "-email", address)
		}()
		resp, err := http.Get(mails.take(t, address)) //nolint:noctx // test
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if out := <-done; !strings.Contains(out, "Credential received") {
			t.Fatalf("register: %s", out)
		}
		return state
	}

	// An election with receipts.
	def := write("election.json", `{"title": "Board election", "tally": {"candidates": ["A", "B", "C"], "method": "schulze", "max_ranks": 2}}`)
	id := strings.TrimSpace(stimmig(t, 0, "admin", "create", "-definition", def))
	stimmig(t, 0, "admin", "roll", "-election", id, "-voters", voters)
	ada, bob := register(id, "ada@example.org"), register(id, "bob@example.org")
	stimmig(t, 1, "client", "register", "-state", ada, "-election", id, "-log", logSrv.URL, "-registrar", regSrv.URL)
	stimmig(t, 1, "admin", "open-voting", "-election", id) // registration is still open
	stimmig(t, 0, "admin", "close-registration", "-election", id)
	stimmig(t, 1, "client", "cast", "-state", ada, "-ranking", "A>B") // voting is not open
	stimmig(t, 0, "admin", "open-voting", "-election", id)
	if out := stimmig(t, 1, "client", "cast", "-state", bob, "-ranking", "A>B>C"); !strings.Contains(out, "not a valid ballot") {
		t.Fatalf("ballot against the rank limit: %s", out)
	}
	stimmig(t, 0, "client", "cast", "-state", ada, "-ranking", "A>B")
	stimmig(t, 0, "client", "cast", "-state", bob, "-ranking", "C = A")
	if out := stimmig(t, 0, "client", "check", "-state", ada); !strings.Contains(out, "not published yet") {
		t.Fatalf("check during the voting: %s", out)
	}
	stimmig(t, 1, "admin", "tally", "-election", id) // voting is still open
	stimmig(t, 0, "admin", "close-voting", "-election", id)
	if out := stimmig(t, 0, "client", "check", "-state", ada); !strings.Contains(out, "not decrypted yet") {
		t.Fatalf("check after the close: %s", out)
	}
	if out := stimmig(t, 0, "admin", "tally", "-election", id); !strings.Contains(out, "winners: A") {
		t.Fatalf("tally: %s", out)
	}
	if out := stimmig(t, 0, "admin", "tally", "-election", id); !strings.Contains(out, "winners: A") {
		t.Fatalf("repeated tally: %s", out)
	}
	if out := stimmig(t, 0, "client", "check", "-state", ada); !strings.Contains(out, "decrypted as: A>B") || !strings.Contains(out, "Winners: A") {
		t.Fatalf("check after the tally: %s", out)
	}
	if out := stimmig(t, 0, "client", "check", "-state", bob); !strings.Contains(out, "decrypted as: C=A") {
		t.Fatalf("check after the tally: %s", out)
	}

	// The standalone verifier agrees.
	export, err := (&api.Client{Base: logSrv.URL}).Raw(ctx, "GET", "/v1/elections/"+id+"/export", nil)
	if err != nil {
		t.Fatal(err)
	}
	out := stimmig(t, 0, "verify", write("export.cbor", string(export)))
	for _, want := range []string{"eligible     3", "issued       2", "cast         2", "counted      2", "winners      A", "OK: the log is valid and the recomputed tally equals the logged result."} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output lacks %q:\n%s", want, out)
		}
	}

	// An election without receipts: after casting, the client keeps
	// neither the credential nor the ballot.
	def = write("none.json", `{"title": "Secret poll", "receipt_mode": "none", "tally": {"candidates": ["yes", "no"], "method": "borda"}}`)
	id = strings.TrimSpace(stimmig(t, 0, "admin", "create", "-definition", def))
	stimmig(t, 0, "admin", "roll", "-election", id, "-voters", voters)
	// Cleo's client stops before she opens the link. The credential is
	// issued when she opens it, and the client picks it up when it runs
	// again, because the state file holds the pending registration.
	cleoState := filepath.Join(dir, id[:8]+"cleo@example.org.json")
	stimmig(t, 1, "client", "register", "-state", cleoState, "-election", id, "-timeout", "300ms",
		"-log", logSrv.URL, "-registrar", regSrv.URL, "-ballotbox", boxSrv.URL, "-email", "cleo@example.org")
	resp, err := http.Get(mails.take(t, "cleo@example.org")) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	cleo := register(id, "cleo@example.org")
	if cleo != cleoState {
		t.Fatal("test uses two state files")
	}
	stimmig(t, 0, "admin", "close-registration", "-election", id)
	stimmig(t, 0, "admin", "open-voting", "-election", id)
	stimmig(t, 0, "client", "cast", "-state", cleo, "-ranking", "yes")
	state, _ := os.ReadFile(cleo)
	if strings.Contains(string(state), "credential_key") || strings.Contains(string(state), `"ballot"`) || strings.Contains(string(state), "receipt") {
		t.Fatalf("state after casting in receipt mode none: %s", state)
	}
	stimmig(t, 1, "client", "check", "-state", cleo)
	stimmig(t, 1, "client", "cast", "-state", cleo, "-ranking", "no")
	stimmig(t, 0, "admin", "close-voting", "-election", id)
	if out := stimmig(t, 0, "admin", "tally", "-election", id); !strings.Contains(out, "winners: yes") {
		t.Fatalf("tally: %s", out)
	}

	// Mistakes of the admin.
	stimmig(t, 1, "admin", "create", "-definition", write("bad.json", `{"title": "x", "tally": {"candidates": ["A"], "method": "plurality"}}`))
	stimmig(t, 1, "admin", "roll", "-election", "xyz", "-voters", voters)
	stimmig(t, 1, "admin", "nonsense", "-election", id)
	stimmig(t, 2, "admin")
	stimmig(t, 2, "client")
	stimmig(t, 1, "client", "cast", "-ranking", "A")
}
