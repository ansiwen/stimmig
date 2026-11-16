package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ansiwen/stimmig/admin"
	"github.com/ansiwen/stimmig/api"
)

const adminWebHelp = `usage: stimmig admin-web
Serves the admin web page. It does what "stimmig admin" does.
environment:
  STIMMIG_ADMINWEB_TOKEN    at least 16 characters; the page asks for it
  STIMMIG_LISTEN            default 127.0.0.1:8090; the page speaks HTTP, so put TLS in front of any other address
  STIMMIG_LOG_URL, STIMMIG_REGISTRAR_URL, STIMMIG_BALLOTBOX_URL
  STIMMIG_LOG_ADMIN_TOKEN, STIMMIG_REGISTRAR_ADMIN_TOKEN, STIMMIG_BALLOTBOX_ADMIN_TOKEN`

func runAdminWeb(stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := serveAdminWeb(ctx, stderr); err != nil {
		_, _ = fmt.Fprintf(stderr, "stimmig admin-web: %v\n", err)
		return 1
	}
	return 0
}

func serveAdminWeb(ctx context.Context, stderr io.Writer) error {
	var e env
	token := e.get("STIMMIG_ADMINWEB_TOKEN")
	c := &admin.Client{
		Log:       &api.Client{Base: e.get("STIMMIG_LOG_URL"), Token: e.get("STIMMIG_LOG_ADMIN_TOKEN")},
		Registrar: &api.Client{Base: e.get("STIMMIG_REGISTRAR_URL"), Token: e.get("STIMMIG_REGISTRAR_ADMIN_TOKEN")},
		BallotBox: &api.Client{Base: e.get("STIMMIG_BALLOTBOX_URL"), Token: e.get("STIMMIG_BALLOTBOX_ADMIN_TOKEN")},
	}
	if len(e.missing) > 0 {
		return fmt.Errorf("missing environment variables %v\n%s", e.missing, adminWebHelp)
	}
	if len(token) < 16 {
		return errors.New("STIMMIG_ADMINWEB_TOKEN must have at least 16 characters")
	}
	listen := os.Getenv("STIMMIG_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:8090"
	}
	srv := &http.Server{
		Addr: listen, Handler: c.Handler(token), ErrorLog: errorLog("admin-web", stderr),
		// A tally or a status reads and verifies a whole log.
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute, WriteTimeout: 5 * time.Minute, IdleTimeout: time.Minute,
	}
	_, _ = fmt.Fprintf(stderr, "stimmig admin-web: listening on %s\n", listen)
	return listenAndServe(ctx, srv, 10*time.Second)
}
