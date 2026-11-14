package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx"

	"github.com/ansiwen/stimmig/api"
	"github.com/ansiwen/stimmig/ballotbox"
	"github.com/ansiwen/stimmig/identity"
	"github.com/ansiwen/stimmig/keystore"
	"github.com/ansiwen/stimmig/logsvc"
	"github.com/ansiwen/stimmig/registrar"
)

// The services are configured by environment variables only, so that
// tokens never appear on a command line.
const serveHelp = `environment of the services:
  STIMMIG_DATABASE_URL     PostgreSQL URL of this service's database
  STIMMIG_LISTEN           listen address, default :8080
  STIMMIG_ADMIN_TOKEN      bearer token of this service's admin API
  STIMMIG_KEY_ENCRYPTION_KEY  64 hexadecimal characters; encrypts the private keys in the database
log:
  STIMMIG_REGISTRAR_TOKEN  token with which the registrar appends
  STIMMIG_BALLOTBOX_TOKEN  token with which the ballot box appends
registrar and ballotbox:
  STIMMIG_LOG_URL          URL of the log service
  STIMMIG_LOG_TOKEN        this service's token at the log service
ballotbox:
  STIMMIG_CLIENT_DIR       directory with the voting client's bundle (make web); optional
registrar:
  STIMMIG_PUBLIC_URL       URL under which voters reach the registrar
  STIMMIG_EMAIL_SECRET     secret that keys the login links and confirmations, 32 characters or more
  STIMMIG_SMTP_ADDR        host:port of the SMTP server; without it mails are printed
  STIMMIG_SMTP_FROM        sender address of the mails`

// env reads required environment variables.
type env struct {
	missing []string
}

func (e *env) get(name string) string {
	v := os.Getenv(name)
	if v == "" {
		e.missing = append(e.missing, name)
	}
	return v
}

func runServe(role string, stderr io.Writer) int {
	if err := serve(context.Background(), role, stderr); err != nil {
		_, _ = fmt.Fprintf(stderr, "stimmig %s: %v\n", role, err)
		return 1
	}
	return 0
}

func serve(ctx context.Context, role string, stderr io.Writer) error {
	var e env
	dbURL, adminToken := e.get("STIMMIG_DATABASE_URL"), e.get("STIMMIG_ADMIN_TOKEN")
	listen := os.Getenv("STIMMIG_LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	keys, err := keystore.Parse(os.Getenv("STIMMIG_KEY_ENCRYPTION_KEY"))
	if err != nil {
		return err
	}
	if keys == (keystore.Plain{}) {
		_, _ = fmt.Fprintf(stderr, "stimmig %s: warning: STIMMIG_KEY_ENCRYPTION_KEY is not set; private keys are stored unencrypted\n", role)
	}
	var handler func(db *sql.DB) (http.Handler, error)
	switch role {
	case "log":
		regToken, boxToken := e.get("STIMMIG_REGISTRAR_TOKEN"), e.get("STIMMIG_BALLOTBOX_TOKEN")
		handler = func(db *sql.DB) (http.Handler, error) {
			store, err := logsvc.NewStore(ctx, db)
			if err != nil {
				return nil, err
			}
			store.Keys = keys
			s := &logsvc.Server{Store: store, AdminToken: adminToken, RegistrarToken: regToken, BallotBoxToken: boxToken}
			return s.Handler(), nil
		}
	case "registrar":
		log := &api.Client{Base: e.get("STIMMIG_LOG_URL"), Token: e.get("STIMMIG_LOG_TOKEN")}
		publicURL, secret := e.get("STIMMIG_PUBLIC_URL"), e.get("STIMMIG_EMAIL_SECRET")
		if secret != "" && len(secret) < 32 {
			return errors.New("STIMMIG_EMAIL_SECRET is shorter than 32 characters")
		}
		var mailer identity.Mailer = identity.LogMailer{W: stderr}
		if addr := os.Getenv("STIMMIG_SMTP_ADDR"); addr != "" {
			mailer = identity.SMTPMailer{Addr: addr, From: e.get("STIMMIG_SMTP_FROM")}
		}
		handler = func(db *sql.DB) (http.Handler, error) {
			s := &registrar.Server{DB: db, Log: log, AdminToken: adminToken, Keys: keys, Secret: []byte(secret)}
			s.Providers = map[string]identity.Provider{"email": &identity.Email{
				BaseURL: publicURL,
				Secret:  []byte(secret),
				Mailer:  mailer,
				Allow: func(ctx context.Context, state, address string) bool {
					return s.Eligible(ctx, state, "email", address)
				},
			}}
			return s.Handler(), s.Init(ctx)
		}
	case "ballotbox":
		log := &api.Client{Base: e.get("STIMMIG_LOG_URL"), Token: e.get("STIMMIG_LOG_TOKEN")}
		handler = func(db *sql.DB) (http.Handler, error) {
			s := &ballotbox.Server{DB: db, Log: log, AdminToken: adminToken, ClientDir: os.Getenv("STIMMIG_CLIENT_DIR"), Keys: keys}
			return s.Handler(), s.Init(ctx)
		}
	}
	if len(e.missing) > 0 {
		return fmt.Errorf("missing environment variables %v\n%s", e.missing, serveHelp)
	}
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	h, err := handler(db)
	if err != nil {
		return err
	}
	// No access log: the ballot box must not record client addresses, and
	// the other services do not need to.
	srv := &http.Server{Addr: listen, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	_, _ = fmt.Fprintf(stderr, "stimmig %s: listening on %s\n", role, listen)
	return srv.ListenAndServe()
}
