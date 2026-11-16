package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
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
  STIMMIG_DB_MAX_CONNS     size of the database pool, default 20
  STIMMIG_KEY_ENCRYPTION_KEY  64 hexadecimal characters; encrypts the private keys in the database;
                           required unless STIMMIG_ALLOW_PLAIN_KEYS=1 (development)
log:
  STIMMIG_REGISTRAR_TOKEN  token with which the registrar appends
  STIMMIG_BALLOTBOX_TOKEN  token with which the ballot box appends
registrar and ballotbox:
  STIMMIG_LOG_URL          URL of the log service
  STIMMIG_LOG_TOKEN        this service's token at the log service
ballotbox:
  STIMMIG_CLIENT_DIR       directory with the voting client's bundle (make web); optional
  STIMMIG_PUBLIC_LOG_URL, STIMMIG_PUBLIC_REGISTRAR_URL  public URLs the voting client uses; required with the bundle
registrar:
  STIMMIG_PUBLIC_URL       URL under which voters reach the registrar
  STIMMIG_EMAIL_SECRET     secret that keys the login links and confirmations, 32 characters or more
  STIMMIG_SMTP_ADDR        host:port of the SMTP server; required unless STIMMIG_PRINT_MAILS=1 (development)
  STIMMIG_SMTP_FROM        sender address of the mails
  STIMMIG_MAIL_INTERVAL    shortest time between two login mails to one address, default 1m
  STIMMIG_OIDC_ISSUER      OpenID Connect issuer URL; adds the provider "oidc"
  STIMMIG_OIDC_CLIENT_ID, STIMMIG_OIDC_CLIENT_SECRET  this registrar's client at the issuer;
                           its redirect URL is <STIMMIG_PUBLIC_URL>/v1/callback/oidc`

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
	var handler func(db *sql.DB) (http.Handler, error)
	switch role {
	case "log":
		regToken, boxToken := e.get("STIMMIG_REGISTRAR_TOKEN"), e.get("STIMMIG_BALLOTBOX_TOKEN")
		// Each token gives its holder different rights, so they must differ.
		if regToken == boxToken || regToken == adminToken || boxToken == adminToken {
			return errors.New("the admin, registrar and ballot box tokens must be different")
		}
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
		if os.Getenv("STIMMIG_SMTP_ADDR") == "" {
			// Login mails hold the voters' addresses and login links.
			if os.Getenv("STIMMIG_PRINT_MAILS") != "1" {
				return errors.New("STIMMIG_SMTP_ADDR is not set; set it, or set STIMMIG_PRINT_MAILS=1 for development")
			}
			_, _ = fmt.Fprintln(stderr, "stimmig registrar: warning: login mails, with the voters' addresses, are printed here")
		}
		if addr := os.Getenv("STIMMIG_SMTP_ADDR"); addr != "" {
			mailer = identity.SMTPMailer{Addr: addr, From: e.get("STIMMIG_SMTP_FROM")}
		}
		handler = func(db *sql.DB) (http.Handler, error) {
			s := &registrar.Server{DB: db, Log: log, AdminToken: adminToken, Keys: keys, Secret: []byte(secret)}
			if v := os.Getenv("STIMMIG_MAIL_INTERVAL"); v != "" {
				if s.MailInterval, err = time.ParseDuration(v); err != nil {
					return nil, err
				}
			}
			s.Providers = map[string]identity.Provider{"email": &identity.Email{
				BaseURL: publicURL,
				Secret:  []byte(secret),
				Mailer:  mailer,
				Allow: func(ctx context.Context, state, address string) bool {
					return s.AllowMail(ctx, state, "email", address)
				},
			}}
			// OpenID Connect is on when an issuer is configured.
			if issuer := os.Getenv("STIMMIG_OIDC_ISSUER"); issuer != "" {
				oidc, err := identity.NewOIDC(ctx, issuer, os.Getenv("STIMMIG_OIDC_CLIENT_ID"),
					os.Getenv("STIMMIG_OIDC_CLIENT_SECRET"), publicURL, []byte(secret))
				if err != nil {
					return nil, err
				}
				s.Providers[oidc.ID()] = oidc
			}
			return s.Handler(), s.Init(ctx)
		}
	case "ballotbox":
		log := &api.Client{Base: e.get("STIMMIG_LOG_URL"), Token: e.get("STIMMIG_LOG_TOKEN")}
		handler = func(db *sql.DB) (http.Handler, error) {
			s := &ballotbox.Server{DB: db, Log: log, AdminToken: adminToken, ClientDir: os.Getenv("STIMMIG_CLIENT_DIR"), Keys: keys}
			if s.ClientDir != "" {
				s.LogURL, s.RegistrarURL = e.get("STIMMIG_PUBLIC_LOG_URL"), e.get("STIMMIG_PUBLIC_REGISTRAR_URL")
			}
			return s.Handler(), s.Init(ctx)
		}
	}
	if len(e.missing) > 0 {
		return fmt.Errorf("missing environment variables %v\n%s", e.missing, serveHelp)
	}
	// A key that is missing by mistake, for example a misspelt key in a
	// secret, must not mean that the keys are stored in clear. That includes the
	// election private key, which opens the ballots.
	if keys == (keystore.Plain{}) {
		if os.Getenv("STIMMIG_ALLOW_PLAIN_KEYS") != "1" {
			return errors.New("STIMMIG_KEY_ENCRYPTION_KEY is not set; set it, or set STIMMIG_ALLOW_PLAIN_KEYS=1 for development")
		}
		_, _ = fmt.Fprintf(stderr, "stimmig %s: warning: private keys are stored unencrypted\n", role)
	}
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	// A request can hold a connection while it waits for another service, so
	// the pool is bounded below the database's limit.
	maxConns := 20
	if v := os.Getenv("STIMMIG_DB_MAX_CONNS"); v != "" {
		if maxConns, err = strconv.Atoi(v); err != nil || maxConns < 2 {
			return errors.New("STIMMIG_DB_MAX_CONNS must be a number of 2 or more")
		}
	}
	db.SetMaxOpenConns(maxConns)
	h, err := handler(db)
	if err != nil {
		return err
	}
	// There is no access log: the ballot box must not record client
	// addresses, and the other services do not need to.
	// The write timeout is long because a tally or an export can take a while.
	srv := &http.Server{
		Addr: listen, Handler: h,
		// net/http logs the address of a client whose handler panicked; the
		// ballot box must not record one.
		ErrorLog:          errorLog(role, stderr),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 5 * time.Minute, IdleTimeout: 2 * time.Minute,
	}
	_, _ = fmt.Fprintf(stderr, "stimmig %s: listening on %s\n", role, listen)
	stop, cancel := signal.NotifyContext(ctx, syscall.SIGTERM, os.Interrupt)
	defer cancel()
	return listenAndServe(stop, srv, ShutdownGrace)
}

// ShutdownGrace is how long a service finishes the requests in flight after
// SIGTERM. A registrar that is killed between the log and its database
// leaves the log ahead of it (the next issuance catches up, but nothing
// should rely on that).
const ShutdownGrace = 45 * time.Second

// listenAndServe serves until ctx ends, then lets the requests in flight
// finish for at most grace.
func listenAndServe(ctx context.Context, srv *http.Server, grace time.Duration) error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	return listenAndServeOn(ctx, srv, ln, grace)
}

func listenAndServeOn(ctx context.Context, srv *http.Server, ln net.Listener, grace time.Duration) error {
	done := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		done <- srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return <-done
}

// errorLog is the logger of the HTTP server for its own errors. The ballot
// box discards them, because they can name the address of a client.
func errorLog(role string, stderr io.Writer) *log.Logger {
	if role == "ballotbox" {
		return log.New(io.Discard, "", 0)
	}
	return log.New(stderr, "http: ", log.LstdFlags)
}
