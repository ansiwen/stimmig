package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ansiwen/stimmig/canon"
)

// Mailer sends plain-text mails.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

// SMTPMailer sends mails through an SMTP server without authentication.
//
// shortcut: no SMTP authentication, which fits a relay on the local network; add credentials when a hosted mail service is used.
type SMTPMailer struct {
	Addr string // host:port
	From string
}

// Send implements Mailer.
func (m SMTPMailer) Send(_ context.Context, to, subject, body string) error {
	if strings.ContainsAny(to+subject, "\r\n") {
		return errors.New("identity: line break in a mail header")
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n", m.From, to, subject, body)
	return smtp.SendMail(m.Addr, nil, m.From, []string{to}, []byte(msg))
}

// LogMailer writes mails to a writer instead of sending them. It is for
// development.
type LogMailer struct {
	W io.Writer
}

// Send implements Mailer.
func (m LogMailer) Send(_ context.Context, to, subject, body string) error {
	_, err := fmt.Fprintf(m.W, "mail to %s: %s\n%s\n", to, subject, body)
	return err
}

// EmailLinkValidity is how long a login link works.
const EmailLinkValidity = 30 * time.Minute

const emailContext = "stimmig-email-link-v1"

// Email is the email link provider. The voter enters an address, receives
// a link, and is logged in as that address when they open it. The subject
// ID is the address in lower case.
//
// The provider is an http.Handler for its form; mount it at
// /v1/identity/email. Its callback is /v1/callback/email.
type Email struct {
	// BaseURL is the public URL of the registrar, without a trailing slash.
	BaseURL string
	// Secret keys the login links. All replicas share it.
	Secret []byte
	Mailer Mailer
	// Allow reports whether a link may be mailed to the address for this
	// session. The registrar allows only addresses on the roll, so that
	// the service cannot be used to mail strangers.
	Allow func(ctx context.Context, state, address string) bool
	// Now may be nil for the system clock.
	Now func() time.Time
}

// ID implements Provider.
func (e *Email) ID() string { return "email" }

// Begin implements Provider.
func (e *Email) Begin(_ context.Context, _, state string) (string, error) {
	return e.BaseURL + "/v1/identity/email?state=" + url.QueryEscape(state), nil
}

func (e *Email) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Email) mac(state, address string, expires int64) string {
	msg, _ := canon.Marshal([]any{emailContext, state, address, expires})
	h := hmac.New(sha256.New, e.Secret)
	h.Write(msg)
	return hex.EncodeToString(h.Sum(nil))
}

var emailForm = template.Must(template.New("form").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Confirm your email address</title></head><body>
<h1>Confirm your email address</h1>
{{if .Sent}}<p role="status">If this address is on the electoral roll, a link was sent to it. Open the link to continue. It is valid for 30 minutes.</p>
{{else}}<form method="post">
<input type="hidden" name="state" value="{{.State}}">
<label for="address">Email address</label>
<input id="address" name="address" type="email" autocomplete="email" required>
<button type="submit">Send link</button>
</form>{{end}}
</body></html>`))

// ServeHTTP shows the address form and mails the login link.
func (e *Email) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state == "" {
		http.Error(w, "state is missing", http.StatusBadRequest)
		return
	}
	sent := false
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		address := strings.ToLower(strings.TrimSpace(r.PostFormValue("address")))
		// The answer is the same whether the address is eligible or not,
		// so that the form does not reveal who is on the roll.
		if address != "" && e.Allow(r.Context(), state, address) {
			expires := e.now().Add(EmailLinkValidity).Unix()
			q := url.Values{
				"state":   {state},
				"address": {address},
				"expires": {strconv.FormatInt(expires, 10)},
				"mac":     {e.mac(state, address, expires)},
			}
			link := e.BaseURL + "/v1/callback/email?" + q.Encode()
			body := "Open this link to confirm your address and receive your voting credential:\n\n" + link +
				"\n\nThe link is valid for 30 minutes. If you did not ask for it, ignore this mail."
			if err := e.Mailer.Send(r.Context(), address, "Your voting credential", body); err != nil {
				http.Error(w, "the mail could not be sent", http.StatusBadGateway)
				return
			}
		}
		sent = true
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = emailForm.Execute(w, map[string]any{"State": state, "Sent": sent})
}

// Complete implements Provider.
func (e *Email) Complete(_ context.Context, r *http.Request) (Subject, error) {
	q := r.URL.Query()
	state, address := q.Get("state"), q.Get("address")
	expires, err := strconv.ParseInt(q.Get("expires"), 10, 64)
	if err != nil {
		return Subject{}, errors.New("identity: malformed login link")
	}
	if !hmac.Equal([]byte(q.Get("mac")), []byte(e.mac(state, address, expires))) {
		return Subject{}, errors.New("identity: invalid login link")
	}
	if e.now().Unix() > expires {
		return Subject{}, errors.New("identity: the login link has expired")
	}
	return Subject{Provider: e.ID(), StableID: address}, nil
}
