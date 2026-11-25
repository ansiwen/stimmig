package identity

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

var linkPattern = regexp.MustCompile(`https://\S+`)

func TestEmail(t *testing.T) {
	var mails bytes.Buffer
	now := time.Unix(1_000_000, 0)
	e := &Email{
		BaseURL: "https://registrar.example",
		Secret:  []byte("secret"),
		Mailer:  LogMailer{W: &mails},
		Allow: func(_ context.Context, state, address string) bool {
			return state == "s1" && address == "ada@example.org"
		},
		Now: func() time.Time { return now },
	}
	var _ Provider = e
	ctx := context.Background()

	begin, err := e.Begin(ctx, "election", "s1")
	if err != nil || begin != "https://registrar.example/v1/identity/email?state=s1" {
		t.Fatalf("begin: %q, %v", begin, err)
	}
	post := func(state, address string) *httptest.ResponseRecorder {
		form := url.Values{"state": {state}, "address": {address}}
		r := httptest.NewRequest(http.MethodPost, "/v1/identity/email", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		return w
	}
	// The form.
	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest(http.MethodGet, begin, nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="state" value="s1"`) {
		t.Fatalf("form: %d %s", w.Code, w.Body)
	}
	// An address that is not allowed gets the same answer and no mail.
	eligible, stranger := post("s1", " Ada@Example.org "), post("s1", "eve@example.org")
	e.Wait()
	if eligible.Header().Get("Content-Security-Policy") == "" {
		t.Error("the form has no content security policy")
	}
	if eligible.Code != http.StatusOK || eligible.Body.String() != stranger.Body.String() {
		t.Fatal("the answer reveals who is on the roll")
	}
	if strings.Count(mails.String(), "mail to") != 1 || !strings.Contains(mails.String(), "mail to ada@example.org") {
		t.Fatalf("mails: %s", mails.String())
	}
	if post("", "ada@example.org").Code != http.StatusBadRequest {
		t.Error("request without state accepted")
	}

	link := linkPattern.FindString(mails.String())
	complete := func(link string) (Subject, error) {
		return e.Complete(ctx, httptest.NewRequest(http.MethodGet, link, nil))
	}
	sub, err := complete(link)
	if err != nil || sub.Provider != "email" || sub.StableID != "ada@example.org" {
		t.Fatalf("subject %+v, %v", sub, err)
	}
	u, _ := url.Parse(link)
	if u.Path != "/v1/callback/email" || u.Query().Get("state") != "s1" {
		t.Fatalf("link: %s", link)
	}
	// Every part of the link is authenticated.
	for _, param := range []string{"state", "address", "expires", "mac"} {
		q := u.Query()
		q.Set(param, q.Get(param)+"1")
		changed := *u
		changed.RawQuery = q.Encode()
		if _, err := complete(changed.String()); err == nil {
			t.Errorf("link with changed %s accepted", param)
		}
	}
	// Another secret, and expiry.
	other := &Email{BaseURL: e.BaseURL, Secret: []byte("other"), Mailer: e.Mailer, Allow: e.Allow, Now: e.Now}
	if _, err := other.Complete(ctx, httptest.NewRequest(http.MethodGet, link, nil)); err == nil {
		t.Error("link of another secret accepted")
	}
	now = now.Add(EmailLinkValidity + time.Second)
	if _, err := complete(link); err == nil {
		t.Error("expired link accepted")
	}
}

func TestSMTPMailerRejectsHeaderInjection(t *testing.T) {
	m := SMTPMailer{Addr: "127.0.0.1:1", From: "noreply@example.org"}
	if err := m.Send(context.Background(), "a@example.org\r\nBcc: x@example.org", "s", "b"); err == nil {
		t.Fatal("line break in the recipient accepted")
	}
}

// A mailer that fails gives the same answer as one that works.
type failingMailer struct{}

func (failingMailer) Send(context.Context, string, string, string) error {
	return errors.New("smtp down")
}

func TestEmailAnswerDoesNotDependOnTheMail(t *testing.T) {
	e := &Email{BaseURL: "https://r.example", Secret: []byte("s"), Mailer: failingMailer{},
		Allow: func(context.Context, string, string) bool { return true }}
	post := func(address string) *httptest.ResponseRecorder {
		form := url.Values{"state": {"s"}, "address": {address}}
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		return w
	}
	w := post("ada@example.org")
	e.Wait()
	if w.Code != http.StatusOK || w.Body.String() != post("").Body.String() {
		t.Fatalf("answer %d differs for a failing mailer", w.Code)
	}
}

// fakeSMTP answers like a relay that rejects the recipient and quotes it.
func fakeSMTP(t *testing.T, stall bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if stall {
					time.Sleep(5 * time.Second)
					return
				}
				r := bufio.NewReader(conn)
				_, _ = fmt.Fprint(conn, "220 relay\r\n")
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						_, _ = fmt.Fprint(conn, "250 relay\r\n")
					case strings.HasPrefix(line, "MAIL"):
						_, _ = fmt.Fprint(conn, "250 ok\r\n")
					case strings.HasPrefix(line, "RCPT"):
						_, _ = fmt.Fprint(conn, "550 5.1.1 <ada@example.org>: Recipient address rejected\r\n")
					default:
						_, _ = fmt.Fprint(conn, "221 bye\r\n")
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestSMTPMailerErrorsDoNotNameTheRecipient(t *testing.T) {
	m := SMTPMailer{Addr: fakeSMTP(t, false), From: "noreply@example.org"}
	err := m.Send(context.Background(), "ada@example.org", "s", "b")
	if err == nil || strings.Contains(err.Error(), "ada") || !strings.Contains(err.Error(), "550") {
		t.Fatalf("%v", err)
	}
}

func TestSMTPMailerHonoursTheDeadline(t *testing.T) {
	m := SMTPMailer{Addr: fakeSMTP(t, true), From: "noreply@example.org"}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := m.Send(ctx, "ada@example.org", "s", "b"); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
}

func TestSMTPMailerLogsIn(t *testing.T) {
	m := SMTPMailer{Addr: fakeSMTP(t, false), From: "noreply@example.org", Username: "user", Password: "hunter2"}
	err := m.Send(context.Background(), "ada@example.org", "s", "b")
	if err == nil || !strings.Contains(err.Error(), "login") || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("%v", err)
	}
}
