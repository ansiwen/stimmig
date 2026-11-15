package identity

import (
	"bytes"
	"context"
	"errors"
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
