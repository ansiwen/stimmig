// Package identity defines the identity plugins of the registrar: providers
// that map an external login to a stable subject ID (SPEC.md section 9).
package identity

import (
	"context"
	"net/http"
)

// Provider authenticates voters.
type Provider interface {
	// ID names the provider, for example "email". The roll stores it with
	// every subject ID.
	ID() string
	// Begin starts a login for one registration session and returns the URL
	// to send the voter to. The provider must hand the state back in the
	// "state" query parameter of its callback.
	Begin(ctx context.Context, electionID, state string) (redirectURL string, err error)
	// Complete checks the callback request and returns who logged in.
	Complete(ctx context.Context, callback *http.Request) (Subject, error)
}

// Subject is an authenticated identity.
type Subject struct {
	Provider   string
	StableID   string
	Attributes map[string]string
}
