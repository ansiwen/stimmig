package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDC is the OpenID Connect provider: the voter logs in at an identity
// provider of the organisation, with the authorization code flow and PKCE.
// The subject ID is the issuer and the "sub" claim, joined by "#".
//
// Its callback is /v1/callback/oidc; register that URL at the identity
// provider.
type OIDC struct {
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
	secret   []byte
}

// NewOIDC reads the configuration of the issuer from its discovery
// document. baseURL is the public URL of the registrar. The secret derives
// the nonce and the PKCE verifier of every login; all replicas share it.
func NewOIDC(ctx context.Context, issuer, clientID, clientSecret, baseURL string, secret []byte) (*OIDC, error) {
	if len(secret) == 0 {
		return nil, errors.New("identity: the OIDC provider needs a secret")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("identity: OIDC discovery: %w", err)
	}
	return &OIDC{
		config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  baseURL + "/v1/callback/oidc",
			Scopes:       []string{oidc.ScopeOpenID},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
		secret:   secret,
	}, nil
}

// ID implements Provider.
func (o *OIDC) ID() string { return "oidc" }

// derive makes a per-login secret from the state, so that the provider
// stores nothing between Begin and Complete.
func (o *OIDC) derive(label, state string) string {
	h := hmac.New(sha256.New, o.secret)
	h.Write([]byte(label + "\x00" + state))
	return hex.EncodeToString(h.Sum(nil))
}

// Begin implements Provider.
func (o *OIDC) Begin(_ context.Context, _, state string) (string, error) {
	return o.config.AuthCodeURL(state,
		oidc.Nonce(o.derive("nonce", state)),
		oauth2.S256ChallengeOption(o.derive("pkce", state))), nil
}

// Complete implements Provider. It exchanges the code, verifies the ID
// token against the issuer's keys and checks that the token answers this
// login.
func (o *OIDC) Complete(ctx context.Context, r *http.Request) (Subject, error) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		return Subject{}, fmt.Errorf("identity: the identity provider refused the login: %s", e)
	}
	state := q.Get("state")
	token, err := o.config.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(o.derive("pkce", state)))
	if err != nil {
		return Subject{}, errors.New("identity: the login code was not accepted")
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return Subject{}, errors.New("identity: the identity provider sent no ID token")
	}
	idToken, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return Subject{}, errors.New("identity: the ID token is invalid")
	}
	if !hmac.Equal([]byte(idToken.Nonce), []byte(o.derive("nonce", state))) {
		return Subject{}, errors.New("identity: the ID token belongs to another login")
	}
	if idToken.Subject == "" {
		return Subject{}, errors.New("identity: the ID token names no subject")
	}
	return Subject{Provider: o.ID(), StableID: idToken.Issuer + "#" + idToken.Subject}, nil
}
