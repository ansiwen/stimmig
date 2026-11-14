// Package testkit gives tests the keys and the manifest of an election.
package testkit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"

	"github.com/ansiwen/stimmig/ballot"
	"github.com/ansiwen/stimmig/credential"
	"github.com/ansiwen/stimmig/publog"
	"github.com/ansiwen/stimmig/tally"
)

// Keys holds the keys of the registrar and the ballot box.
type Keys struct {
	Issuing         *rsa.PrivateKey
	IssuingPublic   []byte
	ElectionPublic  []byte
	ElectionPrivate []byte
	Receipt         ed25519.PrivateKey
}

// SharedKeys returns keys that are created once per test binary, because
// RSA key generation is slow.
var SharedKeys = sync.OnceValue(func() Keys {
	var k Keys
	var err error
	if k.Issuing, err = credential.GenerateIssuingKey(rand.Reader); err != nil {
		panic(err)
	}
	if k.IssuingPublic, err = credential.MarshalIssuingKey(&k.Issuing.PublicKey); err != nil {
		panic(err)
	}
	if k.ElectionPublic, k.ElectionPrivate, err = ballot.GenerateElectionKey(); err != nil {
		panic(err)
	}
	if _, k.Receipt, err = ed25519.GenerateKey(rand.Reader); err != nil {
		panic(err)
	}
	return k
})

// Manifest returns a valid manifest with three candidates, the given log
// key and the public keys of k.
func Manifest(logKey []byte, k Keys) publog.Manifest {
	return publog.Manifest{
		Version: publog.ManifestVersion,
		Title:   "Board election",
		Nonce:   bytes.Repeat([]byte{1}, 16),
		Tally: tally.Manifest{
			Candidates: []string{"A", "B", "C"},
			Method:     tally.Schulze,
			MaxRanks:   2,
		},
		Algorithms:  publog.DefaultAlgorithms(publog.ReceiptFull),
		ReceiptMode: publog.ReceiptFull,
		LogKey:      logKey,
		IssuingKey:  k.IssuingPublic,
		ElectionKey: k.ElectionPublic,
		ReceiptKey:  k.Receipt.Public().(ed25519.PublicKey), //nolint:forcetypeassert // an Ed25519 key
	}
}

var tokenPattern = regexp.MustCompile(`name="token" value="([^"]+)"`)

// Login opens a login link of the registrar and types the confirmation
// code, as a voter does. It returns the status of the last response.
func Login(link, code string) (int, error) {
	resp, err := http.Get(link) //nolint:gosec,noctx // test helper
	if err != nil {
		return 0, err
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	m := tokenPattern.FindSubmatch(body)
	if resp.StatusCode != http.StatusOK || m == nil {
		return resp.StatusCode, nil
	}
	u, err := url.Parse(link)
	if err != nil {
		return 0, err
	}
	resp, err = http.PostForm(u.Scheme+"://"+u.Host+"/v1/confirm", url.Values{"token": {string(m[1])}, "code": {code}}) //nolint:noctx // test helper
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}
