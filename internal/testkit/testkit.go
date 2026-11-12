// Package testkit gives tests the keys and the manifest of an election.
package testkit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
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
