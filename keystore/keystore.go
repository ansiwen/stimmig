// Package keystore protects the private keys that the services keep in
// their databases. This is the software key store of SPEC.md section 10:
// keys are encrypted at rest under a key-encryption key that the operator
// gives to the service, so that a copy of the database does not reveal
// them. The keys are still used inside the service process; an HSM that
// never releases them is a later step.
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// Sealer encrypts private keys for storage. The label names what the key
// belongs to, usually the public key; a sealed key opens only with the
// label it was sealed with, so that stored keys cannot be swapped.
type Sealer interface {
	Seal(private, label []byte) ([]byte, error)
	Open(sealed, label []byte) ([]byte, error)
}

// Plain stores keys unencrypted. It is for development and tests.
type Plain struct{}

// Seal implements Sealer.
func (Plain) Seal(private, _ []byte) ([]byte, error) { return private, nil }

// Open implements Sealer.
func (Plain) Open(sealed, _ []byte) ([]byte, error) { return sealed, nil }

type aesSealer struct {
	aead cipher.AEAD
}

// Parse returns the Sealer for a key-encryption key given as 64
// hexadecimal characters: AES-256-GCM with a random nonce. The empty text
// gives Plain.
func Parse(hexKey string) (Sealer, error) {
	if hexKey == "" {
		return Plain{}, nil
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("keystore: the key-encryption key must be 64 hexadecimal characters")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	return aesSealer{aead}, err
}

func (s aesSealer) Seal(private, label []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, private, label), nil
}

func (s aesSealer) Open(sealed, label []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("keystore: the stored key is too short")
	}
	private, err := s.aead.Open(nil, sealed[:n], sealed[n:], label)
	if err != nil {
		return nil, errors.New("keystore: the stored key does not open with this key-encryption key")
	}
	return private, nil
}
