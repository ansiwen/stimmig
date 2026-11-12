// Package credential implements the blind-signed voting credential of
// assurance profile A (SPEC.md section 5.1).
//
// The voter's client creates an Ed25519 credential key pair for one
// election. The registrar signs the credential message with RSA blind
// signatures (RFC 9474, variant RSABSSA-SHA384-PSS-Deterministic) and never
// sees the message or the signature. The unblinded signature is a standard
// RSASSA-PSS signature with SHA-384 and a 48-byte salt that anyone can
// verify.
//
// The deterministic variant is safe here because every credential message
// contains a fresh public key and therefore has high entropy.
package credential

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/cloudflare/circl/blindsign/blindrsa"

	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/merkle"
)

// Algorithm is the identifier of the credential scheme in the manifest.
const Algorithm = "rsabssa-sha384-pss-deterministic-v1"

// MinBits is the smallest accepted size of the issuing key.
const MinBits = 3072

const (
	variant = blindrsa.SHA384PSSDeterministic
	context = "stimmig-credential-v1"
)

// Message returns the byte string that the registrar signs blindly: the
// canonical encoding of ["stimmig-credential-v1", election_id,
// credential_public_key]. It binds the credential to one election.
func Message(electionID merkle.Hash, credentialKey ed25519.PublicKey) ([]byte, error) {
	if len(credentialKey) != ed25519.PublicKeySize {
		return nil, errors.New("credential: credential key has the wrong size")
	}
	return canon.Marshal([]any{context, electionID[:], []byte(credentialKey)})
}

// GenerateIssuingKey creates an issuing key of MinBits bits.
func GenerateIssuingKey(random io.Reader) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(random, MinBits)
}

// MarshalIssuingKey encodes the public issuing key for the manifest, as a
// DER SubjectPublicKeyInfo. Browsers import this form directly.
func MarshalIssuingKey(pub *rsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

// smallPrimes is the product of the odd primes below 100.
var smallPrimes = func() *big.Int {
	product := big.NewInt(1)
	for _, p := range []int64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97} {
		product.Mul(product, big.NewInt(p))
	}
	return product
}()

// ParseIssuingKey decodes and validates a public issuing key. The client
// must do this before blinding, because blindness depends on a well-formed
// key. It checks the size, the public exponent 65537, the DER form and that
// the modulus has no small prime factor.
//
// It cannot prove that the exponent is coprime to the group order; that
// needs a proof from the registrar or trust in its key generation.
func ParseIssuingKey(der []byte) (*rsa.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("credential: issuing key: %w", err)
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("credential: issuing key is not an RSA key")
	}
	if again, err := x509.MarshalPKIXPublicKey(pub); err != nil || !bytes.Equal(again, der) {
		return nil, errors.New("credential: issuing key is not in canonical DER form")
	}
	if pub.N.BitLen() < MinBits {
		return nil, fmt.Errorf("credential: issuing key has %d bits, minimum is %d", pub.N.BitLen(), MinBits)
	}
	if pub.E != 65537 {
		return nil, errors.New("credential: issuing key exponent is not 65537")
	}
	if pub.N.Bit(0) == 0 || new(big.Int).GCD(nil, nil, pub.N, smallPrimes).Cmp(big.NewInt(1)) != 0 {
		return nil, errors.New("credential: issuing key modulus has a small factor")
	}
	return pub, nil
}

// Request is the client side of one credential issuance.
type Request struct {
	// Blinded is the value the client sends to the registrar.
	Blinded []byte

	client  blindrsa.Client
	state   blindrsa.State
	message []byte
}

// NewRequest blinds the credential message for the registrar.
func NewRequest(random io.Reader, issuingKey *rsa.PublicKey, electionID merkle.Hash, credentialKey ed25519.PublicKey) (*Request, error) {
	msg, err := Message(electionID, credentialKey)
	if err != nil {
		return nil, err
	}
	client, err := blindrsa.NewClient(variant, issuingKey)
	if err != nil {
		return nil, err
	}
	prepared, err := client.Prepare(random, msg)
	if err != nil {
		return nil, err
	}
	blinded, state, err := client.Blind(random, prepared)
	if err != nil {
		return nil, err
	}
	return &Request{Blinded: blinded, client: client, state: state, message: msg}, nil
}

// Finalize unblinds the registrar's answer and verifies the resulting
// signature. The signature goes into the ballot.
func (r *Request) Finalize(blindSignature []byte) ([]byte, error) {
	sig, err := r.client.Finalize(r.state, blindSignature)
	if err != nil {
		return nil, fmt.Errorf("credential: %w", err)
	}
	if err := r.client.Verify(r.message, sig); err != nil {
		return nil, fmt.Errorf("credential: %w", err)
	}
	return sig, nil
}

// Issue signs a blinded value. The registrar calls it once per roll entry.
func Issue(issuingKey *rsa.PrivateKey, blinded []byte) ([]byte, error) {
	return blindrsa.NewSigner(issuingKey).BlindSign(blinded)
}

// Verify checks the registrar's signature on a credential key for an
// election.
func Verify(issuingKey *rsa.PublicKey, electionID merkle.Hash, credentialKey ed25519.PublicKey, signature []byte) error {
	msg, err := Message(electionID, credentialKey)
	if err != nil {
		return err
	}
	verifier, err := blindrsa.NewVerifier(variant, issuingKey)
	if err != nil {
		return err
	}
	if err := verifier.Verify(msg, signature); err != nil {
		return errors.New("credential: registrar signature is invalid")
	}
	return nil
}
