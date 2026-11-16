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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/cloudflare/circl/blindsign/blindrsa"

	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/merkle"
)

// Algorithm is the identifier of the credential scheme in the manifest.
const Algorithm = "rsabssa-sha384-pss-deterministic-v1"

// MinBits is the smallest and MaxBits the largest accepted size of the issuing
// key; the proof of the key and every verification cost time by its size.
const (
	MinBits = 3072
	MaxBits = 8192
)

const (
	variant = blindrsa.SHA384PSSDeterministic
	context = "stimmig-credential-v1"
)

// Message returns the byte string that the registrar signs blindly: the
// canonical encoding of ["stimmig-credential-v1", election_id,
// credential_public_key]. It binds the credential to one election.
func Message(electionID merkle.Hash, credentialKey ed25519.PublicKey) ([]byte, error) {
	if err := CheckKey(credentialKey); err != nil {
		return nil, err
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
	if pub.N.BitLen() > MaxBits {
		return nil, fmt.Errorf("credential: issuing key has %d bits, maximum is %d", pub.N.BitLen(), MaxBits)
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

// SeedSize is the size of the seed of NewRequestFromSeed.
const SeedSize = 32

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// NewRequestFromSeed is NewRequest with all randomness derived from a
// secret seed, so that the same seed gives the same request again. A
// client stores the seed before it contacts the registrar and can then
// finish an issuance after it was interrupted. The seed must be random,
// secret and used for one credential only.
func NewRequestFromSeed(seed []byte, issuingKey *rsa.PublicKey, electionID merkle.Hash, credentialKey ed25519.PublicKey) (*Request, error) {
	block, err := aes.NewCipher(seed)
	if err != nil || len(seed) != SeedSize {
		return nil, errors.New("credential: the seed must have 32 bytes")
	}
	stream := cipher.StreamReader{S: cipher.NewCTR(block, make([]byte, aes.BlockSize)), R: zeroReader{}}
	return NewRequest(stream, issuingKey, electionID, credentialKey)
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

// ProofRoots is the number of values in an issuing key proof. A key whose
// group order is divisible by e passes each with probability 1/e, so the
// registrar that chose the modulus would need about e^ProofRoots tries to
// find one that passes: 2^128 with 8 values (2^64 with 4 was within reach
// of a funded attacker, since a try costs one hash).
const ProofRoots = 8

// proofChallenge derives the i-th value of an issuing key proof from the
// public key alone, by SHA-256 in counter mode, so that the registrar
// cannot choose it. 16 bytes more than the modulus make the reduction
// bias negligible.
func proofChallenge(pub *rsa.PublicKey, i int) *big.Int {
	size := (pub.N.BitLen()+7)/8 + 16
	var stream []byte
	for counter := 0; len(stream) < size; counter++ {
		h := sha256.New()
		h.Write([]byte("stimmig-issuing-key-proof-v1"))
		h.Write([]byte{byte(i), byte(counter >> 8), byte(counter)})
		h.Write(pub.N.Bytes())
		stream = h.Sum(stream)
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(stream[:size]), pub.N)
}

// ProveIssuingKey returns the proof that the public exponent of the key is
// coprime to the order of the group: the e-th roots of ProofRoots values
// that nobody chose. If e divided the order, only one value in e would have
// an e-th root, and the registrar could not answer. RFC 9474 blindness
// depends on this, and a client cannot see it from the key.
func ProveIssuingKey(priv *rsa.PrivateKey) ([][]byte, error) {
	size := (priv.N.BitLen() + 7) / 8
	proof := make([][]byte, ProofRoots)
	for i := range proof {
		y := proofChallenge(&priv.PublicKey, i)
		root := new(big.Int).Exp(y, priv.D, priv.N)
		if new(big.Int).Exp(root, big.NewInt(int64(priv.E)), priv.N).Cmp(y) != 0 {
			return nil, errors.New("credential: the key has no e-th root of a challenge")
		}
		proof[i] = root.FillBytes(make([]byte, size))
	}
	return proof, nil
}

// VerifyIssuingKeyProof checks the proof of ProveIssuingKey.
func VerifyIssuingKeyProof(pub *rsa.PublicKey, proof [][]byte) error {
	if len(proof) != ProofRoots {
		return fmt.Errorf("credential: the issuing key proof must have %d values", ProofRoots)
	}
	size := (pub.N.BitLen() + 7) / 8
	e := big.NewInt(int64(pub.E))
	for i, b := range proof {
		root := new(big.Int).SetBytes(b)
		if len(b) != size || root.Sign() == 0 || root.Cmp(pub.N) >= 0 ||
			new(big.Int).Exp(root, e, pub.N).Cmp(proofChallenge(pub, i)) != 0 {
			return errors.New("credential: the issuing key proof is invalid")
		}
	}
	return nil
}

// CheckKey checks a credential public key: it must be a canonical encoding
// of a point on the curve that does not have a small order. The registrar
// signs credentials blindly, so a voter can get a signature on any 32
// bytes. With a key of small order, Ed25519 signatures can be made by
// anyone, and implementations of Ed25519 disagree on them, which would
// make the verdict on a log depend on the verifier.
func CheckKey(key []byte) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("credential: credential key has the wrong size")
	}
	p, err := new(edwards25519.Point).SetBytes(key)
	if err != nil || !bytes.Equal(p.Bytes(), key) {
		return errors.New("credential: credential key is not a canonical point")
	}
	if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("credential: credential key has a small order")
	}
	return nil
}
