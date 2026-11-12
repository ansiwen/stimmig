package ballot

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/merkle"
)

// SignatureAlgorithm is the identifier of the ballot signature and of the
// receipt signature in the manifest.
const SignatureAlgorithm = "ed25519-v1"

const (
	ballotContext  = "stimmig-ballot-v1"
	receiptContext = "stimmig-receipt-v1"
)

// Sign signs a ballot with the credential private key. The signature covers
// the canonical encoding of ["stimmig-ballot-v1", election_id, ciphertext].
func Sign(credentialKey ed25519.PrivateKey, electionID merkle.Hash, ciphertext []byte) ([]byte, error) {
	msg, err := canon.Marshal([]any{ballotContext, electionID[:], ciphertext})
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(credentialKey, msg), nil
}

// Verify checks the ballot signature against the credential public key.
func Verify(credentialKey ed25519.PublicKey, electionID merkle.Hash, ciphertext, signature []byte) error {
	if len(credentialKey) != ed25519.PublicKeySize {
		return errors.New("ballot: credential key has the wrong size")
	}
	msg, err := canon.Marshal([]any{ballotContext, electionID[:], ciphertext})
	if err != nil {
		return err
	}
	if !ed25519.Verify(credentialKey, msg, signature) {
		return errors.New("ballot: ballot signature is invalid")
	}
	return nil
}

func receiptMessage(electionID, leaf merkle.Hash) ([]byte, error) {
	return canon.Marshal([]any{receiptContext, electionID[:], leaf[:]})
}

// SignReceipt creates the ballot box's receipt for a ballot: its signature
// over the canonical encoding of ["stimmig-receipt-v1", election_id,
// leaf_hash], where leaf_hash is the leaf hash of the ballot's log entry.
// The signer must hold an Ed25519 key.
func SignReceipt(signer crypto.Signer, electionID, leaf merkle.Hash) ([]byte, error) {
	if _, ok := signer.Public().(ed25519.PublicKey); !ok {
		return nil, errors.New("ballot: receipt signer is not an Ed25519 key")
	}
	msg, err := receiptMessage(electionID, leaf)
	if err != nil {
		return nil, err
	}
	return signer.Sign(rand.Reader, msg, crypto.Hash(0))
}

// VerifyReceipt checks a receipt against the receipt key of the manifest.
func VerifyReceipt(receiptKey []byte, electionID, leaf merkle.Hash, receipt []byte) error {
	if len(receiptKey) != ed25519.PublicKeySize {
		return errors.New("ballot: receipt key has the wrong size")
	}
	msg, err := receiptMessage(electionID, leaf)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(receiptKey), msg, receipt) {
		return errors.New("ballot: receipt signature is invalid")
	}
	return nil
}
