// Package publog implements the public log of an election: an append-only
// Merkle log of canonically encoded entries with signed tree heads
// (SPEC.md section 7).
package publog

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/ansiwen/stimmig/ballot"
	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/credential"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/tally"
)

// Entry types.
const (
	TypeManifest          = "manifest"
	TypeRollCommit        = "roll_commit"
	TypeIssuance          = "issuance"
	TypeRegistrationClose = "registration_close"
	TypeBallot            = "ballot"
	TypeVotingClose       = "voting_close"
	TypeElectionKey       = "election_key"
	TypeBallotPlain       = "ballot_plain"
	TypeResult            = "result"
)

// Types lists all entry types in the order of the election lifecycle.
var Types = []string{
	TypeManifest, TypeRollCommit, TypeIssuance, TypeRegistrationClose,
	TypeBallot, TypeVotingClose, TypeElectionKey, TypeBallotPlain, TypeResult,
}

func knownType(typ string) bool {
	for _, t := range Types {
		if t == typ {
			return true
		}
	}
	return false
}

// Algorithm identifiers of v1.
const (
	AlgLogHash  = "sha256-rfc6962-v1"
	AlgTreeHead = "ed25519-v1"
)

// ManifestVersion is the manifest version this code reads and writes.
const ManifestVersion = 1

// Receipt modes (SPEC.md section 5.5).
const (
	ReceiptFull = "full"
	ReceiptNone = "none"
)

// Manifest is the body of log entry 0. It defines the election. The
// schedule is added with the services.
type Manifest struct {
	Version uint64 `cbor:"version"`
	Title   string `cbor:"title"`
	// Nonce holds at least 16 random bytes. It makes the election ID unique
	// even if two elections have the same definition.
	Nonce      []byte         `cbor:"nonce"`
	Tally      tally.Manifest `cbor:"tally"`
	Algorithms Algorithms     `cbor:"algorithms"`
	// ReceiptMode is "full" or "none".
	ReceiptMode string `cbor:"receipt_mode"`
	// LogKey is the Ed25519 public key that signs the tree heads.
	LogKey []byte `cbor:"log_key"`
	// IssuingKey is the registrar's RSA public key for credentials, as a
	// DER SubjectPublicKeyInfo.
	IssuingKey []byte `cbor:"issuing_key"`
	// ElectionKey is the public key that ballots are encrypted to, as an
	// uncompressed P-256 point.
	ElectionKey []byte `cbor:"election_key"`
	// ReceiptKey is the ballot box's Ed25519 public key for receipts. It is
	// present exactly in receipt mode full.
	ReceiptKey []byte `cbor:"receipt_key,omitempty"`
	// ClientHash is the hash of the voting client's bundle that the ballot
	// box serves (ballotbox.ClientHash). It is optional.
	ClientHash []byte `cbor:"client_hash,omitempty"`
}

// Algorithms names the algorithms of an election by versioned identifiers.
type Algorithms struct {
	LogHash          string `cbor:"log_hash"`
	TreeHead         string `cbor:"tree_head_signature"`
	Credential       string `cbor:"credential"`
	BallotSignature  string `cbor:"ballot_signature"`
	BallotEncryption string `cbor:"ballot_encryption"`
	// ReceiptSignature is present exactly in receipt mode full.
	ReceiptSignature string `cbor:"receipt_signature,omitempty"`
}

// DefaultAlgorithms returns the v1 algorithms for a receipt mode.
func DefaultAlgorithms(receiptMode string) Algorithms {
	a := Algorithms{
		LogHash:          AlgLogHash,
		TreeHead:         AlgTreeHead,
		Credential:       credential.Algorithm,
		BallotSignature:  ballot.SignatureAlgorithm,
		BallotEncryption: ballot.EncryptionAlgorithm,
	}
	if receiptMode == ReceiptFull {
		a.ReceiptSignature = ballot.SignatureAlgorithm
	}
	return a
}

// Validate reports whether the manifest is well-formed, uses only known
// algorithm identifiers and holds well-formed keys.
func (m Manifest) Validate() error {
	if m.Version != ManifestVersion {
		return fmt.Errorf("publog: unknown manifest version %d", m.Version)
	}
	if len(m.Nonce) < 16 {
		return errors.New("publog: manifest nonce is shorter than 16 bytes")
	}
	if m.ReceiptMode != ReceiptFull && m.ReceiptMode != ReceiptNone {
		return fmt.Errorf("publog: unknown receipt mode %q", m.ReceiptMode)
	}
	// Comparing with the defaults rejects every unknown identifier.
	if m.Algorithms != DefaultAlgorithms(m.ReceiptMode) {
		return fmt.Errorf("publog: unknown or misplaced algorithm identifier in %+v", m.Algorithms)
	}
	if len(m.LogKey) != ed25519.PublicKeySize {
		return errors.New("publog: log key has the wrong size")
	}
	if _, err := credential.ParseIssuingKey(m.IssuingKey); err != nil {
		return err
	}
	if err := ballot.CheckElectionKey(m.ElectionKey); err != nil {
		return err
	}
	if full := m.ReceiptMode == ReceiptFull; full && len(m.ReceiptKey) != ed25519.PublicKeySize {
		return errors.New("publog: receipt key has the wrong size")
	} else if !full && len(m.ReceiptKey) != 0 {
		return errors.New("publog: receipt key in receipt mode none")
	}
	if len(m.ClientHash) != 0 && len(m.ClientHash) != merkle.HashSize {
		return errors.New("publog: client hash has the wrong size")
	}
	return m.Tally.Validate()
}

// entry is the encoded form of a log entry: an array of the type and the
// body. The body is a map.
type entry struct {
	_    struct{} `cbor:",toarray"`
	Type string
	Body canon.Raw
}

// EncodeEntry returns the canonical encoding of a log entry. This is the
// byte string that the leaf hash covers.
func EncodeEntry(typ string, body any) ([]byte, error) {
	if !knownType(typ) {
		return nil, fmt.Errorf("publog: unknown entry type %q", typ)
	}
	raw, err := canon.Marshal(body)
	if err != nil {
		return nil, err
	}
	if !isMap(raw) {
		return nil, errors.New("publog: entry body is not a map")
	}
	return canon.Marshal(entry{Type: typ, Body: raw})
}

// DecodeEntry splits an encoded log entry into its type and its encoded
// body. It rejects entries that are not canonical or of an unknown type.
func DecodeEntry(data []byte) (typ string, body []byte, err error) {
	var e entry
	if err := canon.Unmarshal(data, &e); err != nil {
		return "", nil, err
	}
	if !knownType(e.Type) {
		return "", nil, fmt.Errorf("publog: unknown entry type %q", e.Type)
	}
	if !isMap(e.Body) {
		return "", nil, errors.New("publog: entry body is not a map")
	}
	return e.Type, e.Body, nil
}

// isMap reports whether an encoded item is a map (CBOR major type 5).
func isMap(raw []byte) bool {
	return len(raw) > 0 && raw[0]>>5 == 5
}

// ElectionID returns the ID of the election that an encoded manifest entry
// defines: the leaf hash of log entry 0.
func ElectionID(manifestEntry []byte) merkle.Hash {
	return merkle.LeafHash(manifestEntry)
}
