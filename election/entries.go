// Package election implements the election protocol of assurance profile A
// on top of the public log: the bodies of the log entries, the steps that
// write them, and the end-to-end verification of a log export
// (SPEC.md sections 5, 7 and 12).
package election

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"sort"

	"github.com/ansiwen/stimmig/ballot"
	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/credential"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/publog"
	"github.com/ansiwen/stimmig/tally"
)

// RollCommit is the body of the roll_commit entry: the pseudonymous
// electoral roll. The references are 32 bytes each and strictly ascending,
// so the roll has one encoding and no duplicates.
type RollCommit struct {
	References [][]byte `cbor:"references"`
}

// Issuance is the body of an issuance entry: one credential was handed out
// for a roll reference. Sequence numbers count from 0.
type Issuance struct {
	RollReference []byte `cbor:"roll_reference"`
	Sequence      uint64 `cbor:"sequence"`
}

// RegistrationClose is the body of the registration_close entry.
type RegistrationClose struct {
	Issued uint64 `cbor:"issued"`
}

// Ballot is the body of a ballot entry, and what a voter submits to the
// ballot box.
type Ballot struct {
	CredentialKey       []byte `cbor:"credential_key"`
	CredentialSignature []byte `cbor:"credential_signature"`
	Ciphertext          []byte `cbor:"ciphertext"`
	Signature           []byte `cbor:"signature"`
}

// VotingClose is the body of the voting_close entry.
type VotingClose struct {
	Cast uint64 `cbor:"cast"`
}

// KeyRelease is the body of the election_key entry: the published private
// key of the election.
type KeyRelease struct {
	PrivateKey []byte `cbor:"private_key"`
}

// BallotPlain is the body of a ballot_plain entry. Ballot is the log index
// of the ballot entry. Exactly one of Ranking and Invalid is present.
type BallotPlain struct {
	Ballot  uint64        `cbor:"ballot"`
	Ranking *tally.Ballot `cbor:"ranking,omitempty"`
	Invalid string        `cbor:"invalid,omitempty"`
}

// Reasons for a ballot_plain entry without a ranking. Rankings that break
// the ballot rules of the manifest are decrypted normally and reported as
// invalid by the tally in the result.
const (
	InvalidDecrypt   = "decryption-failed"
	InvalidMalformed = "malformed"
)

// The body of the result entry is a tally.Result.

// Cast builds a voter's ballot: it encrypts the ranking to the election key
// and signs the ciphertext with the credential key.
func Cast(random io.Reader, m publog.Manifest, electionID merkle.Hash, credentialKey ed25519.PrivateKey, credentialSignature []byte, ranking tally.Ballot) (Ballot, error) {
	pub, ok := credentialKey.Public().(ed25519.PublicKey)
	if !ok {
		return Ballot{}, errors.New("election: credential key is not an Ed25519 key")
	}
	ct, err := ballot.Seal(random, electionID, m.ElectionKey, pub, ranking)
	if err != nil {
		return Ballot{}, err
	}
	sig, err := ballot.Sign(credentialKey, electionID, ct)
	if err != nil {
		return Ballot{}, err
	}
	return Ballot{CredentialKey: pub, CredentialSignature: credentialSignature, Ciphertext: ct, Signature: sig}, nil
}

// CheckBallot verifies the registrar's signature on the credential and the
// credential's signature on the ciphertext. The ballot box calls it before
// it stores a ballot; it must also check that the credential has not voted.
func CheckBallot(m publog.Manifest, electionID merkle.Hash, b Ballot) error {
	issuingKey, err := credential.ParseIssuingKey(m.IssuingKey)
	if err != nil {
		return err
	}
	if err := credential.Verify(issuingKey, electionID, b.CredentialKey, b.CredentialSignature); err != nil {
		return err
	}
	return ballot.Verify(b.CredentialKey, electionID, b.Ciphertext, b.Signature)
}

// BallotLeaf returns the leaf hash that the ballot will have in the log.
// The receipt covers it.
func BallotLeaf(b Ballot) (merkle.Hash, error) {
	data, err := publog.EncodeEntry(publog.TypeBallot, b)
	if err != nil {
		return merkle.Hash{}, err
	}
	return merkle.LeafHash(data), nil
}

// PublishRoll appends the roll_commit entry and signs a tree head.
func PublishRoll(l *publog.Log, references [][]byte) error {
	refs := append([][]byte(nil), references...)
	sort.Slice(refs, func(i, j int) bool { return bytes.Compare(refs[i], refs[j]) < 0 })
	if err := checkRoll(refs); err != nil {
		return err
	}
	return appendAndSign(l, publog.TypeRollCommit, RollCommit{References: refs})
}

func checkRoll(refs [][]byte) error {
	for i, ref := range refs {
		if len(ref) != merkle.HashSize {
			return errors.New("election: roll reference is not 32 bytes")
		}
		if i > 0 && bytes.Compare(refs[i-1], ref) >= 0 {
			return errors.New("election: roll references are not strictly ascending")
		}
	}
	return nil
}

func appendAndSign(l *publog.Log, typ string, body any) error {
	if _, err := l.Append(typ, body); err != nil {
		return err
	}
	_, err := l.Head()
	return err
}

// PublishIssuance appends an issuance entry.
func PublishIssuance(l *publog.Log, rollReference []byte, sequence uint64) error {
	_, err := l.Append(publog.TypeIssuance, Issuance{RollReference: rollReference, Sequence: sequence})
	return err
}

// CloseRegistration appends the registration_close entry and signs a tree
// head.
func CloseRegistration(l *publog.Log, issued uint64) error {
	return appendAndSign(l, publog.TypeRegistrationClose, RegistrationClose{Issued: issued})
}

// PublishBallots closes the voting: it appends all ballots ordered by leaf
// hash, so that the arrival order is not revealed, then the voting_close
// entry, and signs a tree head.
func PublishBallots(l *publog.Log, ballots []Ballot) error {
	type item struct {
		leaf merkle.Hash
		b    Ballot
	}
	items := make([]item, len(ballots))
	for i, b := range ballots {
		leaf, err := BallotLeaf(b)
		if err != nil {
			return err
		}
		items[i] = item{leaf, b}
	}
	sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].leaf[:], items[j].leaf[:]) < 0 })
	for _, it := range items {
		if _, err := l.Append(publog.TypeBallot, it.b); err != nil {
			return err
		}
	}
	return appendAndSign(l, publog.TypeVotingClose, VotingClose{Cast: uint64(len(ballots))})
}

// openBallot decrypts one ballot for its ballot_plain entry.
func openBallot(electionID merkle.Hash, private []byte, index uint64, b Ballot) (BallotPlain, error) {
	ranking, err := ballot.Open(electionID, private, b.CredentialKey, b.Ciphertext)
	switch {
	case errors.Is(err, ballot.ErrDecrypt):
		return BallotPlain{Ballot: index, Invalid: InvalidDecrypt}, nil
	case errors.Is(err, ballot.ErrMalformed):
		return BallotPlain{Ballot: index, Invalid: InvalidMalformed}, nil
	case err != nil:
		return BallotPlain{}, err
	}
	return BallotPlain{Ballot: index, Ranking: &ranking}, nil
}

// PublishTally publishes the election private key, decrypts every ballot of
// the log into a ballot_plain entry, computes the result from the decrypted
// rankings in log order, appends it and signs a tree head.
func PublishTally(l *publog.Log, m publog.Manifest, private []byte) (*tally.Result, error) {
	if err := ballot.MatchElectionKey(m.ElectionKey, private); err != nil {
		return nil, err
	}
	var plains []BallotPlain
	var rankings []tally.Ballot
	for index := uint64(0); index < l.Size(); index++ {
		data, err := l.Entry(index)
		if err != nil {
			return nil, err
		}
		typ, body, err := publog.DecodeEntry(data)
		if err != nil {
			return nil, err
		}
		if typ != publog.TypeBallot {
			continue
		}
		var b Ballot
		if err := canon.Unmarshal(body, &b); err != nil {
			return nil, err
		}
		plain, err := openBallot(l.ElectionID(), private, index, b)
		if err != nil {
			return nil, err
		}
		plains = append(plains, plain)
		if plain.Ranking != nil {
			rankings = append(rankings, *plain.Ranking)
		}
	}
	res, err := tally.Tally(m.Tally, rankings)
	if err != nil {
		return nil, err
	}
	if _, err := l.Append(publog.TypeElectionKey, KeyRelease{PrivateKey: private}); err != nil {
		return nil, err
	}
	for _, plain := range plains {
		if _, err := l.Append(publog.TypeBallotPlain, plain); err != nil {
			return nil, err
		}
	}
	return res, appendAndSign(l, publog.TypeResult, res)
}
