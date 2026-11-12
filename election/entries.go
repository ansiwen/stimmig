// Package election implements the election protocol of assurance profile A
// on top of the public log: the bodies of the log entries, the steps that
// write them, and the end-to-end verification of a log export
// (SPEC.md sections 5, 7 and 12).
package election

import (
	"bytes"
	"context"
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

// RollRecord returns the roll_commit record for the roll references, which
// it sorts.
func RollRecord(references [][]byte) (publog.Record, error) {
	refs := append([][]byte{}, references...) // not nil: an empty roll is an empty array
	sort.Slice(refs, func(i, j int) bool { return bytes.Compare(refs[i], refs[j]) < 0 })
	return publog.Record{Type: publog.TypeRollCommit, Body: RollCommit{References: refs}}, checkRoll(refs)
}

// PublishRoll appends the roll_commit entry and signs a tree head.
func PublishRoll(ctx context.Context, l *publog.Log, references [][]byte) error {
	rec, err := RollRecord(references)
	if err != nil {
		return err
	}
	return appendAndSign(ctx, l, rec.Type, rec.Body)
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

func appendAndSign(ctx context.Context, l *publog.Log, typ string, body any) error {
	if _, err := l.Append(ctx, typ, body); err != nil {
		return err
	}
	_, err := l.Head(ctx)
	return err
}

// PublishIssuance appends an issuance entry.
func PublishIssuance(ctx context.Context, l *publog.Log, rollReference []byte, sequence uint64) error {
	_, err := l.Append(ctx, publog.TypeIssuance, Issuance{RollReference: rollReference, Sequence: sequence})
	return err
}

// CloseRegistration appends the registration_close entry and signs a tree
// head.
func CloseRegistration(ctx context.Context, l *publog.Log, issued uint64) error {
	return appendAndSign(ctx, l, publog.TypeRegistrationClose, RegistrationClose{Issued: issued})
}

// BallotRecords returns the records that close the voting: all ballots
// ordered by leaf hash, so that the arrival order is not revealed, then the
// voting_close entry.
func BallotRecords(ballots []Ballot) ([]publog.Record, error) {
	type item struct {
		leaf merkle.Hash
		b    Ballot
	}
	items := make([]item, len(ballots))
	for i, b := range ballots {
		leaf, err := BallotLeaf(b)
		if err != nil {
			return nil, err
		}
		items[i] = item{leaf, b}
	}
	sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].leaf[:], items[j].leaf[:]) < 0 })
	records := make([]publog.Record, 0, len(items)+1)
	for _, it := range items {
		records = append(records, publog.Record{Type: publog.TypeBallot, Body: it.b})
	}
	return append(records, publog.Record{Type: publog.TypeVotingClose, Body: VotingClose{Cast: uint64(len(ballots))}}), nil
}

// PublishBallots closes the voting: it appends the ballot records and
// signs a tree head.
func PublishBallots(ctx context.Context, l *publog.Log, ballots []Ballot) error {
	records, err := BallotRecords(ballots)
	if err != nil {
		return err
	}
	_, err = l.AppendAll(ctx, -1, records)
	return err
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

// TallyRecords returns the records that end an election: the election
// private key, one ballot_plain entry per ballot, and the result computed
// from the decrypted rankings in log order. ballots and indexes are the
// ballot entries of the log and their log indexes, as Report holds them.
func TallyRecords(m publog.Manifest, electionID merkle.Hash, private []byte, ballots []Ballot, indexes []uint64) ([]publog.Record, *tally.Result, error) {
	if err := ballot.MatchElectionKey(m.ElectionKey, private); err != nil {
		return nil, nil, err
	}
	records := []publog.Record{{Type: publog.TypeElectionKey, Body: KeyRelease{PrivateKey: private}}}
	var rankings []tally.Ballot
	for i, b := range ballots {
		plain, err := openBallot(electionID, private, indexes[i], b)
		if err != nil {
			return nil, nil, err
		}
		records = append(records, publog.Record{Type: publog.TypeBallotPlain, Body: plain})
		if plain.Ranking != nil {
			rankings = append(rankings, *plain.Ranking)
		}
	}
	res, err := tally.Tally(m.Tally, rankings)
	if err != nil {
		return nil, nil, err
	}
	return append(records, publog.Record{Type: publog.TypeResult, Body: res}), res, nil
}

// PublishTally reads the ballots of the log, appends the tally records and
// signs a tree head.
func PublishTally(ctx context.Context, l *publog.Log, m publog.Manifest, private []byte) (*tally.Result, error) {
	size, err := l.Size(ctx)
	if err != nil {
		return nil, err
	}
	var ballots []Ballot
	var indexes []uint64
	for index := uint64(0); index < size; index++ {
		data, err := l.Entry(ctx, index)
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
		ballots = append(ballots, b)
		indexes = append(indexes, index)
	}
	records, res, err := TallyRecords(m, l.ElectionID(), private, ballots, indexes)
	if err != nil {
		return nil, err
	}
	_, err = l.AppendAll(ctx, -1, records)
	return res, err
}
