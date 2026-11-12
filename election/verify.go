package election

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/ansiwen/stimmig/ballot"
	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/credential"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/publog"
	"github.com/ansiwen/stimmig/tally"
)

// Phases that a log can end in.
const (
	PhaseSetup              = "setup"               // manifest only
	PhaseRegistration       = "registration"        // roll published
	PhaseRegistrationClosed = "registration closed" // voting may be open
	PhaseClosing            = "closing"             // ballots published, count not yet
	PhaseVotingClosed       = "voting closed"
	PhaseTallying           = "tallying" // key published, result not yet
	PhaseComplete           = "complete"
)

// Report describes a verified election log.
type Report struct {
	Log *publog.Report
	// Phase is the phase the log ends in. Only a complete log has a result.
	Phase    string
	Eligible uint64
	Issued   uint64
	Cast     uint64
	// Undecryptable counts ballots without a ranking. Rankings that break
	// the ballot rules are counted in Result.Invalid.
	Undecryptable uint64
	Result        *tally.Result
}

// Verify checks a log export end to end (SPEC.md section 12):
//
//  1. The log structure: canonical encoding, tree head roots and
//     signatures (publog.Verify).
//  2. Every issuance refers to a distinct entry of the roll, with
//     consecutive sequence numbers.
//  3. Cast ≤ issued ≤ eligible, and the logged counts are the real ones.
//  4. Every ballot carries a valid registrar signature and ballot
//     signature, no credential is used twice, and the ballots are ordered
//     by leaf hash.
//  5. The published election key matches the public key in the manifest,
//     and there is one ballot_plain entry per ballot, in order, equal to
//     the recomputed decryption.
//  6. The recomputed tally equals the logged result, byte for byte.
//
// The entries must follow the election lifecycle. A log that ends before
// the result is accepted as far as it goes; Report.Phase tells how far.
//
// visit, if not nil, is called for every entry after it passed its checks.
func Verify(r io.Reader, visit func(index uint64, typ string, body []byte) error) (*Report, error) {
	v := &verifier{rep: &Report{Phase: PhaseSetup}}
	logRep, err := publog.Verify(r, func(rep *publog.Report, index uint64, typ string, body []byte) error {
		if err := v.entry(rep, index, typ, body); err != nil {
			return err
		}
		if visit != nil {
			return visit(index, typ, body)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	v.rep.Log = logRep
	return v.rep, nil
}

type verifier struct {
	rep        *Report
	last       string // type of the previous entry
	issuingKey *rsa.PublicKey

	roll        map[merkle.Hash]bool // roll reference to "credential issued"
	credentials map[merkle.Hash]bool // credential keys that voted
	lastLeaf    merkle.Hash
	ballots     []Ballot
	indexes     []uint64 // log index of each ballot
	private     []byte
	plains      uint64
	rankings    []tally.Ballot
}

// follows lists, for every entry type, the types that may come directly
// after it.
var follows = map[string][]string{
	publog.TypeManifest:          {publog.TypeRollCommit},
	publog.TypeRollCommit:        {publog.TypeIssuance, publog.TypeRegistrationClose},
	publog.TypeIssuance:          {publog.TypeIssuance, publog.TypeRegistrationClose},
	publog.TypeRegistrationClose: {publog.TypeBallot, publog.TypeVotingClose},
	publog.TypeBallot:            {publog.TypeBallot, publog.TypeVotingClose},
	publog.TypeVotingClose:       {publog.TypeElectionKey},
	publog.TypeElectionKey:       {publog.TypeBallotPlain, publog.TypeResult},
	publog.TypeBallotPlain:       {publog.TypeBallotPlain, publog.TypeResult},
	publog.TypeResult:            {},
}

func (v *verifier) entry(log *publog.Report, index uint64, typ string, body []byte) error {
	if index > 0 {
		ok := false
		for _, t := range follows[v.last] {
			ok = ok || t == typ
		}
		if !ok {
			return fmt.Errorf("must not follow a %s entry", v.last)
		}
	}
	v.last = typ
	id := log.ElectionID
	switch typ {
	case publog.TypeManifest:
		key, err := credential.ParseIssuingKey(log.Manifest.IssuingKey)
		if err != nil {
			return err
		}
		v.issuingKey = key

	case publog.TypeRollCommit:
		var roll RollCommit
		if err := canon.Unmarshal(body, &roll); err != nil {
			return err
		}
		if err := checkRoll(roll.References); err != nil {
			return err
		}
		v.roll = make(map[merkle.Hash]bool, len(roll.References))
		for _, ref := range roll.References {
			v.roll[merkle.Hash(ref)] = false
		}
		v.rep.Eligible = uint64(len(roll.References))
		v.rep.Phase = PhaseRegistration

	case publog.TypeIssuance:
		var iss Issuance
		if err := canon.Unmarshal(body, &iss); err != nil {
			return err
		}
		if len(iss.RollReference) != merkle.HashSize {
			return errors.New("roll reference is not 32 bytes")
		}
		ref := merkle.Hash(iss.RollReference)
		issued, ok := v.roll[ref]
		if !ok {
			return errors.New("roll reference is not in the roll")
		}
		if issued {
			return errors.New("second credential for the same roll reference")
		}
		if iss.Sequence != v.rep.Issued {
			return fmt.Errorf("sequence number %d, want %d", iss.Sequence, v.rep.Issued)
		}
		v.roll[ref] = true
		v.rep.Issued++

	case publog.TypeRegistrationClose:
		var c RegistrationClose
		if err := canon.Unmarshal(body, &c); err != nil {
			return err
		}
		if c.Issued != v.rep.Issued {
			return fmt.Errorf("logged issued count %d, but %d issuance entries", c.Issued, v.rep.Issued)
		}
		if v.rep.Issued > v.rep.Eligible {
			return errors.New("more credentials issued than voters eligible")
		}
		v.credentials = map[merkle.Hash]bool{}
		v.rep.Phase = PhaseRegistrationClosed

	case publog.TypeBallot:
		var b Ballot
		if err := canon.Unmarshal(body, &b); err != nil {
			return err
		}
		if err := credential.Verify(v.issuingKey, id, b.CredentialKey, b.CredentialSignature); err != nil {
			return err
		}
		if err := ballot.Verify(b.CredentialKey, id, b.Ciphertext, b.Signature); err != nil {
			return err
		}
		cred := merkle.Hash(b.CredentialKey)
		if v.credentials[cred] {
			return errors.New("credential used twice")
		}
		v.credentials[cred] = true
		leaf, err := BallotLeaf(b)
		if err != nil {
			return err
		}
		if len(v.ballots) > 0 && bytes.Compare(v.lastLeaf[:], leaf[:]) >= 0 {
			return errors.New("ballots are not ordered by leaf hash")
		}
		v.lastLeaf = leaf
		v.ballots = append(v.ballots, b)
		v.indexes = append(v.indexes, index)
		v.rep.Cast++
		if v.rep.Cast > v.rep.Issued {
			return errors.New("more ballots cast than credentials issued")
		}
		v.rep.Phase = PhaseClosing

	case publog.TypeVotingClose:
		var c VotingClose
		if err := canon.Unmarshal(body, &c); err != nil {
			return err
		}
		if c.Cast != v.rep.Cast {
			return fmt.Errorf("logged cast count %d, but %d ballot entries", c.Cast, v.rep.Cast)
		}
		v.rep.Phase = PhaseVotingClosed

	case publog.TypeElectionKey:
		var k KeyRelease
		if err := canon.Unmarshal(body, &k); err != nil {
			return err
		}
		if err := ballot.MatchElectionKey(log.Manifest.ElectionKey, k.PrivateKey); err != nil {
			return err
		}
		v.private = k.PrivateKey
		v.rep.Phase = PhaseTallying

	case publog.TypeBallotPlain:
		if v.plains >= v.rep.Cast {
			return errors.New("more ballot_plain entries than ballots")
		}
		want, err := openBallot(id, v.private, v.indexes[v.plains], v.ballots[v.plains])
		if err != nil {
			return err
		}
		encoded, err := canon.Marshal(want)
		if err != nil {
			return err
		}
		if !bytes.Equal(encoded, body) {
			return fmt.Errorf("does not match the decryption of ballot entry %d", want.Ballot)
		}
		if want.Ranking != nil {
			v.rankings = append(v.rankings, *want.Ranking)
		} else {
			v.rep.Undecryptable++
		}
		v.plains++

	case publog.TypeResult:
		if v.plains != v.rep.Cast {
			return fmt.Errorf("%d ballot_plain entries for %d ballots", v.plains, v.rep.Cast)
		}
		res, err := tally.Tally(log.Manifest.Tally, v.rankings)
		if err != nil {
			return err
		}
		encoded, err := canon.Marshal(res)
		if err != nil {
			return err
		}
		if !bytes.Equal(encoded, body) {
			return errors.New("logged result differs from the recomputed tally")
		}
		v.rep.Result = res
		v.rep.Phase = PhaseComplete
	}
	return nil
}
