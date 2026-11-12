// Package client implements the voter's side of an election: it creates
// and stores the credential, casts the ballot and checks the receipt
// (SPEC.md sections 5 and 11). The command line client uses it now; the
// web client will run the same code.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ansiwen/stimmig/api"
	"github.com/ansiwen/stimmig/ballot"
	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/credential"
	"github.com/ansiwen/stimmig/election"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/publog"
	"github.com/ansiwen/stimmig/tally"
)

// State is everything the voter's client stores for one election. It
// holds the credential private key and must stay on the voter's device.
type State struct {
	LogURL       string `json:"log_url"`
	RegistrarURL string `json:"registrar_url"`
	BallotBoxURL string `json:"ballot_box_url"`
	ElectionID   []byte `json:"election_id"`
	// CredentialKey is the Ed25519 private key of the credential and
	// CredentialSignature the registrar's signature on it.
	CredentialKey       []byte `json:"credential_key,omitempty"`
	CredentialSignature []byte `json:"credential_signature,omitempty"`
	// RollReference is the voter's entry in the public roll.
	RollReference []byte `json:"roll_reference,omitempty"`
	// Ballot is the encoded ballot that was cast, and Receipt the ballot
	// box's receipt for it.
	Ballot  []byte `json:"ballot,omitempty"`
	Receipt []byte `json:"receipt,omitempty"`
}

// PollInterval is the pause between two requests for the credential while
// the voter logs in.
var PollInterval = 2 * time.Second

func (st *State) id() merkle.Hash { return merkle.Hash(st.ElectionID) }

// log fetches the public log and verifies it completely. The client trusts
// nothing of an election but its ID.
func (st *State) log(ctx context.Context) (*election.Report, error) {
	if len(st.ElectionID) != merkle.HashSize {
		return nil, errors.New("client: the election ID is not 32 bytes")
	}
	export, err := api.Export(ctx, &api.Client{Base: st.LogURL}, st.id())
	if err != nil {
		return nil, err
	}
	rep, err := election.Verify(bytes.NewReader(export), nil)
	if err != nil {
		return nil, fmt.Errorf("client: the public log does not verify: %w", err)
	}
	if rep.Log.ElectionID != st.id() {
		return nil, errors.New("client: the log service answered with another election")
	}
	return rep, nil
}

// Register obtains the voting credential. It creates the credential key,
// sends the blinded credential to the registrar, calls login with the URL
// where the voter authenticates, waits until the voter has done so, and
// stores the unblinded credential in the state.
func Register(ctx context.Context, st *State, login func(loginURL string) error) error {
	if st.CredentialSignature != nil {
		return errors.New("client: this state already holds a credential")
	}
	rep, err := st.log(ctx)
	if err != nil {
		return err
	}
	// Manifest.Validate has checked the issuing key during verification.
	issuingKey, err := credential.ParseIssuingKey(rep.Log.Manifest.IssuingKey)
	if err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	req, err := credential.NewRequest(rand.Reader, issuingKey, st.id(), pub)
	if err != nil {
		return err
	}
	registrar := &api.Client{Base: st.RegistrarURL}
	var session api.Session
	if err := registrar.Do(ctx, "POST", api.ElectionPath(st.id())+"/sessions", api.SessionRequest{Blinded: req.Blinded}, &session); err != nil {
		return err
	}
	if err := login(session.URL); err != nil {
		return err
	}
	var cred api.Credential
	for {
		err := registrar.Do(ctx, "GET", "/v1/sessions/"+session.Session, nil, &cred)
		if err == nil {
			break
		}
		if !api.IsStatus(err, http.StatusNotFound) {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("client: no credential received: %w", ctx.Err())
		case <-time.After(PollInterval):
		}
	}
	sig, err := req.Finalize(cred.BlindSignature)
	if err != nil {
		return err
	}
	st.CredentialKey, st.CredentialSignature, st.RollReference = priv, sig, cred.RollReference
	return nil
}

// SubmitEmail enters an address into the form of the email identity
// provider at loginURL. The provider then mails the login link.
func SubmitEmail(ctx context.Context, loginURL, address string) error {
	u, err := url.Parse(loginURL)
	if err != nil {
		return err
	}
	form := url.Values{"state": {u.Query().Get("state")}, "address": {address}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("client: the email form answered %s", resp.Status)
	}
	return nil
}

// ParseRanking reads a ranking such as "A>B=C>D": candidates separated by
// ">" from best to worst, with "=" between candidates of equal rank. The
// empty text is the empty ballot.
func ParseRanking(s string) tally.Ballot {
	ranking := tally.Ballot{}
	if strings.TrimSpace(s) == "" {
		return ranking
	}
	for _, group := range strings.Split(s, ">") {
		var rank []string
		for _, c := range strings.Split(group, "=") {
			rank = append(rank, strings.TrimSpace(c))
		}
		ranking = append(ranking, rank)
	}
	return ranking
}

// Cast encrypts and signs the ranking, sends it to the ballot box and, in
// receipt mode full, checks the receipt before it stores ballot and
// receipt. The ranking must follow the ballot rules of the election.
func Cast(ctx context.Context, st *State, ranking tally.Ballot) error {
	if st.CredentialSignature == nil {
		return errors.New("client: this state holds no credential, or the ballot is already cast")
	}
	rep, err := st.log(ctx)
	if err != nil {
		return err
	}
	m := rep.Log.Manifest
	// The tally would report a ballot against the rules as invalid; tell
	// the voter now.
	check, err := tally.Tally(m.Tally, []tally.Ballot{ranking})
	if err != nil {
		return err
	}
	if len(check.Invalid) > 0 {
		return fmt.Errorf("client: this ranking is not a valid ballot: %s", check.Invalid[0].Reason)
	}
	b, err := election.Cast(rand.Reader, m, st.id(), ed25519.PrivateKey(st.CredentialKey), st.CredentialSignature, ranking)
	if err != nil {
		return err
	}
	if st.Ballot != nil {
		// A ballot was built before; send that one again, because the
		// ballot box may already have it.
		if err := canon.Unmarshal(st.Ballot, &b); err != nil {
			return err
		}
	} else if st.Ballot, err = canon.Marshal(b); err != nil {
		return err
	}
	var receipt api.Receipt
	if err := (&api.Client{Base: st.BallotBoxURL}).Do(ctx, "POST", api.ElectionPath(st.id())+"/ballots", b, &receipt); err != nil {
		return err
	}
	if m.ReceiptMode == publog.ReceiptFull {
		leaf, err := election.BallotLeaf(b)
		if err != nil {
			return err
		}
		if err := ballot.VerifyReceipt(m.ReceiptKey, st.id(), leaf, receipt.Receipt); err != nil {
			return fmt.Errorf("client: the ballot box answered without a valid receipt: %w", err)
		}
		st.Receipt = receipt.Receipt
		return nil
	}
	// Receipt mode none: keep nothing that could show the vote to others
	// (SPEC.md section 5.5).
	st.CredentialKey, st.CredentialSignature, st.Ballot = nil, nil, nil
	return nil
}

// Checked is the outcome of a receipt check.
type Checked struct {
	// Phase is the phase of the public log.
	Phase string
	// Included reports that the ballot is in the log, under the final tree
	// head.
	Included bool
	// Ranking is the voter's decrypted ballot as the log shows it, once the
	// election is complete. Invalid is the reason if it did not decrypt.
	Ranking tally.Ballot
	Invalid string
	Result  *tally.Result
}

// Check verifies the public log and looks for the voter's ballot in it
// (SPEC.md section 5.4). After the close, a ballot with a valid receipt
// that is missing from the log is evidence against the ballot box, and
// Check returns an error that says so.
func Check(ctx context.Context, st *State) (*Checked, error) {
	if st.Ballot == nil {
		return nil, errors.New("client: this state holds no ballot")
	}
	rep, err := st.log(ctx)
	if err != nil {
		return nil, err
	}
	var mine election.Ballot
	if err := canon.Unmarshal(st.Ballot, &mine); err != nil {
		return nil, err
	}
	leaf, err := election.BallotLeaf(mine)
	if err != nil {
		return nil, err
	}
	out := &Checked{Phase: rep.Phase, Result: rep.Result}
	if rep.Phase == election.PhaseSetup || rep.Phase == election.PhaseRegistration || rep.Phase == election.PhaseRegistrationClosed {
		return out, nil // the ballots are not published before the close
	}
	// The inclusion proof ties the ballot to the signed final tree head.
	final := rep.Log.Final
	var proof api.Proof
	path := fmt.Sprintf("%s/inclusion?leaf=%x&size=%d", api.ElectionPath(st.id()), leaf[:], final.Size)
	err = (&api.Client{Base: st.LogURL}).Do(ctx, "GET", path, nil, &proof)
	if api.IsStatus(err, http.StatusNotFound) {
		if st.Receipt != nil && ballot.VerifyReceipt(rep.Log.Manifest.ReceiptKey, st.id(), leaf, st.Receipt) == nil {
			return out, errors.New("client: the ballot is missing from the public log although the ballot box signed a receipt for it; the receipt is evidence of this")
		}
		return out, errors.New("client: the ballot is missing from the public log")
	}
	if err != nil {
		return out, err
	}
	hashes := make([]merkle.Hash, len(proof.Hashes))
	for i, h := range proof.Hashes {
		if len(h) != merkle.HashSize {
			return out, errors.New("client: malformed inclusion proof")
		}
		hashes[i] = merkle.Hash(h)
	}
	if err := merkle.VerifyInclusion(leaf, proof.Index, final.Size, hashes, merkle.Hash(final.Root)); err != nil {
		return out, err
	}
	out.Included = true
	// Show the voter the decrypted ballot of the log.
	if rep.Phase == election.PhaseComplete {
		for _, b := range rep.Ballots {
			if !bytes.Equal(b.CredentialKey, mine.CredentialKey) {
				continue
			}
			ranking, err := ballot.Open(st.id(), rep.ElectionPrivateKey, b.CredentialKey, b.Ciphertext)
			switch {
			case errors.Is(err, ballot.ErrDecrypt):
				out.Invalid = election.InvalidDecrypt
			case errors.Is(err, ballot.ErrMalformed):
				out.Invalid = election.InvalidMalformed
			case err != nil:
				return out, err
			default:
				out.Ranking = ranking
			}
		}
	}
	return out, nil
}
