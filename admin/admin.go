// Package admin drives an election through the three services with their
// admin tokens: creating it, publishing the roll, closing and opening the
// phases, tallying and reading its state. The admin command and the admin web
// page use it.
package admin

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode"

	"github.com/ansiwen/stimmig/api"
	"github.com/ansiwen/stimmig/election"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/publog"
	"github.com/ansiwen/stimmig/tally"
)

// Client holds the clients of the three services, with their admin tokens.
type Client struct {
	Log, Registrar, BallotBox *api.Client
}

// Definition is what the admin writes to define an election. The keys, the
// nonce and the algorithms are added by Create.
type Definition struct {
	Title       string         `json:"title"`
	ReceiptMode string         `json:"receipt_mode"` // "full" (default) or "none"
	Tally       tally.Manifest `json:"tally"`
	// Schedule gives times in RFC 3339 at which the services close and open the
	// phases by themselves; every time is optional.
	Schedule struct {
		RegistrationClose string `json:"registration_close"`
		VotingOpen        string `json:"voting_open"`
		VotingClose       string `json:"voting_close"`
	} `json:"schedule"`
}

// ParseSchedule converts the times of a definition. It returns nil if no time
// is given.
func (d Definition) ParseSchedule() (*publog.Schedule, error) {
	var out publog.Schedule
	for _, t := range []struct {
		name, text string
		to         *uint64
	}{
		{"registration_close", d.Schedule.RegistrationClose, &out.RegistrationClose},
		{"voting_open", d.Schedule.VotingOpen, &out.VotingOpen},
		{"voting_close", d.Schedule.VotingClose, &out.VotingClose},
	} {
		if t.text == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339, t.text)
		if err != nil || at.Unix() <= 0 {
			return nil, fmt.Errorf("schedule.%s: not a time in RFC 3339: %q", t.name, t.text)
		}
		*t.to = uint64(at.Unix()) //nolint:gosec // checked above
	}
	if out == (publog.Schedule{}) {
		return nil, nil
	}
	return &out, out.Validate()
}

// manifest builds the manifest of a definition, without the keys.
func (d Definition) manifest() (publog.Manifest, error) {
	if d.ReceiptMode == "" {
		d.ReceiptMode = publog.ReceiptFull
	}
	m := publog.Manifest{
		Version:     publog.ManifestVersion,
		Title:       d.Title,
		Nonce:       make([]byte, 16),
		Tally:       d.Tally,
		Algorithms:  publog.DefaultAlgorithms(d.ReceiptMode),
		ReceiptMode: d.ReceiptMode,
	}
	if d.ReceiptMode != publog.ReceiptFull && d.ReceiptMode != publog.ReceiptNone {
		return m, fmt.Errorf("receipt_mode must be %q or %q", publog.ReceiptFull, publog.ReceiptNone)
	}
	if strings.TrimSpace(d.Title) == "" {
		return m, errors.New("the election needs a title")
	}
	if _, err := rand.Read(m.Nonce); err != nil {
		return m, err
	}
	var err error
	if m.Schedule, err = d.ParseSchedule(); err != nil {
		return m, err
	}
	// Check the definition before any service creates keys for it.
	return m, m.Tally.Validate()
}

// Preview checks a definition without creating anything, and returns the
// number of different ballots it allows. If that is larger than the number of
// voters, a ranking can identify a ballot (SPEC.md section 2).
func Preview(d Definition) (possible *big.Int, err error) {
	m, err := d.manifest()
	if err != nil {
		return nil, err
	}
	return m.Tally.PossibleBallots()
}

// Create collects the public keys of the three services, builds the manifest
// and registers the election with each service. It returns the election ID.
func (c *Client) Create(ctx context.Context, def Definition) (merkle.Hash, error) {
	m, err := def.manifest()
	if err != nil {
		return merkle.Hash{}, err
	}
	var logKey api.LogKey
	if err := c.Log.Do(ctx, "POST", "/v1/keys", nil, &logKey); err != nil {
		return merkle.Hash{}, fmt.Errorf("log: %w", err)
	}
	var regKeys api.RegistrarKeys
	if err := c.Registrar.Do(ctx, "POST", "/v1/keys", nil, &regKeys); err != nil {
		return merkle.Hash{}, fmt.Errorf("registrar: %w", err)
	}
	m.LogKey, m.IssuingKey, m.IssuingKeyProof, m.ElectionKey = logKey.LogKey, regKeys.IssuingKey, regKeys.IssuingKeyProof, regKeys.ElectionKey
	if m.ReceiptMode == publog.ReceiptFull {
		var boxKey api.BallotBoxKey
		if err := c.BallotBox.Do(ctx, "POST", "/v1/keys", nil, &boxKey); err != nil {
			return merkle.Hash{}, fmt.Errorf("ballot box: %w", err)
		}
		m.ReceiptKey = boxKey.ReceiptKey
	}
	// The hash of the voting client, if the ballot box serves one.
	var bundle api.ClientBundle
	if err := c.BallotBox.Do(ctx, "GET", "/v1/client", nil, &bundle); err == nil {
		m.ClientHash = bundle.Hash
	} else if !api.IsStatus(err, http.StatusNotFound) {
		return merkle.Hash{}, fmt.Errorf("ballot box: %w", err)
	}
	var head publog.TreeHead
	if err := c.Log.Do(ctx, "POST", "/v1/elections", m, &head); err != nil {
		return merkle.Hash{}, fmt.Errorf("log: %w", err)
	}
	if err := c.Registrar.Do(ctx, "POST", "/v1/elections", m, nil); err != nil {
		return merkle.Hash{}, fmt.Errorf("registrar: %w", err)
	}
	if err := c.BallotBox.Do(ctx, "POST", "/v1/elections", m, nil); err != nil {
		return merkle.Hash{}, fmt.Errorf("ballot box: %w", err)
	}
	return merkle.Hash(head.ElectionID), nil
}

// ParseVoters reads a list of voters, one per line: an email address, or
// oidc:<issuer>#<sub> for OpenID Connect. Empty lines are ignored.
func ParseVoters(text string) (api.Roll, error) {
	var roll api.Roll
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if subject, ok := strings.CutPrefix(line, "oidc:"); ok {
			// <issuer>#<sub>, without blanks: a subject that never matches a login
			// excludes the voter for good.
			if i := strings.Index(subject, "#"); i < 1 || i == len(subject)-1 || strings.ContainsFunc(subject, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
				return roll, fmt.Errorf("line %d: %q is not oidc:<issuer>#<sub>", n, line)
			}
			roll.Voters = append(roll.Voters, api.Voter{Provider: "oidc", Subject: subject})
		} else if line != "" {
			// The roll cannot be changed once it is published, and a line such as
			// "Ada <ada@example.org>" or two addresses would be a voter who can never
			// log in.
			if a, err := mail.ParseAddress(line); err != nil || a.Address != line {
				return roll, fmt.Errorf("line %d: %q is not a plain email address", n, line)
			}
			// The email provider reports addresses in lower case.
			roll.Voters = append(roll.Voters, api.Voter{Provider: "email", Subject: strings.ToLower(line)})
		}
	}
	return roll, sc.Err()
}

// Roll publishes the roll and opens the registration. The warning is not
// empty if the election allows more different ballots than it has voters: a
// voter can then make a ballot recognisable by an unusual ranking.
func (c *Client) Roll(ctx context.Context, id merkle.Hash, roll api.Roll) (warning string, err error) {
	if err := c.Registrar.Do(ctx, "PUT", api.ElectionPath(id)+"/roll", roll, nil); err != nil {
		return "", err
	}
	st, err := c.Status(ctx, id)
	if err != nil {
		return "", err
	}
	possible, ok := new(big.Int).SetString(st.PossibleBallots, 10)
	if ok && possible.Cmp(big.NewInt(int64(len(roll.Voters)))) > 0 {
		return fmt.Sprintf("%s different ballots are possible, but only %d voters are eligible. "+
			"A voter can make a ballot recognisable by an unusual ranking. Consider a lower max_ranks.",
			possible, len(roll.Voters)), nil
	}
	return "", nil
}

// CloseRegistration closes the registration.
func (c *Client) CloseRegistration(ctx context.Context, id merkle.Hash) error {
	return c.Registrar.Do(ctx, "POST", api.ElectionPath(id)+"/close", nil, nil)
}

// OpenVoting opens the voting; the registration must be closed.
func (c *Client) OpenVoting(ctx context.Context, id merkle.Hash) error {
	return c.BallotBox.Do(ctx, "POST", api.ElectionPath(id)+"/open", nil, nil)
}

// CloseVoting closes the voting and publishes the ballots.
func (c *Client) CloseVoting(ctx context.Context, id merkle.Hash) error {
	return c.BallotBox.Do(ctx, "POST", api.ElectionPath(id)+"/close", nil, nil)
}

// Tally publishes the election key, the plaintexts and the result.
func (c *Client) Tally(ctx context.Context, id merkle.Hash) (*tally.Result, error) {
	var res tally.Result
	if err := c.Registrar.Do(ctx, "POST", api.ElectionPath(id)+"/tally", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Status is the state of an election as the verified public log shows it.
type Status struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Phase    string `json:"phase"`
	Eligible uint64 `json:"eligible"`
	Issued   uint64 `json:"issued"`
	Cast     uint64 `json:"cast"`
	Entries  uint64 `json:"entries"`
	// Undecryptable is the number of ballots that did not decrypt, once the
	// election is complete.
	Undecryptable   uint64           `json:"undecryptable"`
	Method          tally.Method     `json:"method"`
	Candidates      []string         `json:"candidates"`
	Seats           int              `json:"seats"`
	MaxRanks        int              `json:"max_ranks"`
	ReceiptMode     string           `json:"receipt_mode"`
	PossibleBallots string           `json:"possible_ballots"`
	Schedule        *publog.Schedule `json:"schedule,omitempty"`
	Result          *tally.Result    `json:"result,omitempty"`
}

// Status fetches the log of an election, verifies it completely and
// summarises it.
func (c *Client) Status(ctx context.Context, id merkle.Hash) (*Status, error) {
	export, err := api.Export(ctx, c.Log, id)
	if err != nil {
		return nil, fmt.Errorf("log: %w", err)
	}
	rep, err := election.VerifyFor(bytes.NewReader(export), id)
	if err != nil {
		return nil, fmt.Errorf("the log does not verify: %w", err)
	}
	m := rep.Log.Manifest
	possible, err := m.Tally.PossibleBallots()
	if err != nil {
		return nil, err
	}
	maxRanks := m.Tally.MaxRanks
	if maxRanks == 0 {
		maxRanks = len(m.Tally.Candidates)
	}
	seats := max(m.Tally.Seats, 1)
	return &Status{
		ID: fmt.Sprintf("%x", id[:]), Title: m.Title, Phase: rep.Phase,
		Eligible: rep.Eligible, Issued: rep.Issued, Cast: rep.Cast, Entries: rep.Log.Entries,
		Undecryptable: rep.Undecryptable,
		Method:        m.Tally.Method, Candidates: m.Tally.Candidates, Seats: seats, MaxRanks: maxRanks,
		ReceiptMode: m.ReceiptMode, PossibleBallots: possible.String(), Schedule: m.Schedule, Result: rep.Result,
	}, nil
}

// Election is one entry of the list of elections.
type Election struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Phase is the phase at the registrar: setup, open or closed.
	Phase   string `json:"phase"`
	Tallied bool   `json:"tallied"`
}

// List returns the elections that the registrar knows, newest first.
func (c *Client) List(ctx context.Context) ([]Election, error) {
	var list api.ElectionList
	if err := c.Registrar.Do(ctx, "GET", "/v1/elections", nil, &list); err != nil {
		return nil, err
	}
	out := make([]Election, 0, len(list.Elections))
	for _, e := range list.Elections {
		out = append(out, Election{ID: hex.EncodeToString(e.ID), Title: e.Title, Phase: e.Phase, Tallied: e.Tallied})
	}
	return out, nil
}
