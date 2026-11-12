package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/ansiwen/stimmig/api"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/publog"
	"github.com/ansiwen/stimmig/tally"
)

const adminHelp = `usage: stimmig admin <command> [flags]
commands:
  create -definition FILE        create an election; prints its ID
  roll -election ID -voters FILE publish the roll (one email address per line), open registration
  close-registration -election ID
  open-voting -election ID
  close-voting -election ID      close the voting and publish the ballots
  tally -election ID             publish the key, the plaintexts and the result
environment:
  STIMMIG_LOG_URL, STIMMIG_REGISTRAR_URL, STIMMIG_BALLOTBOX_URL
  STIMMIG_LOG_ADMIN_TOKEN, STIMMIG_REGISTRAR_ADMIN_TOKEN, STIMMIG_BALLOTBOX_ADMIN_TOKEN`

// definition is what the admin writes to define an election. The keys,
// the nonce and the algorithms are added by "admin create".
type definition struct {
	Title       string         `json:"title"`
	ReceiptMode string         `json:"receipt_mode"` // "full" (default) or "none"
	Tally       tally.Manifest `json:"tally"`
}

func runAdmin(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, adminHelp)
		return 2
	}
	fs := flag.NewFlagSet("admin "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	electionFlag := fs.String("election", "", "election ID")
	definitionPath := fs.String("definition", "", "JSON file with title, receipt_mode and tally")
	votersPath := fs.String("voters", "", "file with one email address per line")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	var e env
	log := &api.Client{Base: e.get("STIMMIG_LOG_URL"), Token: e.get("STIMMIG_LOG_ADMIN_TOKEN")}
	reg := &api.Client{Base: e.get("STIMMIG_REGISTRAR_URL"), Token: e.get("STIMMIG_REGISTRAR_ADMIN_TOKEN")}
	box := &api.Client{Base: e.get("STIMMIG_BALLOTBOX_URL"), Token: e.get("STIMMIG_BALLOTBOX_ADMIN_TOKEN")}
	if len(e.missing) > 0 {
		_, _ = fmt.Fprintf(stderr, "stimmig admin: missing environment variables %v\n", e.missing)
		return 2
	}
	ctx := context.Background()
	err := func() error {
		if args[0] == "create" {
			id, err := adminCreate(ctx, log, reg, box, *definitionPath)
			if err == nil {
				_, _ = fmt.Fprintln(stdout, hex.EncodeToString(id[:]))
			}
			return err
		}
		id, err := api.ParseHash(*electionFlag)
		if err != nil {
			return fmt.Errorf("-election: %w", err)
		}
		path := api.ElectionPath(id)
		switch args[0] {
		case "roll":
			roll, err := readVoters(*votersPath)
			if err != nil {
				return err
			}
			if err := reg.Do(ctx, "PUT", path+"/roll", roll, nil); err != nil {
				return err
			}
			return warnFingerprint(ctx, log, id, len(roll.Voters), stderr)
		case "close-registration":
			return reg.Do(ctx, "POST", path+"/close", nil, nil)
		case "open-voting":
			return box.Do(ctx, "POST", path+"/open", nil, nil)
		case "close-voting":
			return box.Do(ctx, "POST", path+"/close", nil, nil)
		case "tally":
			var res tally.Result
			if err := reg.Do(ctx, "POST", path+"/tally", nil, &res); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "winners: %s\n", strings.Join(res.Winners, ", "))
			if res.Tie != nil {
				_, _ = fmt.Fprintf(stdout, "unresolved tie between: %s\n", strings.Join(res.Tie.Candidates, ", "))
			}
			return nil
		}
		return errors.New("unknown command; run \"stimmig admin\" for help")
	}()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stimmig admin %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

// adminCreate collects the public keys of the three services, builds the
// manifest and registers the election with each service.
func adminCreate(ctx context.Context, log, reg, box *api.Client, definitionPath string) (merkle.Hash, error) {
	var def definition
	if err := readJSON(definitionPath, &def); err != nil {
		return merkle.Hash{}, err
	}
	if def.ReceiptMode == "" {
		def.ReceiptMode = publog.ReceiptFull
	}
	m := publog.Manifest{
		Version:     publog.ManifestVersion,
		Title:       def.Title,
		Nonce:       make([]byte, 16),
		Tally:       def.Tally,
		Algorithms:  publog.DefaultAlgorithms(def.ReceiptMode),
		ReceiptMode: def.ReceiptMode,
	}
	if _, err := rand.Read(m.Nonce); err != nil {
		return merkle.Hash{}, err
	}
	// Check the definition before any service creates keys for it.
	if err := m.Tally.Validate(); err != nil {
		return merkle.Hash{}, err
	}
	var logKey api.LogKey
	if err := log.Do(ctx, "POST", "/v1/keys", nil, &logKey); err != nil {
		return merkle.Hash{}, fmt.Errorf("log: %w", err)
	}
	var regKeys api.RegistrarKeys
	if err := reg.Do(ctx, "POST", "/v1/keys", nil, &regKeys); err != nil {
		return merkle.Hash{}, fmt.Errorf("registrar: %w", err)
	}
	m.LogKey, m.IssuingKey, m.ElectionKey = logKey.LogKey, regKeys.IssuingKey, regKeys.ElectionKey
	if def.ReceiptMode == publog.ReceiptFull {
		var boxKey api.BallotBoxKey
		if err := box.Do(ctx, "POST", "/v1/keys", nil, &boxKey); err != nil {
			return merkle.Hash{}, fmt.Errorf("ballot box: %w", err)
		}
		m.ReceiptKey = boxKey.ReceiptKey
	}
	var head publog.TreeHead
	if err := log.Do(ctx, "POST", "/v1/elections", m, &head); err != nil {
		return merkle.Hash{}, fmt.Errorf("log: %w", err)
	}
	if err := reg.Do(ctx, "POST", "/v1/elections", m, nil); err != nil {
		return merkle.Hash{}, fmt.Errorf("registrar: %w", err)
	}
	if err := box.Do(ctx, "POST", "/v1/elections", m, nil); err != nil {
		return merkle.Hash{}, fmt.Errorf("ballot box: %w", err)
	}
	return merkle.Hash(head.ElectionID), nil
}

func readVoters(path string) (api.Roll, error) {
	var roll api.Roll
	f, err := os.Open(path) //nolint:gosec // the path is given by the operator on the command line
	if err != nil {
		return roll, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// The email provider reports addresses in lower case.
		if address := strings.ToLower(strings.TrimSpace(sc.Text())); address != "" {
			roll.Voters = append(roll.Voters, api.Voter{Provider: "email", Subject: address})
		}
	}
	return roll, sc.Err()
}

// warnFingerprint warns when the election allows more different ballots
// than it has voters: a ranking can then work as a fingerprint that
// identifies a ballot (SPEC.md section 2).
func warnFingerprint(ctx context.Context, log *api.Client, id merkle.Hash, voters int, stderr io.Writer) error {
	export, err := api.Export(ctx, log, id)
	if err != nil {
		return err
	}
	rep, err := publog.Verify(bytes.NewReader(export), nil)
	if err != nil {
		return err
	}
	possible, err := rep.Manifest.Tally.PossibleBallots()
	if err != nil {
		return err
	}
	if possible.Cmp(big.NewInt(int64(voters))) > 0 {
		_, _ = fmt.Fprintf(stderr, "warning: %s different ballots are possible, but only %d voters are eligible. "+
			"A voter can make a ballot recognisable by an unusual ranking. Consider a lower max_ranks.\n", possible, voters)
	}
	return nil
}
