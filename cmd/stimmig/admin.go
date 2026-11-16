package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ansiwen/stimmig/admin"
	"github.com/ansiwen/stimmig/api"
)

const adminHelp = `usage: stimmig admin <command> [flags]
commands:
  create -definition FILE        create an election; prints its ID
  roll -election ID -voters FILE publish the roll, open registration; the file has one voter per line:
                                 an email address, or oidc:<issuer>#<sub> for OpenID Connect
  close-registration -election ID
  open-voting -election ID
  close-voting -election ID      close the voting and publish the ballots
  tally -election ID             publish the key, the plaintexts and the result
environment:
  STIMMIG_LOG_URL, STIMMIG_REGISTRAR_URL, STIMMIG_BALLOTBOX_URL
  STIMMIG_LOG_ADMIN_TOKEN, STIMMIG_REGISTRAR_ADMIN_TOKEN, STIMMIG_BALLOTBOX_ADMIN_TOKEN`

func runAdmin(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, adminHelp)
		return 2
	}
	fs := flag.NewFlagSet("admin "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	electionFlag := fs.String("election", "", "election ID")
	definitionPath := fs.String("definition", "", "JSON file with title, receipt_mode and tally")
	votersPath := fs.String("voters", "", "file with one voter per line")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	var e env
	c := &admin.Client{
		Log:       &api.Client{Base: e.get("STIMMIG_LOG_URL"), Token: e.get("STIMMIG_LOG_ADMIN_TOKEN")},
		Registrar: &api.Client{Base: e.get("STIMMIG_REGISTRAR_URL"), Token: e.get("STIMMIG_REGISTRAR_ADMIN_TOKEN")},
		BallotBox: &api.Client{Base: e.get("STIMMIG_BALLOTBOX_URL"), Token: e.get("STIMMIG_BALLOTBOX_ADMIN_TOKEN")},
	}
	if len(e.missing) > 0 {
		_, _ = fmt.Fprintf(stderr, "stimmig admin: missing environment variables %v\n", e.missing)
		return 2
	}
	ctx := context.Background()
	err := func() error {
		if args[0] == "create" {
			var def admin.Definition
			if err := readJSON(*definitionPath, &def); err != nil {
				return err
			}
			id, err := c.Create(ctx, def)
			if err == nil {
				_, _ = fmt.Fprintln(stdout, hex.EncodeToString(id[:]))
			}
			return err
		}
		id, err := api.ParseHash(*electionFlag)
		if err != nil {
			return fmt.Errorf("-election: %w", err)
		}
		switch args[0] {
		case "roll":
			text, err := os.ReadFile(*votersPath) //nolint:gosec // the path is given by the operator on the command line
			if err != nil {
				return err
			}
			roll, err := admin.ParseVoters(string(text))
			if err != nil {
				return err
			}
			warning, err := c.Roll(ctx, id, roll)
			if warning != "" {
				_, _ = fmt.Fprintln(stderr, "warning: "+warning)
			}
			return err
		case "close-registration":
			return c.CloseRegistration(ctx, id)
		case "open-voting":
			return c.OpenVoting(ctx, id)
		case "close-voting":
			return c.CloseVoting(ctx, id)
		case "tally":
			res, err := c.Tally(ctx, id)
			if err != nil {
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
