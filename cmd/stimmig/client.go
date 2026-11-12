package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ansiwen/stimmig/api"
	"github.com/ansiwen/stimmig/client"
)

const clientHelp = `usage: stimmig client <command> -state FILE [flags]
commands:
  register -election ID -log URL -registrar URL -ballotbox URL [-email ADDRESS]
           obtain the voting credential; waits until you have logged in
  cast -ranking "A>B=C"   cast the ballot; ">" separates ranks, "=" equal candidates
  check                   look for the ballot in the public log
The state file holds your credential. Keep it private.`

func runClient(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, clientHelp)
		return 2
	}
	fs := flag.NewFlagSet("client "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	statePath := fs.String("state", "", "file that holds the credential, the ballot and the receipt")
	electionFlag := fs.String("election", "", "election ID")
	logURL := fs.String("log", "", "URL of the log service")
	registrarURL := fs.String("registrar", "", "URL of the registrar")
	ballotBoxURL := fs.String("ballotbox", "", "URL of the ballot box")
	email := fs.String("email", "", "email address to log in with; without it the login URL is printed")
	ranking := fs.String("ranking", "", `ranking, for example "A>B=C"`)
	timeout := fs.Duration("timeout", 30*time.Minute, "how long register waits for the login")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	err := func() error {
		if *statePath == "" {
			return errors.New("-state is required")
		}
		var st client.State
		ctx := context.Background()
		switch args[0] {
		case "register":
			if _, err := os.Stat(*statePath); err == nil {
				return errors.New("the state file exists already; a credential cannot be issued twice")
			}
			id, err := api.ParseHash(*electionFlag)
			if err != nil {
				return fmt.Errorf("-election: %w", err)
			}
			st = client.State{LogURL: *logURL, RegistrarURL: *registrarURL, BallotBoxURL: *ballotBoxURL, ElectionID: id[:]}
			ctx, cancel := context.WithTimeout(ctx, *timeout)
			defer cancel()
			err = client.Register(ctx, &st, func(loginURL string) error {
				if *email == "" {
					_, _ = fmt.Fprintf(stdout, "Open this URL to log in:\n%s\n", loginURL)
					return nil
				}
				_, _ = fmt.Fprintf(stdout, "A login link is on its way to %s. Open it to continue.\n", *email)
				return client.SubmitEmail(ctx, loginURL, *email)
			})
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "Credential received. Your entry in the public roll is %s.\n", hex.EncodeToString(st.RollReference))
		case "cast":
			if err := readJSON(*statePath, &st); err != nil {
				return err
			}
			err := client.Cast(ctx, &st, client.ParseRanking(*ranking))
			// Store the state also after a failure: it may hold the ballot
			// that must be sent again.
			if saveErr := saveState(*statePath, &st); saveErr != nil {
				return saveErr
			}
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(stdout, "Ballot cast.")
			return nil
		case "check":
			if err := readJSON(*statePath, &st); err != nil {
				return err
			}
			c, err := client.Check(ctx, &st)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "The public log verifies. Phase: %s.\n", c.Phase)
			switch {
			case !c.Included:
				_, _ = fmt.Fprintln(stdout, "The ballots are not published yet. Check again after the close.")
			case c.Result == nil:
				_, _ = fmt.Fprintln(stdout, "Your ballot is in the public log. It is not decrypted yet.")
			case c.Invalid != "":
				_, _ = fmt.Fprintf(stdout, "Your ballot is in the public log, but it is invalid: %s.\n", c.Invalid)
			default:
				groups := make([]string, len(c.Ranking))
				for i, g := range c.Ranking {
					groups[i] = strings.Join(g, "=")
				}
				_, _ = fmt.Fprintf(stdout, "Your ballot is in the public log and was decrypted as: %s\n", strings.Join(groups, ">"))
			}
			if c.Result != nil {
				_, _ = fmt.Fprintf(stdout, "Winners: %s\n", strings.Join(c.Result.Winners, ", "))
			}
			return nil
		default:
			return errors.New("unknown command; run \"stimmig client\" for help")
		}
		return saveState(*statePath, &st)
	}()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stimmig client %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

func saveState(path string, st *client.State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
