package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/election"
	"github.com/ansiwen/stimmig/publog"
)

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: stimmig verify [-json] <log export file>")
		fs.PrintDefaults()
	}
	dump := fs.Bool("json", false, "print every entry in its JSON rendering before the report")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	f, err := os.Open(fs.Arg(0)) //nolint:gosec // the path is given by the operator on the command line
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "stimmig verify:", err)
		return 1
	}
	defer func() { _ = f.Close() }()

	var visit func(uint64, string, []byte) error
	if *dump {
		visit = func(index uint64, typ string, body []byte) error {
			js, err := canon.ToJSON(body)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "entry %d (%s): %s\n", index, typ, js)
			return nil
		}
	}
	rep, err := election.Verify(f, visit)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "stimmig verify: FAILED:", err)
		return 1
	}
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(stdout, format+"\n", a...) }
	log := rep.Log
	p("election     %s", hex.EncodeToString(log.ElectionID[:]))
	p("title        %s", log.Manifest.Title)
	if log.Manifest.ClientHash != nil {
		p("client hash  %s", hex.EncodeToString(log.Manifest.ClientHash))
	}
	p("entries      %d", log.Entries)
	for i, typ := range publog.Types {
		if log.Counts[i] > 0 {
			p("  %-20s %d", typ, log.Counts[i])
		}
	}
	p("tree heads   %d", log.TreeHeads)
	ts := time.Unix(int64(log.Final.Timestamp), 0).UTC().Format(time.RFC3339) //nolint:gosec // display only
	p("final head   size %d, root %s, %s", log.Final.Size, hex.EncodeToString(log.Final.Root), ts)
	p("phase        %s", rep.Phase)
	p("eligible     %d", rep.Eligible)
	p("issued       %d", rep.Issued)
	p("cast         %d", rep.Cast)
	if res := rep.Result; res != nil {
		p("counted      %d (not decryptable %d, against the ballot rules %d, abstentions %d)",
			res.Valid, rep.Undecryptable, len(res.Invalid), res.Abstentions)
		p("method       %s, %d seat(s)", res.Method, res.Seats)
		p("winners      %s", strings.Join(res.Winners, ", "))
		if res.Tie != nil {
			p("TIE          unresolved between %s (%s)", strings.Join(res.Tie.Candidates, ", "), res.Tie.Context)
		}
		p("OK: the log is valid and the recomputed tally equals the logged result.")
	} else {
		p("OK: the log is valid as far as it goes. It has no result yet.")
	}
	return 0
}
