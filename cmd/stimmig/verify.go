package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ansiwen/stimmig/canon"
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

	var visit func(*publog.Report, uint64, string, []byte) error
	if *dump {
		visit = func(_ *publog.Report, index uint64, typ string, body []byte) error {
			js, err := canon.ToJSON(body)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "entry %d (%s): %s\n", index, typ, js)
			return nil
		}
	}
	rep, err := publog.Verify(f, visit)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "stimmig verify: FAILED:", err)
		return 1
	}
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(stdout, format+"\n", a...) }
	p("election     %s", hex.EncodeToString(rep.ElectionID[:]))
	p("title        %s", rep.Manifest.Title)
	p("entries      %d", rep.Entries)
	for i, typ := range publog.Types {
		if rep.Counts[i] > 0 {
			p("  %-20s %d", typ, rep.Counts[i])
		}
	}
	p("tree heads   %d", rep.TreeHeads)
	ts := time.Unix(int64(rep.Final.Timestamp), 0).UTC().Format(time.RFC3339) //nolint:gosec // display only
	p("final head   size %d, root %s, %s", rep.Final.Size, hex.EncodeToString(rep.Final.Root), ts)
	p("OK: the log structure is valid: canonical encoding, entry types, tree head roots and signatures.")
	p("Not checked yet: issuance, ballots, decryption and tally (later milestones).")
	return 0
}
