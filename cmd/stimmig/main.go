// Command stimmig provides all roles of the platform as subcommands
// (SPEC.md section 10).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ansiwen/stimmig/tally"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "tally":
		return runTally(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "log", "registrar", "ballotbox":
		return runServe(args[0], stderr)
	case "admin":
		return runAdmin(args[1:], stdout, stderr)
	case "client":
		return runClient(args[1:], stdout, stderr)
	}
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "usage: stimmig <command> [flags]")
	_, _ = fmt.Fprintln(w, "services: log, registrar, ballotbox")
	_, _ = fmt.Fprintln(w, "tools:    admin, client, verify, tally")
}

func runTally(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tally", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifestPath := fs.String("manifest", "", "JSON file with the tally manifest")
	ballotsPath := fs.String("ballots", "", "JSON file with an array of ballots; each ballot is an array of rank groups")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *manifestPath == "" || *ballotsPath == "" || fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	var m tally.Manifest
	var ballots []tally.Ballot
	if err := readJSON(*manifestPath, &m); err != nil {
		_, _ = fmt.Fprintln(stderr, "stimmig tally:", err)
		return 1
	}
	if err := readJSON(*ballotsPath, &ballots); err != nil {
		_, _ = fmt.Fprintln(stderr, "stimmig tally:", err)
		return 1
	}
	res, err := tally.Tally(m, ballots)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "stimmig tally:", err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		_, _ = fmt.Fprintln(stderr, "stimmig tally:", err)
		return 1
	}
	return 0
}

func readJSON(path string, v any) error {
	f, err := os.Open(path) //nolint:gosec // the path is given by the operator on the command line
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
