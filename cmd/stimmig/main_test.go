package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTallyCommand(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "m.json")
	ballots := filepath.Join(dir, "b.json")
	if err := os.WriteFile(manifest, []byte(`{"candidates":["A","B"],"method":"schulze"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ballots, []byte(`[[["A"],["B"]],[["A"]],[["B"]]]`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"tally", "-manifest", manifest, "-ballots", ballots}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"winners": [`) || !strings.Contains(out.String(), `"A"`) {
		t.Errorf("output: %s", out.String())
	}
	if code := run([]string{"registrar"}, &out, &errOut); code != 2 {
		t.Errorf("exit %d for a pending command", code)
	}
	if code := run(nil, &out, &errOut); code != 2 {
		t.Errorf("exit %d without a command", code)
	}
}

const goldenExport = "../../election/testdata/election-v1.cbor"

func TestVerifyCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"verify", "-json", goldenExport}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{
		"entries      25",
		"ballot               6",
		"phase        complete",
		"eligible     8",
		"issued       7",
		"cast         6",
		"counted      4 (not decryptable 1, against the ballot rules 1, abstentions 0)",
		"winners      A",
		"OK: the log is valid and the recomputed tally equals the logged result.",
		"entry 0 (manifest): {",
		`"title": "Board election"`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestVerifyCommandFails(t *testing.T) {
	data, err := os.ReadFile(goldenExport)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 1
	bad := filepath.Join(t.TempDir(), "bad.cbor")
	if err := os.WriteFile(bad, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"verify", bad}, &out, &errOut); code != 1 {
		t.Fatalf("exit %d for a changed export", code)
	}
	if !strings.Contains(errOut.String(), "FAILED") || strings.Contains(out.String(), "OK") {
		t.Errorf("stdout %q, stderr %q", out.String(), errOut.String())
	}
	if code := run([]string{"verify"}, &out, &errOut); code != 2 {
		t.Errorf("exit %d without a file", code)
	}
	if code := run([]string{"verify", filepath.Join(t.TempDir(), "missing")}, &out, &errOut); code != 1 {
		t.Errorf("exit %d for a missing file", code)
	}
}
