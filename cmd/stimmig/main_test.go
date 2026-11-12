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
