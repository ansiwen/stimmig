package keystore

import (
	"bytes"
	"strings"
	"testing"
)

func TestSealer(t *testing.T) {
	s, err := Parse(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	private, label := []byte("private key"), []byte("public key")
	sealed, err := s.Seal(private, label)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, private) {
		t.Fatal("the sealed key holds the private key in clear")
	}
	again, _ := s.Seal(private, label)
	if bytes.Equal(sealed, again) {
		t.Fatal("sealing is not randomised")
	}
	if got, err := s.Open(sealed, label); err != nil || !bytes.Equal(got, private) {
		t.Fatalf("open: %q, %v", got, err)
	}
	// Another label, a changed blob and another key do not open.
	if _, err := s.Open(sealed, []byte("other")); err == nil {
		t.Error("opened with another label")
	}
	changed := append([]byte(nil), sealed...)
	changed[len(changed)-1] ^= 1
	if _, err := s.Open(changed, label); err == nil {
		t.Error("changed blob opened")
	}
	if _, err := s.Open(sealed[:5], label); err == nil {
		t.Error("short blob opened")
	}
	other, _ := Parse(strings.Repeat("cd", 32))
	if _, err := other.Open(sealed, label); err == nil {
		t.Error("opened with another key-encryption key")
	}
}

func TestParse(t *testing.T) {
	if s, err := Parse(""); err != nil || s != (Plain{}) {
		t.Fatalf("empty key: %v, %v", s, err)
	}
	for _, bad := range []string{"abc", strings.Repeat("ab", 16), strings.Repeat("zz", 32)} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("key %q accepted", bad)
		}
	}
	p := Plain{}
	sealed, _ := p.Seal([]byte("k"), nil)
	if got, _ := p.Open(sealed, nil); string(got) != "k" {
		t.Fatal("plain round trip")
	}
}
