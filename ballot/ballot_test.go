package ballot

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"

	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/tally"
)

var (
	id        = merkle.LeafHash([]byte("election"))
	otherID   = merkle.LeafHash([]byte("other election"))
	cred      = ed25519.PublicKey(bytes.Repeat([]byte{1}, ed25519.PublicKeySize))
	otherCred = ed25519.PublicKey(bytes.Repeat([]byte{2}, ed25519.PublicKeySize))
)

func keys(t *testing.T) (public, private []byte) {
	t.Helper()
	public, private, err := GenerateElectionKey()
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func TestSealOpen(t *testing.T) {
	pub, priv := keys(t)
	for _, ranking := range []tally.Ballot{
		{{"A"}, {"B", "C"}},
		{{"C"}},
		{},
		nil,
	} {
		ct, err := Seal(rand.Reader, id, pub, cred, ranking)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Open(id, priv, cred, ct)
		if err != nil {
			t.Fatal(err)
		}
		want := ranking
		if want == nil {
			want = tally.Ballot{}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
		// Encryption is randomised.
		again, _ := Seal(rand.Reader, id, pub, cred, ranking)
		if bytes.Equal(ct, again) {
			t.Error("two ciphertexts of the same ranking are equal")
		}
	}
}

func TestOpenRejects(t *testing.T) {
	pub, priv := keys(t)
	_, otherPriv := keys(t)
	ct, err := Seal(rand.Reader, id, pub, cred, tally.Ballot{{"A"}})
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) []byte {
		c := append([]byte(nil), ct...)
		c[i] ^= 1
		return c
	}
	// A ciphertext copied into the ballot of another credential does not
	// decrypt.
	if _, err := Open(id, priv, otherCred, ct); !errors.Is(err, ErrDecrypt) {
		t.Errorf("other credential: got %v, want ErrDecrypt", err)
	}
	if _, err := Open(id, priv, cred[:31], ct); !errors.Is(err, ErrDecrypt) {
		t.Errorf("short credential key: got %v, want ErrDecrypt", err)
	}
	if _, err := Seal(rand.Reader, id, pub, cred[:31], tally.Ballot{}); err == nil {
		t.Error("sealed for a short credential key")
	}
	cases := map[string]struct {
		id   merkle.Hash
		priv []byte
		ct   []byte
	}{
		"other election":        {otherID, priv, ct},
		"other key":             {id, otherPriv, ct},
		"changed ciphertext":    {id, priv, flip(len(ct) - 1)},
		"changed encapsulation": {id, priv, flip(10)},
		"invalid point":         {id, priv, append(bytes.Repeat([]byte{4}, 65), ct[65:]...)},
		"truncated":             {id, priv, ct[:70]},
		"too short":             {id, priv, ct[:10]},
		"empty":                 {id, priv, nil},
	}
	for name, c := range cases {
		if _, err := Open(c.id, c.priv, cred, c.ct); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: got %v, want ErrDecrypt", name, err)
		}
	}
	if _, err := Open(id, priv[:31], cred, ct); err == nil || errors.Is(err, ErrDecrypt) {
		t.Errorf("malformed private key: %v", err)
	}
}

// sealRaw encrypts arbitrary plaintext, as a modified client could.
func sealRaw(t *testing.T, pub, plain []byte) []byte {
	t.Helper()
	pk, _ := parsePublic(pub)
	info, _ := sealInfo(id, cred)
	sender, err := suite.NewSender(pk, info)
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sealer.Seal(plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	return append(enc, ct...)
}

func TestOpenMalformed(t *testing.T) {
	pub, priv := keys(t)
	enc := func(v any) []byte {
		data, err := canon.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	plains := map[string][]byte{
		"not CBOR":         []byte("hello"),
		"not canonical":    {0x81, 0x81, 0x78, 0x01, 'A'},
		"null":             enc(nil),
		"text":             enc("A"),
		"flat array":       enc([]string{"A"}),
		"null group":       enc([]any{nil}),
		"number candidate": enc([][]int{{1}}),
		"map":              enc(map[string]int{"A": 1}),
		"empty plaintext":  {},
		"two items":        append(enc([][]string{{"A"}}), enc([][]string{{"B"}})...),
	}
	for name, plain := range plains {
		if _, err := Open(id, priv, cred, sealRaw(t, pub, plain)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v, want ErrMalformed", name, err)
		}
	}
}

func TestElectionKey(t *testing.T) {
	pub, priv := keys(t)
	otherPub, _ := keys(t)
	if err := CheckElectionKey(pub); err != nil {
		t.Fatal(err)
	}
	if err := MatchElectionKey(pub, priv); err != nil {
		t.Fatal(err)
	}
	if MatchElectionKey(otherPub, priv) == nil {
		t.Error("private key matches another public key")
	}
	if MatchElectionKey(pub, priv[:31]) == nil || MatchElectionKey(pub, make([]byte, 32)) == nil {
		t.Error("malformed private key accepted")
	}
	// The key format is the one of the standard library and of browsers:
	// an uncompressed point and a big-endian scalar.
	sk, err := ecdh.P256().NewPrivateKey(priv)
	if err != nil || !bytes.Equal(sk.PublicKey().Bytes(), pub) {
		t.Errorf("key format differs from crypto/ecdh: %v", err)
	}
	for name, bad := range map[string][]byte{
		"empty":         nil,
		"short":         pub[:64],
		"not on curve":  bytes.Repeat([]byte{4}, 65),
		"compressed":    append([]byte{2}, pub[1:33]...),
		"trailing byte": append(append([]byte(nil), pub...), 0),
	} {
		if CheckElectionKey(bad) == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := Seal(rand.Reader, id, bad, cred, tally.Ballot{}); err == nil {
			t.Errorf("%s: sealed", name)
		}
	}
}

func TestBallotSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ct := []byte("ciphertext")
	sig, err := Sign(priv, id, ct)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, id, ct, sig); err != nil {
		t.Fatal(err)
	}
	if Verify(pub, otherID, ct, sig) == nil {
		t.Error("verifies for another election")
	}
	if Verify(pub, id, []byte("other"), sig) == nil {
		t.Error("verifies for another ciphertext")
	}
	if Verify(otherPub, id, ct, sig) == nil {
		t.Error("verifies for another credential")
	}
	if Verify(pub[:31], id, ct, sig) == nil || Verify(pub, id, ct, sig[:63]) == nil {
		t.Error("short key or signature accepted")
	}
}

func TestReceipt(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	leaf := merkle.LeafHash([]byte("ballot entry"))
	receipt, err := SignReceipt(priv, id, leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceipt(pub, id, leaf, receipt); err != nil {
		t.Fatal(err)
	}
	if VerifyReceipt(pub, otherID, leaf, receipt) == nil {
		t.Error("verifies for another election")
	}
	if VerifyReceipt(pub, id, merkle.LeafHash([]byte("x")), receipt) == nil {
		t.Error("verifies for another ballot")
	}
	if VerifyReceipt(pub[:31], id, leaf, receipt) == nil {
		t.Error("short key accepted")
	}
	// A receipt is not a ballot signature and the reverse: the contexts
	// separate them even with the same key and the same 32 bytes.
	if Verify(pub, id, leaf[:], receipt) == nil {
		t.Error("receipt verifies as ballot signature")
	}
}
