package credential

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"math/big"
	"sync"
	"testing"

	"github.com/ansiwen/stimmig/merkle"
)

var issuingKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := GenerateIssuingKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
})

func newCredential(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestIssuance(t *testing.T) {
	sk := issuingKey()
	id := merkle.LeafHash([]byte("election"))
	cred := newCredential(t)

	req, err := NewRequest(rand.Reader, &sk.PublicKey, id, cred)
	if err != nil {
		t.Fatal(err)
	}
	blindSig, err := Issue(sk, req.Blinded)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := req.Finalize(blindSig)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(&sk.PublicKey, id, cred, sig); err != nil {
		t.Fatal(err)
	}

	// The registrar sees neither the message nor the signature.
	msg, _ := Message(id, cred)
	if bytes.Contains(req.Blinded, cred) || bytes.Equal(blindSig, sig) {
		t.Error("blinded value or blind signature reveals the credential")
	}
	// The result is a standard RSASSA-PSS signature (SHA-384, 48-byte
	// salt), as browsers verify it.
	digest := sha512.Sum384(msg)
	if err := rsa.VerifyPSS(&sk.PublicKey, crypto.SHA384, digest[:], sig, &rsa.PSSOptions{SaltLength: 48}); err != nil {
		t.Errorf("not a standard PSS signature: %v", err)
	}

	// The signature is bound to the election and to the credential key.
	if Verify(&sk.PublicKey, merkle.LeafHash([]byte("other")), cred, sig) == nil {
		t.Error("signature verifies for another election")
	}
	if Verify(&sk.PublicKey, id, newCredential(t), sig) == nil {
		t.Error("signature verifies for another credential")
	}
	bad := append([]byte(nil), sig...)
	bad[10] ^= 1
	if Verify(&sk.PublicKey, id, cred, bad) == nil {
		t.Error("changed signature verifies")
	}
	if Verify(&sk.PublicKey, id, cred[:31], sig) == nil {
		t.Error("short credential key accepted")
	}
}

// Two requests for the same credential differ, so the registrar cannot
// recognise a credential by its blinded value.
func TestBlindingIsRandom(t *testing.T) {
	sk := issuingKey()
	id := merkle.LeafHash([]byte("election"))
	cred := newCredential(t)
	a, err := NewRequest(rand.Reader, &sk.PublicKey, id, cred)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewRequest(rand.Reader, &sk.PublicKey, id, cred)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Blinded, b.Blinded) {
		t.Fatal("blinding is not random")
	}
}

func TestFinalizeRejectsWrongAnswer(t *testing.T) {
	sk := issuingKey()
	id := merkle.LeafHash([]byte("election"))
	req, err := NewRequest(rand.Reader, &sk.PublicKey, id, newCredential(t))
	if err != nil {
		t.Fatal(err)
	}
	blindSig, _ := Issue(sk, req.Blinded)
	bad := append([]byte(nil), blindSig...)
	bad[20] ^= 1
	if _, err := req.Finalize(bad); err == nil {
		t.Error("changed blind signature accepted")
	}
	// The answer to another request does not fit.
	other, _ := NewRequest(rand.Reader, &sk.PublicKey, id, newCredential(t))
	otherSig, _ := Issue(sk, other.Blinded)
	if _, err := req.Finalize(otherSig); err == nil {
		t.Error("blind signature of another request accepted")
	}
	if _, err := Issue(sk, req.Blinded[1:]); err == nil {
		t.Error("blinded value of the wrong length signed")
	}
}

func TestParseIssuingKey(t *testing.T) {
	sk := issuingKey()
	der, err := MarshalIssuingKey(&sk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseIssuingKey(der)
	if err != nil || !pub.Equal(&sk.PublicKey) {
		t.Fatalf("round trip: %v", err)
	}
	marshal := func(k any) []byte {
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	small, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	bad := map[string][]byte{
		"2048 bits":     marshal(&small.PublicKey),
		"exponent 3":    marshal(&rsa.PublicKey{N: sk.N, E: 3}),
		"even modulus":  marshal(&rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 3072), E: 65537}),
		"factor 7":      marshal(&rsa.PublicKey{N: new(big.Int).Mul(sk.N, big.NewInt(7)), E: 65537}),
		"not RSA":       marshal(edPub),
		"trailing data": append(append([]byte(nil), der...), 0),
		"empty":         nil,
	}
	for name, der := range bad {
		if _, err := ParseIssuingKey(der); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSmallPrimes(t *testing.T) {
	want := big.NewInt(1)
	for p := int64(3); p < 100; p += 2 {
		if big.NewInt(p).ProbablyPrime(10) {
			want.Mul(want, big.NewInt(p))
		}
	}
	if want.Cmp(smallPrimes) != 0 {
		t.Fatalf("smallPrimes = %s, want %s", smallPrimes, want)
	}
}

// The same seed gives the same request, and that request finishes an
// issuance that another instance started.
func TestRequestFromSeed(t *testing.T) {
	sk := issuingKey()
	id := merkle.LeafHash([]byte("election"))
	cred := newCredential(t)
	seed := bytes.Repeat([]byte{9}, SeedSize)
	first, err := NewRequestFromSeed(seed, &sk.PublicKey, id, cred)
	if err != nil {
		t.Fatal(err)
	}
	blindSig, err := Issue(sk, first.Blinded)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		again, err := NewRequestFromSeed(seed, &sk.PublicKey, id, cred)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again.Blinded, first.Blinded) {
			t.Fatalf("run %d: the request differs", i)
		}
		sig, err := again.Finalize(blindSig)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(&sk.PublicKey, id, cred, sig); err != nil {
			t.Fatal(err)
		}
	}
	other, _ := NewRequestFromSeed(bytes.Repeat([]byte{8}, SeedSize), &sk.PublicKey, id, cred)
	if bytes.Equal(other.Blinded, first.Blinded) {
		t.Fatal("another seed gives the same request")
	}
	if _, err := NewRequestFromSeed(seed[:16], &sk.PublicKey, id, cred); err == nil {
		t.Fatal("short seed accepted")
	}
}
