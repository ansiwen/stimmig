package credential

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"os"
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

func TestIssuingKeyProof(t *testing.T) {
	sk := issuingKey()
	proof, err := ProveIssuingKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyIssuingKeyProof(&sk.PublicKey, proof); err != nil {
		t.Fatal(err)
	}
	bad := map[string][][]byte{
		"missing value": proof[:3],
		"extra value":   append(append([][]byte{}, proof...), proof[0]),
		"swapped":       {proof[1], proof[0], proof[2], proof[3]},
		"short value":   {proof[0][1:], proof[1], proof[2], proof[3]},
		"zero value":    {make([]byte, len(proof[0])), proof[1], proof[2], proof[3]},
		"value one":     {append(make([]byte, len(proof[0])-1), 1), proof[1], proof[2], proof[3]},
	}
	for name, p := range bad {
		if VerifyIssuingKeyProof(&sk.PublicKey, p) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The proof belongs to its key.
	other, _ := GenerateIssuingKey(rand.Reader)
	if VerifyIssuingKeyProof(&other.PublicKey, proof) == nil {
		t.Error("proof of another key accepted")
	}
}

// A modulus with a prime p where e divides p-1 has e-th roots for one value
// in e only, so it cannot give the proof. The key here is small and made
// for the test; it is not an RSA key that ParseIssuingKey would accept.
func TestIssuingKeyProofFailsWhenEDividesTheOrder(t *testing.T) {
	e := int64(65537)
	// p = k*e + 1 and q, both prime, with p-1 divisible by e.
	var p *big.Int
	for k := int64(2); ; k += 2 {
		c := big.NewInt(k*e + 1)
		if c.ProbablyPrime(20) {
			p = c
			break
		}
	}
	q, _ := rand.Prime(rand.Reader, 160)
	n := new(big.Int).Mul(p, q)
	pub := &rsa.PublicKey{N: n, E: int(e)}
	// The registrar knows p and q. It can take e-th roots only of the
	// values that are e-th powers modulo p.
	rootable := 0
	for i := 0; i < 2000; i++ {
		y := new(big.Int).Add(proofChallenge(pub, 0), big.NewInt(int64(i)))
		y.Mod(y, n)
		// y is an e-th power modulo p iff y^((p-1)/e) = 1 mod p.
		exp := new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(e))
		if new(big.Int).Exp(new(big.Int).Mod(y, p), exp, p).Cmp(big.NewInt(1)) == 0 {
			rootable++
		}
	}
	// About 2000/65537 values are rootable: practically none.
	if rootable > 5 {
		t.Fatalf("%d of 2000 values have roots", rootable)
	}
}

func TestCheckKey(t *testing.T) {
	good, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := CheckKey(good); err != nil {
		t.Fatal(err)
	}
	le := func(b ...byte) []byte { return append(b, make([]byte, 32-len(b))...) }
	allFF := func(first, last byte) []byte {
		k := bytes.Repeat([]byte{0xff}, 32)
		k[0], k[31] = first, last
		return k
	}
	bad := map[string][]byte{
		"identity":                     le(1),
		"order 2 (0, -1)":              allFF(0xec, 0x7f),
		"order 4 (x=±sqrt(-1), y=0)":   le(0),
		"not canonical identity (p+1)": allFF(0xee, 0x7f),
		"not canonical zero (p)":       allFF(0xed, 0x7f),
		"short":                        good[:31],
		"not on the curve":             bytes.Repeat([]byte{2}, 32),
	}
	for name, key := range bad {
		if CheckKey(key) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Message refuses them, so a client cannot ask for such a credential.
	if _, err := Message(merkle.Hash{}, le(1)); err == nil {
		t.Error("message for the identity key")
	}
}

// The blinded value for a stored seed must not change when the blind RSA
// library changes: a client that stored a seed and a pending registration
// rebuilds the request from it. If this test fails after an upgrade of
// circl, resumable registrations of the old version cannot be finished.
func TestRequestFromSeedGolden(t *testing.T) {
	der, err := os.ReadFile("testdata/issuing-key.der")
	if err != nil {
		t.Fatal(err)
	}
	sk, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	cred := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public().(ed25519.PublicKey)
	req, err := NewRequestFromSeed(bytes.Repeat([]byte{0x42}, SeedSize), &sk.PublicKey, merkle.LeafHash([]byte("golden")), cred)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(req.Blinded)
	if got := hex.EncodeToString(sum[:]); got != goldenBlindedHash {
		t.Fatalf("blinded value hash %s, want %s", got, goldenBlindedHash)
	}
}

const goldenBlindedHash = "56b12f5e1e89eac3ffb134f981df8aac0312a3a88971579c488efe35ee4a7d18"
