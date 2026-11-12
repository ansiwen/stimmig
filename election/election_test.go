package election

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"flag"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ansiwen/stimmig/ballot"
	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/credential"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/publog"
	"github.com/ansiwen/stimmig/tally"
)

var update = flag.Bool("update", false, "rewrite the golden export in testdata")

// keys holds the keys of all parties of a test election.
type keys struct {
	log, receipt    ed25519.PrivateKey
	issuing         *rsa.PrivateKey
	electionPublic  []byte
	electionPrivate []byte
}

var testKeys = sync.OnceValue(func() keys {
	var k keys
	var err error
	if _, k.log, err = ed25519.GenerateKey(rand.Reader); err != nil {
		panic(err)
	}
	if _, k.receipt, err = ed25519.GenerateKey(rand.Reader); err != nil {
		panic(err)
	}
	if k.issuing, err = credential.GenerateIssuingKey(rand.Reader); err != nil {
		panic(err)
	}
	if k.electionPublic, k.electionPrivate, err = ballot.GenerateElectionKey(); err != nil {
		panic(err)
	}
	return k
})

func testManifest(t *testing.T) publog.Manifest {
	t.Helper()
	k := testKeys()
	issuing, err := credential.MarshalIssuingKey(&k.issuing.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return publog.Manifest{
		Version: publog.ManifestVersion,
		Title:   "Board election",
		Nonce:   bytes.Repeat([]byte{1}, 16),
		Tally: tally.Manifest{
			Candidates: []string{"A", "B", "C"},
			Method:     tally.Schulze,
			MaxRanks:   2,
		},
		Algorithms:  publog.DefaultAlgorithms(publog.ReceiptFull),
		ReceiptMode: publog.ReceiptFull,
		LogKey:      k.log.Public().(ed25519.PublicKey),
		IssuingKey:  issuing,
		ElectionKey: k.electionPublic,
		ReceiptKey:  k.receipt.Public().(ed25519.PublicKey),
	}
}

func rollReference(i int) []byte {
	h := sha256.Sum256([]byte{byte(i)})
	return h[:]
}

// voter is the state of a voter's client.
type voter struct {
	key       ed25519.PrivateKey
	signature []byte // registrar's signature on the credential
	ballot    Ballot
	receipt   []byte
}

// register runs the credential issuance between a voter's client and the
// registrar.
func register(t *testing.T, m publog.Manifest, id merkle.Hash) voter {
	t.Helper()
	// Client: validate the issuing key, create the credential, blind it.
	issuingKey, err := credential.ParseIssuingKey(m.IssuingKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req, err := credential.NewRequest(rand.Reader, issuingKey, id, pub)
	if err != nil {
		t.Fatal(err)
	}
	// Registrar: sees only the blinded value.
	blindSig, err := credential.Issue(testKeys().issuing, req.Blinded)
	if err != nil {
		t.Fatal(err)
	}
	// Client: unblind and verify.
	sig, err := req.Finalize(blindSig)
	if err != nil {
		t.Fatal(err)
	}
	return voter{key: priv, signature: sig}
}

// rawBallot builds a ballot around an arbitrary ciphertext, as a modified
// client could.
func rawBallot(t *testing.T, id merkle.Hash, v voter, ciphertext []byte) Ballot {
	t.Helper()
	sig, err := ballot.Sign(v.key, id, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	return Ballot{
		CredentialKey:       v.key.Public().(ed25519.PublicKey),
		CredentialSignature: v.signature,
		Ciphertext:          ciphertext,
		Signature:           sig,
	}
}

type testElection struct {
	log      *publog.Log
	manifest publog.Manifest
	voters   []voter
	result   *tally.Result
}

// The rankings of the honest test election. Voter 4 breaks the rank limit,
// voter 5 submits a ciphertext that does not decrypt, voter 6 registers but
// does not vote, and roll entry 7 never registers.
var testRankings = []tally.Ballot{
	{{"A"}, {"B"}},
	{{"A"}, {"C"}},
	{{"B"}, {"A"}},
	{{"C"}},
	{{"A"}, {"B"}, {"C"}},
}

func testClock() func() time.Time {
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	return func() time.Time {
		now = now.Add(time.Minute)
		return now
	}
}

// runElection runs a complete honest election.
func runElection(t *testing.T) *testElection {
	t.Helper()
	k := testKeys()
	e := &testElection{manifest: testManifest(t)}
	var err error
	if e.log, err = publog.New(k.log, e.manifest, testClock()); err != nil {
		t.Fatal(err)
	}
	id := e.log.ElectionID()

	// Roll publication: 8 eligible voters.
	var roll [][]byte
	for i := 0; i < 8; i++ {
		roll = append(roll, rollReference(i))
	}
	if err := PublishRoll(e.log, roll); err != nil {
		t.Fatal(err)
	}
	// Registration: 7 of them obtain a credential.
	for i := 0; i < 7; i++ {
		e.voters = append(e.voters, register(t, e.manifest, id))
		if err := PublishIssuance(e.log, rollReference(i), uint64(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := CloseRegistration(e.log, 7); err != nil {
		t.Fatal(err)
	}
	// Voting: 6 of them cast a ballot; the ballot box checks it and
	// answers with a receipt.
	var box []Ballot
	for i := 0; i < 6; i++ {
		v := &e.voters[i]
		if i < len(testRankings) {
			v.ballot, err = Cast(rand.Reader, e.manifest, id, v.key, v.signature, testRankings[i])
			if err != nil {
				t.Fatal(err)
			}
		} else {
			v.ballot = rawBallot(t, id, *v, bytes.Repeat([]byte{4}, 100))
		}
		if err := CheckBallot(e.manifest, id, v.ballot); err != nil {
			t.Fatal(err)
		}
		leaf, err := BallotLeaf(v.ballot)
		if err != nil {
			t.Fatal(err)
		}
		if v.receipt, err = ballot.SignReceipt(k.receipt, id, leaf); err != nil {
			t.Fatal(err)
		}
		box = append(box, v.ballot)
	}
	// Close and tally.
	if err := PublishBallots(e.log, box); err != nil {
		t.Fatal(err)
	}
	if e.result, err = PublishTally(e.log, e.manifest, k.electionPrivate); err != nil {
		t.Fatal(err)
	}
	return e
}

func exportLog(t *testing.T, l *publog.Log) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := l.Export(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestElectionEndToEnd(t *testing.T) {
	e := runElection(t)
	data := exportLog(t, e.log)
	rep, err := Verify(bytes.NewReader(data), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Phase != PhaseComplete || rep.Eligible != 8 || rep.Issued != 7 || rep.Cast != 6 || rep.Undecryptable != 1 {
		t.Fatalf("report: %+v", rep)
	}
	// Counted: A>B, A>C, B>A, C. A beats B 2 to 1 and C 3 to 1.
	res := rep.Result
	if !reflect.DeepEqual(res.Winners, []string{"A"}) || res.Valid != 4 || res.Ballots != 5 {
		t.Fatalf("result: winners %v, valid %d of %d", res.Winners, res.Valid, res.Ballots)
	}
	if len(res.Invalid) != 1 || !strings.Contains(res.Invalid[0].Reason, "3 ranks") {
		t.Fatalf("invalid: %+v", res.Invalid)
	}
	if !reflect.DeepEqual(res, e.result) {
		t.Fatal("verified result differs from the published result")
	}

	// Receipt check: every voter finds their ballot in the final tree.
	final := rep.Log.Final
	id := e.log.ElectionID()
	for i, v := range e.voters[:6] {
		leaf, _ := BallotLeaf(v.ballot)
		if err := ballot.VerifyReceipt(e.manifest.ReceiptKey, id, leaf, v.receipt); err != nil {
			t.Fatalf("voter %d: %v", i, err)
		}
		found := false
		for index := uint64(0); index < final.Size; index++ {
			entry, _ := e.log.Entry(index)
			if merkle.LeafHash(entry) != leaf {
				continue
			}
			found = true
			proof, err := e.log.InclusionProof(index, final.Size)
			if err != nil {
				t.Fatal(err)
			}
			if err := merkle.VerifyInclusion(leaf, index, final.Size, proof, merkle.Hash(final.Root)); err != nil {
				t.Fatalf("voter %d: %v", i, err)
			}
		}
		if !found {
			t.Fatalf("voter %d: ballot is not in the log", i)
		}
	}
}

// The golden export is a published test vector for independent verifiers.
// It cannot be regenerated byte for byte, because signatures and
// encryption are randomised.
func TestGoldenExport(t *testing.T) {
	const path = "testdata/election-v1.cbor"
	if *update {
		if err := os.WriteFile(path, exportLog(t, runElection(t).log), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(bytes.NewReader(golden), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Phase != PhaseComplete || rep.Cast != 6 || !reflect.DeepEqual(rep.Result.Winners, []string{"A"}) {
		t.Fatalf("report: %+v", rep)
	}
}

func TestCheckBallot(t *testing.T) {
	m := testManifest(t)
	id := merkle.LeafHash([]byte("election"))
	v := register(t, m, id)
	b, err := Cast(rand.Reader, m, id, v.key, v.signature, tally.Ballot{{"A"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckBallot(m, id, b); err != nil {
		t.Fatal(err)
	}
	other := register(t, m, id)
	changes := map[string]func(*Ballot){
		"other credential key": func(b *Ballot) { b.CredentialKey = other.key.Public().(ed25519.PublicKey) },
		"other registrar sig":  func(b *Ballot) { b.CredentialSignature = other.signature },
		"changed ciphertext":   func(b *Ballot) { b.Ciphertext = append([]byte{0}, b.Ciphertext...) },
		"no signature":         func(b *Ballot) { b.Signature = nil },
		"self-made credential": func(b *Ballot) {
			*b = rawBallot(t, id, voter{key: other.key, signature: make([]byte, 384)}, b.Ciphertext)
		},
	}
	for name, change := range changes {
		c := b
		change(&c)
		if CheckBallot(m, id, c) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if CheckBallot(m, merkle.LeafHash([]byte("other")), b) == nil {
		t.Error("ballot accepted for another election")
	}
}

// rec is one log entry of a rebuilt log.
type rec struct {
	typ  string
	body any
}

// entries returns the entries of a log after the manifest.
func entries(t *testing.T, l *publog.Log) []rec {
	t.Helper()
	var out []rec
	for index := uint64(1); index < l.Size(); index++ {
		data, _ := l.Entry(index)
		typ, body, err := publog.DecodeEntry(data)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rec{typ, canon.Raw(body)})
	}
	return out
}

// rebuild signs a log with the given entries, as a dishonest operator
// could, and exports it.
func rebuild(t *testing.T, m publog.Manifest, recs []rec) []byte {
	t.Helper()
	l, err := publog.New(testKeys().log, m, testClock())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if _, err := l.Append(r.typ, r.body); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.Head(); err != nil {
		t.Fatal(err)
	}
	return exportLog(t, l)
}

func TestVerifyRejects(t *testing.T) {
	e := runElection(t)
	id := e.log.ElectionID()
	good := entries(t, e.log)
	// Positions in good: roll 0, issuances 1-7, registration_close 8,
	// ballots 9-14, voting_close 15, election_key 16, ballot_plain 17-22,
	// result 23.
	const (
		iRoll, iIssuance, iRegClose = 0, 1, 8
		iBallot, iVoteClose, iKey   = 9, 15, 16
		iPlain, iResult             = 17, 23
	)
	if len(good) != 24 || good[iResult].typ != publog.TypeResult || good[iPlain].typ != publog.TypeBallotPlain {
		t.Fatalf("unexpected log layout: %d entries", len(good))
	}
	if _, err := Verify(bytes.NewReader(rebuild(t, e.manifest, good)), nil); err != nil {
		t.Fatalf("rebuilt honest log: %v", err)
	}
	set := func(i int, typ string, body any) []rec {
		out := append([]rec(nil), good...)
		out[i] = rec{typ, body}
		return out
	}
	cut := func(i, j int) []rec { // remove entries i to j-1
		out := append([]rec(nil), good[:i]...)
		return append(out, good[j:]...)
	}
	insert := func(i int, r rec) []rec {
		out := append([]rec(nil), good[:i]...)
		out = append(out, r)
		return append(out, good[i:]...)
	}
	swap := func(i, j int) []rec {
		out := append([]rec(nil), good...)
		out[i], out[j] = out[j], out[i]
		return out
	}
	// withBallot adds a ballot at its place in the leaf hash order.
	withBallot := func(recs []rec, b Ballot) []rec {
		leaf, _ := BallotLeaf(b)
		at := 0
		for recs[at].typ != publog.TypeBallot {
			at++
		}
		for ; recs[at].typ == publog.TypeBallot; at++ {
			var other Ballot
			if err := canon.Unmarshal(recs[at].body.(canon.Raw), &other); err != nil {
				t.Fatal(err)
			}
			if otherLeaf, _ := BallotLeaf(other); bytes.Compare(leaf[:], otherLeaf[:]) < 0 {
				break
			}
		}
		out := append([]rec(nil), recs[:at]...)
		out = append(out, rec{publog.TypeBallot, b})
		return append(out, recs[at:]...)
	}
	decode := func(i int, v any) {
		if err := canon.Unmarshal(good[i].body.(canon.Raw), v); err != nil {
			t.Fatal(err)
		}
	}
	var b0 Ballot
	decode(iBallot, &b0)
	// The first decrypted ballot that has a ranking; the ballots are in
	// leaf hash order, so its place differs from run to run.
	var plain0, plainBad BallotPlain
	iValid := iPlain
	for ; ; iValid++ {
		plain0 = BallotPlain{}
		decode(iValid, &plain0)
		if plain0.Ranking != nil {
			break
		}
	}
	var res tally.Result
	decode(iResult, &res)
	res.Winners = []string{"B"}

	// A ballot with a credential that is not among the cast ballots, to
	// stuff the ballot box.
	extra, err := Cast(rand.Reader, e.manifest, id, e.voters[6].key, e.voters[6].signature, tally.Ballot{{"B"}})
	if err != nil {
		t.Fatal(err)
	}
	// A ballot whose credential the registrar never signed.
	_, forgedKey, _ := ed25519.GenerateKey(rand.Reader)
	forged := rawBallot(t, id, voter{key: forgedKey, signature: b0.CredentialSignature}, b0.Ciphertext)
	// The first ballot again, with a fresh ciphertext.
	second, err := Cast(rand.Reader, e.manifest, id, e.voters[0].key, e.voters[0].signature, tally.Ballot{{"C"}})
	if err != nil {
		t.Fatal(err)
	}
	badSig := b0
	badSig.Signature = append([]byte{b0.Signature[0] ^ 1}, b0.Signature[1:]...)
	wrongRanking := tally.Ballot{{"B"}}
	plainBad = BallotPlain{Ballot: plain0.Ballot, Ranking: &wrongRanking}
	_, otherPrivate, _ := ballot.GenerateElectionKey()

	// The registrar signs a credential without logging the issuance: the
	// log shows 6 issuances, and a seventh ballot appears.
	hidden := cut(iIssuance+6, iIssuance+7)
	hidden[iRegClose-1] = rec{publog.TypeRegistrationClose, RegistrationClose{Issued: 6}}

	cases := map[string]struct {
		recs []rec
		want string
	}{
		"no roll":                  {cut(iRoll, iRoll+1), "must not follow a manifest entry"},
		"roll not sorted":          {set(iRoll, publog.TypeRollCommit, RollCommit{References: [][]byte{rollReference(0), rollReference(0)}}), "not strictly ascending"},
		"roll reference too short": {set(iRoll, publog.TypeRollCommit, RollCommit{References: [][]byte{{1}}}), "not 32 bytes"},
		"issuance outside roll":    {set(iIssuance, publog.TypeIssuance, Issuance{RollReference: rollReference(99), Sequence: 0}), "not in the roll"},
		"issuance twice":           {set(iIssuance+1, publog.TypeIssuance, Issuance{RollReference: rollReference(0), Sequence: 1}), "second credential"},
		"issuance sequence":        {set(iIssuance+1, publog.TypeIssuance, Issuance{RollReference: rollReference(1), Sequence: 5}), "sequence number 5, want 1"},
		"issuance removed":         {cut(iIssuance+6, iIssuance+7), "logged issued count 7, but 6"},
		"issued count":             {set(iRegClose, publog.TypeRegistrationClose, RegistrationClose{Issued: 8}), "logged issued count 8, but 7"},
		"issuance after close":     {insert(iBallot, rec{publog.TypeIssuance, Issuance{RollReference: rollReference(7), Sequence: 7}}), "must not follow a registration_close entry"},
		"ballot before close":      {swap(iRegClose, iBallot), "must not follow a issuance entry"},
		"forged credential":        {set(iBallot, publog.TypeBallot, forged), "registrar signature is invalid"},
		"bad ballot signature":     {set(iBallot, publog.TypeBallot, badSig), "ballot signature is invalid"},
		"credential twice":         {withBallot(good, second), "credential used twice"},
		"ballot added":             {withBallot(good, extra), "logged cast count 6, but 7"},
		"hidden credential":        {withBallot(hidden, extra), "more ballots cast than credentials issued"},
		"ballots not sorted":       {swap(iBallot, iBallot+1), "not ordered by leaf hash"},
		"ballot removed":           {cut(iBallot, iBallot+1), "logged cast count 6, but 5"},
		"cast count":               {set(iVoteClose, publog.TypeVotingClose, VotingClose{Cast: 5}), "logged cast count 5, but 6"},
		"wrong election key":       {set(iKey, publog.TypeElectionKey, KeyRelease{PrivateKey: otherPrivate}), "does not match the public key"},
		"key before close":         {swap(iVoteClose, iKey), "must not follow a ballot entry"},
		"wrong plaintext":          {set(iValid, publog.TypeBallotPlain, plainBad), "does not match the decryption"},
		"plaintext marked invalid": {set(iValid, publog.TypeBallotPlain, BallotPlain{Ballot: plain0.Ballot, Invalid: InvalidDecrypt}), "does not match the decryption"},
		"plaintexts swapped":       {swap(iPlain, iPlain+1), "does not match the decryption"},
		"plaintext missing":        {cut(iPlain+5, iPlain+6), "5 ballot_plain entries for 6 ballots"},
		"plaintext extra":          {insert(iResult, good[iPlain]), "more ballot_plain entries than ballots"},
		"wrong result":             {set(iResult, publog.TypeResult, res), "differs from the recomputed tally"},
		"entry after result":       {append(append([]rec(nil), good...), good[iResult]), "must not follow a result entry"},
		"unknown field":            {set(iRegClose, publog.TypeRegistrationClose, map[string]int{"issued": 7, "extra": 1}), "unknown field"},
	}
	for name, c := range cases {
		_, err := Verify(bytes.NewReader(rebuild(t, e.manifest, c.recs)), nil)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not contain %q", name, err, c.want)
		}
	}
}

// A log that ends before the result verifies as far as it goes.
func TestVerifyPartial(t *testing.T) {
	e := runElection(t)
	good := entries(t, e.log)
	for n, phase := range map[int]string{
		0:  PhaseSetup,
		1:  PhaseRegistration,
		4:  PhaseRegistration,
		9:  PhaseRegistrationClosed,
		12: PhaseClosing,
		16: PhaseVotingClosed,
		17: PhaseTallying,
		20: PhaseTallying,
		24: PhaseComplete,
	} {
		rep, err := Verify(bytes.NewReader(rebuild(t, e.manifest, good[:n])), nil)
		if err != nil {
			t.Errorf("%d entries: %v", n, err)
		} else if rep.Phase != phase || (rep.Result != nil) != (phase == PhaseComplete) {
			t.Errorf("%d entries: phase %q, want %q", n, rep.Phase, phase)
		}
	}
}

// An election without ballots completes with a declared tie.
func TestEmptyElection(t *testing.T) {
	k := testKeys()
	m := testManifest(t)
	l, err := publog.New(k.log, m, testClock())
	if err != nil {
		t.Fatal(err)
	}
	if err := PublishRoll(l, nil); err != nil {
		t.Fatal(err)
	}
	if err := CloseRegistration(l, 0); err != nil {
		t.Fatal(err)
	}
	if err := PublishBallots(l, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishTally(l, m, k.electionPrivate); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(bytes.NewReader(exportLog(t, l)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Phase != PhaseComplete || rep.Cast != 0 || rep.Result.Tie == nil {
		t.Fatalf("report: %+v, result %+v", rep, rep.Result)
	}
}
