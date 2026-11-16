# Symbolic protocol model

A model of profile A in [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/)
(SPEC.md section 12, milestone M8). It checks the design, not the code: the
Go implementation is not derived from it, and nothing here checks that the
implementation matches it.

```bash
PROVERIF=/path/to/proverif ./run.sh     # about 20 seconds; exit status 1 on a surprise
```

Version used: ProVerif 2.05.

## What is checked

| File | What it checks | Result |
| --- | --- | --- |
| `privacy.pv` | Ballot privacy against a registrar and a ballot box that work together | Observational equivalence **is true** |
| `privacy-early-key.pv` | The same, with the election key known to the attacker from the start | **is true** |
| `privacy-noblind.pv` | The same without blinding (control) | cannot be proved: the attack is found, as it must |
| `privacy-nobinding.pv` | The same without binding the ciphertext to the credential | **is true**: not a control, see below |
| `integrity.pv` | Independence of votes; secrecy of the votes until the close | both **true** |
| `integrity-nobinding.pv` | The same without the binding (control) | independence is **false**: the attack is found; secrecy true |

The controls matter as much as the proofs. A model that cannot find an attack
when a protection is taken away proves nothing. Two earlier versions of the
privacy model did exactly that (see below), so the controls stay.

### Ballot privacy (`privacy.pv`)

Two honest voters, A and B, register and cast. In the right-hand process
they swap their votes. The attacker cannot tell the two processes apart, although it:

- controls the network, and the registrar (it holds the registrar's key and
  sees and answers every registration, with the identities);
- sees the registration of every voter, every ballot, the key at the close and the
  published decryptions;
- may cast a ballot of its own through the ballot box.

Anything that a ballot box which works with the registrar could see, the
attacker sees here. The result therefore covers the collusion that SPEC.md
section 2 excludes from the trust assumptions, up to timing.

### Independence of votes (`integrity.pv`)

A vote is counted only under the credential that cast it. Without the binding
of SPEC.md section 5.6 (the credential key in the HPKE info) the attacker
copies an honest ciphertext into a ballot of its own credential, and that
vote is counted under the attacker's credential: `integrity-nobinding.pv`.

### What the binding does not do

`privacy-nobinding.pv` is **true**. Ballots are anonymous, so a copy of a
ballot reveals nothing about whose it was. This differs from Helios, where
ballots are published under the voters' names and a copy reveals a vote. In
Stimmig the binding protects the independence of votes, not their privacy. The
specification said it answers the ballot-copying attacks on Helios (section
14); that is right for independence and not an anonymity matter.

## Assumptions of the model

- The usual symbolic ones: the attacker controls the network; the primitives
  are perfect. The blind signature, the signatures, HPKE and the hash are
  function symbols with the equations of `stimmig.pvl`.
- The registration closes before the voting opens (the phases of ProVerif),
  as in SPEC.md section 4. A model without the separation would leak through
  timing, which is the reason for the separation.
- The ballots are published in no order, and the order in which the voters
  cast is not observable: the two honest entries are released as an unordered
  pair, by swapping them in the right-hand process (the *mixer* and the
  *tally*). **Timing, network addresses and the order of the casts are not
  modelled.** They are the residual risks of SPEC.md section 2. This is the
  standard technique for ProVerif and it is an assumption, not a result.
- Two honest voters and one ballot of the attacker. Results for two voters do
  not by themselves extend to larger electorates; that is a limit of this kind
  of model.
- `privacy.pv` keeps the election key secret until the close, as the operator is
  trusted to (SPEC.md section 2). `privacy-early-key.pv` gives it to the attacker
  from the start, as when the registrar uses it early: privacy holds as well,
  because ballots do not tell whose they are. `integrity.pv` proves secrecy of
  the votes only as long as the key is secret.
- Lengths are not modelled: the symbolic encryption hides the size of its
  plaintext. The implementation pads every ballot of an election to one size
  (SPEC.md section 5.6), so the length of a ciphertext does not tell the
  ranking.
- Votes are public values. Only who cast which is hidden.

## What is not checked

- **Unforgeability of credentials** (every accepted ballot is backed by a
  signature of the registrar). ProVerif does not finish this query with the
  blind signature equation, not even for the ballot box alone. The model
  assumes it, by giving the attacker no way to sign except through the
  registrar.
- **Counting**: one credential per identity, one ballot per credential, and so
  cast <= issued <= eligible. ProVerif treats a message on a private channel as
  available any number of times, and it cannot say that an entry is not in a
  table, so neither a token nor a table can prove "only once". These are
  checks of the implementation (a primary key, an atomic insert) and of the
  verifier (SPEC.md section 12).
- Everything outside the cryptographic message flow: the Merkle log and the
  verifier, receipts, the web client and its code, key management, the
  confirmation code, the identity plugins, the tally methods, TLS.
- Receipt-freeness and coercion resistance, which are not goals of profile A.
- That the Go code does what the model says.

## How the model was found wrong

Worth knowing for anyone who changes it:

1. A first version said "true" for everything, including the controls. The
   tally process started in phase 0 and ProVerif discards a process that waits
   when the phase changes, so nothing was ever published and the equivalence held
   trivially. The reachability of the tally is now checked while the model is
   developed (a copy without `choice`, asking whether the end of the tally can be
   reached); do the same after a change.
2. ProVerif matches the two processes by position, and it merges the two
   orders in which a mixer can read two ballots into one derivation, then
   compares facts from different orders. That reports an attack that cannot
   happen. Each voter has a channel of its own, so the mixer reads in a fixed
   order.
3. The duplicate-credential check made the lookup in a table observable
   differently in the two processes. It has nothing to do with privacy and is
   not in the privacy model; accepting replays only gives the attacker more.
4. `get` followed by `insert` is not atomic, which ProVerif used for a
   "second credential for the same identity". Table-based counting is not
   provable in ProVerif at all, see above.
