# Verifiable Ranked Voting Platform — Specification v0.1

Nov 10, 2026 · @Sven Anderson

## 1. Goals and non-goals

The platform runs ranked-choice elections whose result anyone can recompute from public data, while no single party can link a ballot to a voter under the stated trust assumptions.

Goals:

- **Public counts.** Everyone sees the number of eligible voters, credentials handed out and ballots cast. The invariant is cast ≤ issued ≤ eligible.
- **Universal verifiability.** All ballots are public after the close. A standalone verifier recomputes the result.
- **Individual verifiability.** Each voter holds a receipt and can check that their ballot is in the public log.
- **Ballot anonymity.** Hand-out and casting are cryptographically unlinkable.
- **Several ranked methods.** Condorcet methods are the default; others plug into the same interface.
- **Web application.** It works on desktop and mobile browsers without installation.
- **Go, horizontally scalable.** Stateless services run as containers on Kubernetes.
- **Open source.** The licence is EUPL-1.2.

Desired, but not goals of the first version:

- Coercion resistance and receipt-freeness, for example through a mixnet or other methods. v1 offers only the per-election receipt mode (section 5.5).
- Suitability for legally binding public political elections.
- Protection against compromised voter devices.

These remain design targets: v1 decisions must not block them, and the assurance profiles (section 2) are the extension point.

Never a goal:

- Live results during voting. Only general statistics are published while voting is open, such as the number of ballots cast so far.

## 2. Threat model and assurance profiles

Each election declares an assurance profile in its manifest, and the voter interface states what that profile does and does not protect against. v1 ships profile A only.

The security baseline is postal voting: v1 does not need to be more secure than mail-in ballots. Unsupervised voting is therefore accepted, as it is for postal votes.

| Profile | Mechanism | Status |
| --- | --- | --- |
| A: Blind credentials | Blind-signed credential, anonymous casting, public log | v1 |
| B: Mixnet | Encrypted ballots, verifiable shuffle, threshold decryption | Later |

Trust assumptions for profile A:

- Registrar and ballot box do not collude and do not share logs.
- The operator does not use or reveal the election private key before the close. In v1 this is enforced by business logic, not by cryptography.
- The voter's device and the delivered client code are honest.
- At least one independent party monitors the public log.

| Threat | v1 position |
| --- | --- |
| Vote selling or coercion using the receipt | Partly mitigated by receipt mode none (section 5.5); full protection needs profile B; stated to voters |
| Linking by IP address | Separate origins, no IP logging at the ballot box, Tor-friendly; residual risk |
| Linking by timing | Registration closes before voting opens (default); ballots are published only at the close |
| Linking by browser state | No cookies or shared storage between registrar and ballot box |
| Ranking used as a fingerprint | Configurable rank limit; admin warning when possible ballots exceed voters; residual risk in small electorates |
| Registrar issues extra credentials | Every issuance is logged against a roll entry; voters can check their own entry; count is bounded by the roll. A registrar can still sign hidden credentials and use them for voters who registered and did not vote: the verifier sees cast <= issued and cannot tell (see section 14, Review of M3 to M7) |
| Ballot box drops a ballot | In receipt mode full, the signed receipt is evidence and the inclusion proof fails publicly. In mode none nobody can tell |
| Ballot box forges a ballot | Impossible without a credential private key |
| Early results leak | Ballots are encrypted until the close; the operator is trusted not to decrypt early |
| Malicious client code | Static bundle with published hash, reproducible build, independent verifier; residual risk |
| Quantum adversary | Anonymity holds; forgery needs a quantum computer during the election (section 6) |
| Very small electorate | Anonymity set equals the number of ballots cast; stated to the admin |
| Registrar links a voter to their ballot | Blind signing: the registrar never sees the credential it signs, so it cannot match a roll entry to a ballot (section 5.1) |

## 3. Components and roles

The registrar and the ballot box are separate services on separate origins, so that neither alone can link a voter to a ballot.

| Component | Responsibility | Knows |
| --- | --- | --- |
| Registrar | Authenticates voters through an identity plugin, blind-signs one credential per roll entry | Who registered; never which credential |
| Ballot box | Accepts anonymous signed ballots, issues receipts | Credentials and ballots; never who |
| Public log | Append-only Merkle log of all election events | Public data only |
| Tally library | Pure Go package that computes results from ballots | Public data only |
| Verifier CLI | Checks a log export end to end and recomputes the result | Public data only |
| Trustees | Not used in v1; needed for threshold decryption in the mixnet profile | Nothing in v1 |
| Election admin | Defines the manifest and the electoral roll | The roll |
| Identity plugins | Map an external login to a stable subject ID | Login identity |
| Web client | Generates keys, blinds, encrypts, signs, stores the credential and receipt | The voter's secrets, locally only |
| Monitors | Third parties that mirror the log and check consistency | Public data only |

## 4. Election lifecycle

An election moves through seven phases, and each transition is itself an entry in the public log.

1. **Setup.** The admin creates the manifest: candidates, method, tie-break rule, maximum ranks, assurance profile, algorithms and schedule. The service generates the election key pair. The manifest is log entry 0.
2. **Roll publication.** The pseudonymous electoral roll is committed to the log: one opaque reference per eligible voter. This fixes the eligible count.
3. **Registration (hand-out).** Voters authenticate and obtain a blind-signed credential. Each issuance is logged against its roll reference. By default this phase closes before voting opens.
4. **Voting.** Voters submit encrypted, signed ballots anonymously and, if the election enables receipts, receive a signed receipt.
5. **Close.** The ballot box publishes all ballots and the final tree head. The election private key is published.
6. **Tally.** The result and its full trace are computed and logged.
7. **Audit.** Anyone runs the verifier on the log export. Voters check their receipts. A dispute window is configurable.

A registration deadline before voting is the default because it removes timing correlation. An election may allow overlapping registration and voting, at the cost of weaker anonymity, and the manifest records that choice.

## 5. Protocol for profile A

The voter's browser generates a credential key pair, the registrar blind-signs the public key, and the ballot box later accepts exactly one ballot signed by that key.

### 5.1 Credential issuance

1. The voter opens the voting client, a static page on the ballot-box origin. The client generates a credential key pair for this election and keeps it in local storage.
2. The client computes the blinded form of the credential message (section 5.6) and sends it to the registrar, which answers with a login link and a confirmation code. The client shows both to the voter; the link opens in a new tab.
3. The voter authenticates through an identity plugin. The registrar maps the login to a roll reference and checks that no credential has been issued for it.
4. The registrar asks the voter for the confirmation code that the voting client shows. If it is right, the registrar signs the blinded value with the election's issuing key and logs an `issuance` entry with the roll reference. The client fetches the blind signature.
5. The client unblinds and verifies the signature, then stores the credential: private key, public key and registrar signature.

The registrar sees only the blinded value. The ballot box sees no login. Before use, the client validates the issuing public key, because blindness depends on a well-formed key.

The registrar keeps the blinded value and its blind signature with the roll entry. If the answer gets lost, the same client can fetch the same blind signature again; a request with another blinded value is refused.

Lost credentials cannot be reissued in v1. A reissue would either break the count invariant or require revoking a credential that the registrar cannot identify.

### 5.2 Casting

1. The client encodes the ranking and encrypts it to the election public key.
2. The client signs `(election_id, ciphertext)` with the credential private key.
3. The client sends credential public key, registrar signature, ciphertext and ballot signature to the ballot box, with no cookies or authentication.
4. The ballot box verifies both signatures and that the credential has not voted, stores the ballot, and, in receipt mode full, returns a receipt: its signature over the election ID and the ballot's leaf hash.

Re-voting is off by default: one ballot per credential. If an election enables it, the last ballot counts and all versions stay visible in the log. The implementation does not offer re-voting yet: the verifier rejects a log in which a credential is used twice.

### 5.3 Close and decryption

1. The ballot box appends all ballots to the public log, ordered by leaf hash so that arrival order is not revealed, and publishes the final signed tree head.
2. The election private key is published in the log.
3. Anyone checks that it matches the election public key and decrypts every ballot. Plaintext ballots are logged next to their ciphertexts.
4. Malformed ballots are published and marked invalid with a reason; they are never silently dropped.

### 5.4 Receipt check

After the close, the client or any other tool requests an inclusion proof for the receipt's leaf hash against the final tree head. A valid receipt without a valid inclusion proof is public evidence of misbehaviour by the ballot box.

### 5.5 Receipt mode

Each election sets a receipt mode in its manifest, which trades proof of inclusion for the voter against protection from vote selling.

| Mode | What the voter keeps | Voter can check own ballot | Voter can prove vote to others |
| --- | --- | --- | --- |
| `full` (default) | Signed receipt and credential | Yes | Yes |
| `none` | Nothing: the ballot box issues no receipt, and the client deletes the credential key and all ballot data after casting | No | Not with the standard client |

In mode `none` the voter relies on the public counts and on universal verification of the tally.

**What a receipt ties together.** The receipt is the ballot box's signature over the election ID and the leaf hash of the ballot entry. The entry holds the credential public key, the signature by the credential, the ciphertext and the ballot signature, so the leaf hash commits to all of them, and the receipt does not show them by itself. After the close, the entries appear in the log in leaf-hash order, and whoever holds a receipt finds the entry by its leaf hash and so learns the credential public key of that ballot. After the tally the entry's decrypted ranking is published with it. A receipt therefore shows anyone who sees it how the ballot it covers was voted, and under which pseudonym. A receipt can be handed on, so it proves who voted only together with the credential key; vote sellers and coercers still ask for it. Nothing in the log links a ballot to a voter, because the registrar signed the credential blindly; timing and network addresses, which are not in the log, remain the residual risk of section 2. The pseudonym is the same for every ballot under one credential. Today a credential can cast only one ballot, so this adds nothing; an election that allowed re-voting would show anybody with a receipt whether the credential cast another ballot, which defeats re-voting as a defence against coercion (section 14).

Mode `none` stops casual vote selling but not a determined seller. A seller can run a modified client that keeps the credential key, or hand the credential to the buyer before voting. In profile A, any data that lets a voter find their ballot also lets them show it to others. Checking inclusion without being able to prove the vote requires profile B or a comparable method.

### 5.6 Messages and bindings

Every signed or encrypted message is the canonical encoding (section 7) of an array that starts with a context text. The context separates the uses of a key, and the election ID binds every message to one election.

| Message | Content | Made with |
| --- | --- | --- |
| Credential | `["stimmig-credential-v1", election_id, credential_public_key]` | Blind signature of the registrar's issuing key |
| Ballot signature | `["stimmig-ballot-v1", election_id, ciphertext]` | Credential private key |
| Ballot encryption info | `["stimmig-ballot-encryption-v1", election_id, credential_public_key]` | HPKE `info` input |
| Receipt | `["stimmig-receipt-v1", election_id, leaf_hash]` | Ballot box's receipt key |
| Tree head | `["stimmig-tree-head-v1", election_id, size, root, timestamp]` | Log key |

Details:

- **Ciphertext.** The ciphertext is the HPKE encapsulated key, an uncompressed P-256 point of 65 bytes, followed by the AEAD ciphertext. The plaintext is the canonical encoding of the ranking: an array of rank groups, each an array of candidate IDs. The associated data is empty.
- **Binding to the credential.** The credential public key is part of the encryption info. A ciphertext that is copied into the ballot of another credential therefore does not decrypt and is logged as invalid. This keeps the votes independent: nobody can have a copy of another voter's vote counted under their own credential. It is not a matter of anonymity, because ballots are anonymous and a copy reveals nothing about whose it was (the model in `model/` shows both; section 14).
- **Invalid ballots.** A ballot whose ciphertext does not decrypt is logged with the reason `decryption-failed`; one whose plaintext is not an encoded ranking with `malformed`. A ranking that breaks the ballot rules of the manifest is logged as decrypted, and the tally reports it as invalid in the result.
- **Issuing key check.** Before blinding, the client checks that the issuing key is an RSA key of at least 3072 bits in canonical DER form, with public exponent 65537 and a modulus without prime factors below 100.
- **Issuing key proof.** The client cannot see from the key that the exponent is coprime to the group order, and a registrar that chose a prime p with p-1 divisible by 65537 could learn about 16 bits of each credential from the blinded value. The manifest therefore holds `issuing_key_proof`, an array of eight byte strings. Value i (0 to 7) is the 65537th root modulo N of the challenge y_i, in big-endian form of exactly the length of N. The challenge y_i is derived from the modulus alone: SHA-256 is run in counter mode over the bytes `"stimmig-issuing-key-proof-v1"`, then the byte i, then the counter as 2 bytes big-endian, then N as a minimal big-endian integer, with the counter counting up from 0, and the output blocks are concatenated until they are at least the length of N plus 16 bytes; the first length-of-N plus 16 bytes, read as a big-endian integer, reduced modulo N, are y_i. A verifier checks that every value is between 1 and N-1 and that its 65537th power modulo N is y_i. If 65537 divided the group order, one value in 65537 would have such a root, so a registrar that picked the modulus would need about 2^128 tries to find one that passes eight values; four values left 2^64, which a funded attacker could grind, since a try costs one hash. The manifest is not valid without the proof. The construction is the project's own and has not been reviewed by a cryptographer.
- **Credential keys.** The registrar signs credentials blindly, so a voter can obtain a signature on any 32 bytes. The client, the ballot box and the verifier therefore accept only credential public keys that are canonical encodings of points that do not have a small order (a key whose multiple by 8 is the identity is refused). For such a key anyone could forge the ballot signature, and implementations of Ed25519 disagree on the signatures of such keys. For the other keys the ballot signature rule is that of Go's `crypto/ed25519`, which is RFC 8032 without the cofactor in the verification equation.
- **Keys per role.** The log key, the issuing key, the election key and the receipt key are four different keys.

## 6. Cryptography and algorithm agility

Every algorithm is named by a versioned identifier in the manifest and fixed for the whole election; the verifier rejects identifiers it does not know.

| Purpose | v1 default | Optional or later |
| --- | --- | --- |
| Credential blind signature | RSA blind signatures per [RFC 9474](https://www.rfc-editor.org/rfc/rfc9474), variant RSABSSA-SHA384-PSS-Deterministic, key of 3072 bits or more | Blind BLS as first alternative; later a public-registration scheme or a lattice blind signature |
| Ballot signature | Ed25519 | ML-DSA, selectable per election |
| Ballot encryption until close | HPKE ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)) in base mode: ECDH key agreement on P-256, HKDF-SHA256 and AES-256-GCM; the private key is published at the close | None needed |
| Decryption proofs | None: anyone decrypts with the published key | None needed |
| Log hashing | SHA-256 Merkle tree | None needed |
| Tree head and receipt signatures | Ed25519 | ML-DSA, selectable per election |
| Transport | TLS 1.3, hybrid post-quantum key exchange where the browser supports it | None needed |

Post-quantum position:

- **Anonymity.** RSA blinding hides the credential information-theoretically, so recorded traffic cannot be de-anonymised later. This statement is from general cryptographic knowledge and should be confirmed in the protocol review.
- **Unforgeability.** A quantum attacker could forge credentials or Ed25519 signatures only by attacking during the election. Elections that want to exclude this can select ML-DSA for ballot and log signatures today.
- **Ballot encryption.** Ballots are published in clear at the close, so there is no long-term secret to protect.
- **Blind signature.** No post-quantum blind signature is standardised. Published lattice schemes are still research: one has signatures of about 22 KB ([Beullens et al.](https://eprint.iacr.org/2023/077.pdf)), and a 2026 preprint proposes one with standard signature syntax ([BRaccoon](https://eprint.iacr.org/2026/1084)).

Credential scheme choices:

- **RSA blind signatures (v1 default).** The only standardised publicly verifiable blind signature, and the simplest to implement correctly. Its cost is size: 384 bytes or more per signature in every ballot entry.
- **Blind BLS (first alternative).** A pairing-based drop-in replacement behind the same algorithm identifier, with 48-byte signatures. The blind variant has no standard, and it needs a pairing library on server and client.
- **Public registration (preferred long-term direction).** Voters register public keys or commitments openly, and each ballot proves membership with a linkable ring signature or a zero-knowledge set-membership proof. This removes blind signing and lets everyone see exactly which roll entries registered, so the registrar cannot issue hidden credentials.
- **Excluded.** Blind Schnorr is forgeable when signing sessions run in parallel ([Benhamouda et al.](https://iacr.org/archive/eurocrypt2021/126960077/126960077.pdf)). Elliptic-curve Privacy Pass tokens can be verified only by the issuer, which rules out public verification.

Signing keys of the registrar and the log are held in an HSM where one is available.

In v1 the service generates the election key pair, keeps the private key until the close and then publishes it. Early decryption is prevented by business logic and operator trust, not by cryptography. Threshold decryption among trustees arrives with the mixnet profile, where the key must never be revealed.

P-256 and AES-GCM are chosen for ballot encryption because browsers provide both natively (section 11).

## 7. Public log and data formats

Each election has one append-only Merkle log, in the style of Certificate Transparency, and the complete log is downloadable as a single export.

| Entry type | Written by | Content |
| --- | --- | --- |
| `manifest` | Admin | Election definition, algorithms, public keys, schedule |
| `roll_commit` | Admin | Pseudonymous roll references and their count |
| `issuance` | Registrar | Roll reference and sequence number |
| `registration_close` | Registrar | Final issued count |
| `ballot` | Ballot box | Credential public key, registrar signature, ciphertext, ballot signature |
| `voting_close` | Ballot box | Final cast count |
| `election_key` | Tally | Election private key |
| `ballot_plain` | Tally | Decrypted ranking or invalidity reason, with reference to the ballot entry |
| `result` | Tally | Winners, pairwise matrix, trace, tie-break events |

Format rules:

- Entries use one canonical, deterministic encoding, so that independent implementations compute identical hashes. The bytes that are hashed and signed use deterministic CBOR (RFC 8949). The export and the API also offer a JSON rendering for human inspection, which is not the reference form.
- The leaf hash is SHA-256 over a domain-separation byte and the encoded entry.
- A signed tree head contains election ID, tree size, root hash, timestamp and signature. One is published at every phase transition and at a fixed interval.
- The log serves inclusion proofs and consistency proofs between any two tree heads.
- Roll references are salted hashes of the identity plugin's subject ID: SHA-256 over the canonical encoding of `["stimmig-roll-v1", salt, provider, subject]`. The salt is 32 random bytes per election and stays secret at the registrar, so that nobody can test whether a known address is on the roll. Each voter is told their own reference when the credential is issued, to check their roll entry and issuance status.

Encoding details:

- **Allowed CBOR subset.** Integers, byte strings, text strings, arrays, maps with text keys, booleans and null. Floating-point numbers, tags and indefinite-length items are forbidden. A reader rejects any item that is not in its single canonical encoding: shortest-form integers and lengths, map keys sorted bytewise by their encoding, no duplicate keys.
- **Entry.** An entry is the array `[type, body]`. The type is the text from the table above and the body is a map. The leaf hash is SHA-256 over the byte `0x00` and the encoded entry; inner nodes hash the byte `0x01` and both children, as in RFC 6962.
- **Election ID.** The election ID is the leaf hash of entry 0, the manifest. The manifest holds a random nonce of at least 16 bytes, so two elections with the same definition have different IDs.
- **Manifest.** The body has the fields `version` (1), `title`, `nonce`, `tally` (candidates, method, seats, rank limit, ballot rules and tie-break chain of section 8), `algorithms`, `receipt_mode`, `log_key`, `issuing_key` (DER SubjectPublicKeyInfo), `issuing_key_proof` (eight byte strings, section 5.6), `election_key` (uncompressed P-256 point), in receipt mode full `receipt_key`, optionally `schedule` and optionally `client_hash` (32 bytes). The schedule is added with the services. A reader rejects fields and algorithm identifiers it does not know.
- **Algorithm identifiers.** `log_hash` is `sha256-rfc6962-v1`, `tree_head_signature` is `ed25519-v1`, `credential` is `rsabssa-sha384-pss-deterministic-v1`, `ballot_signature` is `ed25519-v1`, `ballot_encryption` is `hpke-p256-hkdf-sha256-aes256gcm-v1` and, in receipt mode full, `receipt_signature` is `ed25519-v1`.
- **Entry bodies.** The fields of each body are:

  | Entry type | Fields |
  | --- | --- |
  | `roll_commit` | `references`: array of 32-byte roll references, strictly ascending |
  | `issuance` | `roll_reference`, `sequence` counting from 0 |
  | `registration_close` | `issued` |
  | `ballot` | `credential_key`, `credential_signature`, `ciphertext`, `signature` |
  | `voting_close` | `cast` |
  | `election_key` | `private_key`: the P-256 scalar, 32 bytes |
  | `ballot_plain` | `ballot`: log index of the ballot entry; and either `ranking` or `invalid` with a reason |
  | `result` | The tally result: counts, winners, ranking, tie, pairwise matrix, trace and tie-break events |

- **Entry order.** The entries follow the lifecycle: manifest, roll_commit, issuances, registration_close, ballots in leaf-hash order, voting_close, election_key, one ballot_plain per ballot in ballot order, result. Nothing follows the result. A log may end earlier; it is then valid as far as it goes.
- **Schedule.** The optional `schedule` map has the keys `registration_close`, `voting_open` and `voting_close`, each the time in seconds since the Unix epoch and each absent if not scheduled. The times that are present must be in this order, strictly: the registration closes before the voting opens, and the voting closes after it opens. At the time of `registration_close` the registrar closes the registration; at `voting_open` the ballot box opens the voting, as soon as the registration is closed in the log; at `voting_close` the ballot box closes the voting and publishes the ballots, and the registrar then tallies. Every service looks at its elections every 15 seconds. A step that is not scheduled, or that is late because another is, is left to the admin, who can also do a scheduled step earlier or later. The times are public from entry 0, so anybody can see whether the phases followed them; the verifier does not check the times of the entries.
- **Manifest tally keys.** The `tally` map has the keys `candidates` (array of text), `method` (`schulze`, `ranked-pairs`, `minimax`, `copeland`, `irv`, `borda` or `stv`), `seats` (integer, absent for 1), `max_ranks` (absent for the number of candidates), `no_equal_ranks` and `allow_empty` (booleans, absent for false), `tie_break` (array of `first-ranks`, `head-to-head`, `borda`, `fixed-order`, `declare-tie`; absent for first-ranks then declare-tie) and `fixed_order` (array of text). Absent means that the key is not in the encoding.
- **Result entry.** The body of the result entry is the result of the tally with the keys `method`, `seats`, `candidates`, `ballots`, `valid`, `abstentions`, `invalid` (array of `index` and `reason`, absent if empty), `winners`, `ranking` (array of arrays of candidates, tied candidates in one array), `tie` (`context`, `round` if not 0, `candidates`; absent if there is none), `pairwise` (matrix in candidate order of the manifest), `trace` and `tie_breaks` (absent if empty). A trace step has `op`, `round` (absent for 0), `candidates`, `values` (array of `candidate` and `value`, a decimal integer or a fraction `a/b`), `matrix` and `note`, each absent when empty. The operations are `pairwise`, `strongest-paths`, `copeland-scores`, `minimax-worst-defeats`, `borda-scores`, `lock` and `skip` (note `<winning votes> to <opposing votes>`), `quota` (note: the quota), `count` (note `exhausted: <number>`), `elect` (note `reached the quota` or `last candidates for the open seats`), `transfer-surplus` (note `surplus <number>, factor <number>`), `eliminate` and `tie-break` (note `<context>: <rule>`). The verifier compares the logged result with its own, byte for byte, so an independent verifier has to reproduce these texts; a verifier that does not can compare winners, ranking, pairwise matrix and tie. `invalid[].index` is the log index of the ballot entry, and the reasons are the texts of section 8.
- **Invalid reasons.** A ballot that breaks the ballot rules is reported with one of `empty ballot`, `<n> ranks, maximum is <m>`, `rank <k> is empty`, `rank <k> holds <n> candidates, equal ranks are disabled`, `unknown candidate "<id>"` and `candidate "<id>" ranked twice`.
- **Tree heads.** Section 4 says that a tree head is published at every phase transition. The verifier requires only that the last record is a tree head: a log that omits the heads in between, or ends before a phase is complete, is accepted as far as it goes. An independent party that wants the transitions witnessed must check the heads itself.
- **Tally input.** The result is computed from the rankings of the ballot_plain entries in log order. The logged result must equal the recomputed one byte for byte.
- **Signed tree head.** A map with `election_id`, `size`, `root`, `timestamp` in seconds since the Unix epoch, and `signature`. The signature covers the canonical encoding of the array `["stimmig-tree-head-v1", election_id, size, root, timestamp]`. Timestamps never decrease from one tree head to the next.
- **Export.** The export is a sequence of canonical items (RFC 8742), so it can be written and checked as a stream. The first item is the header `{"format": "stimmig-log-export-v1"}`. Each further item is a record, `["entry", entry]` or `["tree_head", tree head]`. Entries appear in log order, each tree head follows directly after the last entry it covers, and the last record is a tree head.
- **JSON rendering.** Byte strings are shown as hexadecimal text. The rendering cannot be converted back.

The verifier recomputes the root of every tree head from the entries of the export. This proves that all tree heads are consistent with each other without separate consistency proofs. Monitors that hold only tree heads use the consistency proofs of the log.

Ballot entries are not public during voting. Where receipts are enabled, the receipt binds the ballot box to the leaf hash, and the entries appear at the close in leaf-hash order.

Witness co-signing of tree heads by independent monitors is planned after v1.

## 8. Ballot rules and tally methods

A ballot is a limited ranking, and every tally method is a pure function from the manifest and the ballots to a result with a full trace.

Ballot rules:

- A ballot is an ordered list of rank groups, each holding one or more candidates.
- `max_ranks` is set per election, from 1 to the number of candidates. Typical values are 2 to 5.
- Equal ranks are allowed by default and can be disabled per election.
- Unranked candidates count as tied below all ranked ones.
- Whether an empty ballot is a valid abstention is set per election.

| Method | Type | Target |
| --- | --- | --- |
| Schulze | Condorcet, single winner or full ranking | v1, default |
| Ranked Pairs | Condorcet | v1 |
| Minimax | Condorcet | v1 |
| Copeland | Condorcet | v1 |
| Instant runoff | Elimination | v1 |
| Borda | Positional | v1 |
| Single transferable vote | Multi-winner, proportional | v1 |

Multi-winner elections can use the top places of the Schulze ranking or single transferable vote. All other methods fill one seat only.

Method details:

- **Pairwise strength.** Schulze, Ranked Pairs and Minimax measure a pairwise win by its winning votes, not by its margin. Ranked Pairs prefers the smaller opposition among wins with equal winning votes.
- **Rankings.** Schulze ranks by strongest paths, Ranked Pairs by the locked wins, Copeland by wins minus losses, Minimax by the largest defeat. Candidates that the method leaves level go through the tie-break chain.
- **Borda.** A candidate scores one point for every candidate ranked below and half a point for every candidate tied with. Unranked candidates are tied at the bottom.
- **Equal ranks in instant runoff and single transferable vote.** A ballot counts for the candidates of its highest rank group that still holds a continuing candidate, and its weight is split equally among them. A ballot with no continuing candidate is exhausted.
- **Instant runoff.** The candidate with the fewest votes is eliminated until one is left.
- **Single transferable vote.** The quota is the Droop quota `floor(votes / (seats + 1)) + 1`, fixed at the start over the non-empty valid ballots. A candidate who reaches the quota is elected. All ballots of an elected candidate are transferred at the fraction surplus / total of their weight (weighted inclusive Gregory method). The surpluses of all candidates elected in one round are transferred together, so their order never needs a tie-break. If nobody reaches the quota, the candidate with the fewest votes is eliminated. When the continuing candidates are as many as the open seats, all are elected.
- **Invalid ballots.** A ballot that breaks a ballot rule is not counted and is reported with its reason.

Tally interface and rules:

- `Tally(manifest, ballots)` returns winners, ranking, pairwise matrix, a step-by-step trace and all tie-break events.
- The library has no I/O, uses exact integer or rational arithmetic, never floating point, and never depends on map iteration order.
- The server and the verifier CLI use the same package.

The admin chooses the tie-breaking when creating the election, and the choice is recorded in the manifest. Only non-random rules exist: every rule is computed from the ballots or fixed in the manifest before voting starts. The admin picks an ordered chain of rules; each rule is applied only to the candidates still tied after the previous one, and the chain must end with *fixed order* or *declare tie*:

- **Most first ranks.** The tied candidate ranked first on the most ballots wins. If still tied, second ranks are compared, and so on down to the maximum rank.
- **Head-to-head.** Among the tied candidates only, the one who beats the others pairwise wins.
- **Borda score.** The tied candidate with the highest Borda score over all ballots wins.
- **Fixed order.** The manifest lists a candidate order that decides ties.
- **Declare tie.** The result reports the tie and the organisation decides outside the platform.

The default chain is: most first ranks, then declare tie.

How the chain is applied:

- **Tied places in a ranking.** The chain orders every group of candidates that the method leaves level. If a group that straddles the last seat stays tied, the result reports the tie and names only the definite winners.
- **Tied elimination.** In instant runoff and single transferable vote, the chain orders the candidates with the fewest votes, and the one ranked last is eliminated. If the chain leaves that tie standing, the count stops and reports the tie.
- **A tie in Ranked Pairs that does not matter.** The chain orders all candidates in a batch of equally strong wins when two of its wins conflict, and the count stops with a tie when two wins of the batch stay level, also if they do not conflict. The result then reports a tie that a finer rule would have resolved. This follows the rule below literally and errs on the side of declaring a tie.
- **Equally strong wins in Ranked Pairs.** Such wins are locked together when that closes no cycle. Otherwise the chain orders the candidates involved, and the wins are locked by the rank of their winner, then of their loser. If two wins stay level, the count stops and reports the tie.
- **Most first ranks** counts a candidate once for every ballot that has it in the first rank group, also when it shares that group.
- **Head-to-head** moves the candidate who beats all other tied candidates to the top and the one who loses to all of them to the bottom, and repeats. The rest stay tied.

No seed and no randomness beacon is used. Every tie-break is recomputable from the manifest and the published ballots alone, and each applied rule appears as a tie-break event in the trace.

## 9. Identity plugins

Identity comes from pluggable providers that return a stable subject ID; eligibility is a separate electoral roll matched against those IDs.

```go
type IdentityProvider interface {
    ID() string
    Begin(ctx context.Context, electionID, state string) (redirectURL string, err error)
    Complete(ctx context.Context, callback *http.Request) (Subject, error)
}

type Subject struct {
    Provider   string
    StableID   string
    Attributes map[string]string
}
```

| Plugin | Subject ID | Target | Note |
| --- | --- | --- | --- |
| Email link | Email address | v1 | Roll is a list of addresses |
| OpenID Connect | Issuer and `sub` claim | v1 | Covers most organisational single sign-on |
| ATProto | DID | v1 or shortly after | The roll must list specific DIDs, because an account is not proof of one person |
| SAML | Name ID | Later | Needed for BundID |

Rules:

- An election may accept several providers; the roll stores provider and subject ID per voter.
- `Begin` receives a state value that names the registration session, and the provider hands it back in the `state` query parameter of its callback. A provider may serve pages of its own under `/v1/identity/{provider}`.
- The email provider shows a form for the address and mails a login link, authenticated with HMAC-SHA256 under a secret of the registrar. The subject ID is the address in lower case. A link is mailed only to addresses on the roll, and the form answers the same either way, so that it neither reveals the roll nor mails strangers.
- The registrar stores only the roll reference and an issued flag. It keeps no profile data.
- v1 plugins are Go packages compiled into the registrar. An out-of-process plugin protocol can follow.

BundID needs an organisational step as well as code. Its integration process uses SAML ([FITKO slides](https://www.fitko.de/fileadmin/fitko/veranstaltungen/ozg-erfahrungsaustausch-22/BundID_OZG-Erfahrungsaustausch.pdf)), and one integrator states that only public authorities currently get access ([Bare.ID](https://support.bare.id/de/kb/articles/pdf/beh-rdliche-identity-provider-einbinden-bundid-elster-unternehmenskonto-bayernid)).

## 10. Architecture and deployment

All services are stateless Go processes that scale horizontally on Kubernetes; PostgreSQL is the only stateful component.

| Service | State | Scaling |
| --- | --- | --- |
| Registrar | Roll references and issued flags in its own database | Horizontal, autoscaled |
| Ballot box | Ballots and used credentials in its own database | Horizontal, autoscaled |
| Log | Entries, Merkle nodes and tree heads | One sequencer per election for appends; read path horizontal and cacheable |
| Tally | None; runs once at the close, inside the registrar, which holds the election key | Single request |
| Static client | None | Any static host or CDN |

Deployment rules:

- One Go binary provides all roles as subcommands: the services `log`, `registrar` and `ballotbox`, and the tools `admin`, `client`, `verify` and `tally`. The services are configured by environment variables only, so that tokens never appear on a command line.
- Registrar and ballot box run as separate deployments with separate databases, credentials and domains. Operation by separate parties is supported and recommended.
- The ballot box and its ingress write no IP addresses or other client identifiers to logs or metrics.
- A valid credential signature is the ballot box's abuse control, so it needs no IP-based rate limiting.
- Append ordering is serialised in PostgreSQL, so any replica can accept writes without a separate coordinator.
- The databases enforce uniqueness themselves: one issuance per roll reference and one ballot per credential are constraints, not read-then-write checks. Every request is checked against the current phase on the server.
- No service stores a link between a voter and a ballot, not even in encrypted form.
- Log exports and proofs are immutable once published and can be served from object storage.
- Signing keys are accessed through an HSM interface (PKCS#11 or a network HSM); a software key store exists for development.
- Deployment artefacts are a container image and a Helm chart.

Service interfaces:

All request and response bodies are canonical CBOR; errors are plain text with an HTTP status. Admin and writer calls carry a bearer token.

| Service | Call | Caller | Purpose |
| --- | --- | --- | --- |
| Log | `POST /v1/keys` | Admin | Create a log key |
| Log | `POST /v1/elections` | Admin | Create the log from the manifest |
| Log | `POST /v1/elections/{id}/entries` | Registrar, ballot box | Append entries atomically and sign a tree head |
| Log | `GET /v1/elections/{id}/head`, `/export`, `/inclusion`, `/consistency` | Public | Tree head, complete log, proofs |
| Registrar | `POST /v1/keys` | Admin | Create the issuing key and the election key |
| Registrar | `POST /v1/elections` | Admin | Register the election by its manifest |
| Registrar | `PUT /v1/elections/{id}/roll` | Admin | Publish the roll and open registration |
| Registrar | `POST /v1/elections/{id}/close` | Admin | Close registration |
| Registrar | `POST /v1/elections/{id}/tally` | Admin | Publish the key, the plaintexts and the result |
| Registrar | `POST /v1/elections/{id}/sessions` | Voter | Send the blinded credential, receive the login URL |
| Registrar | `GET /v1/callback/{provider}` | Voter | Return from the identity provider; shows the confirmation form |
| Registrar | `POST /v1/confirm` | Voter | Check the confirmation code; the credential is issued |
| Registrar | `GET /v1/sessions/{session}` | Voter | Fetch the blind signature |
| Ballot box | `POST /v1/keys` | Admin | Create a receipt key |
| Ballot box | `POST /v1/elections` | Admin | Register the election by its manifest |
| Ballot box | `POST /v1/elections/{id}/open`, `/close` | Admin | Open the voting; close it and publish the ballots |
| Ballot box | `POST /v1/elections/{id}/ballots` | Voter | Cast a ballot, receive the receipt |
| Ballot box | `GET /v1/elections/{id}` | Public | Phase and number of ballots cast |
| Ballot box | `GET /v1/config` | Public | The public URLs of the log and the registrar, for the voting client |
| Ballot box | `GET /v1/client` | Public | Hash of the voting client's bundle |

Service rules:

- **Keys per election.** Every election has its own log key, issuing key, election key and receipt key. An issuing key must never serve two elections: the registrar signs blindly and could not tell for which election a credential is, so a voter of one election could obtain a credential for another.
- **Election key.** The registrar holds the election private key until the tally, and the ballot box holds the ciphertexts until the close. Reading ballots early therefore needs both services, the same assumption as for anonymity.
- **Writers.** The log gives the registrar and the ballot box one token each and limits each to its entry types: roll, issuance, registration close and the tally entries for the registrar; ballots and voting close for the ballot box.
- **Safe repetition.** Every append names the log size it expects and is refused otherwise. The registrar and the ballot box verify the whole public log before they open the voting, close it or tally, and act on the phase they find there. Closing the voting and tallying can be repeated after a failure.
- **Order of phases.** The ballot box opens the voting only when registration is closed in the public log. Overlapping registration and voting (section 4) is not implemented.
- **Repeated ballot.** The ballot box answers the same ballot of a credential again with the same receipt, so that a voter whose connection broke can retry. Another ballot of that credential is refused.
- **Sessions.** A registration session lasts one hour, an email login link 30 minutes, a confirmation 10 minutes with 5 attempts per session. A client continues a stored session for 50 minutes instead of starting another. A login mail goes to an address once a minute.
- **Ballot answers.** A ballot that is stored gets its receipt again whatever the phase. A ballot that is not stored is refused with 425 before the voting opens, 410 after it closed, 403 if a signature is invalid and 409 if the credential has voted another ballot. A client keeps a ballot that it sent only after an answer that tells nothing (408, 429, 5xx, no answer); after any other 4xx it deletes it.
- **Appends.** Every append to the log names the size the log must have, and the log service refuses it with 409 if the log differs or the entry type may not follow the last one, and with 422 if the entries are not valid in this log: the log service applies the checks of the verifier (section 12) to every entry before it signs a tree head, so a leaked writer token cannot append an issuance for a voter who is not on the roll, a wrong sequence number or count, or a ballot without valid signatures, which would make the log fail verification for good. The service keeps the state of the checks in memory for up to 16 elections and builds it again from the log when it is missing or when another replica has appended; that costs one verification of the log. The log service does not know the voters' real eligibility or the receipts; it checks only what the log shows. The registrar catches up with issuance entries that its database lost: it adopts the next issuances in order for roll entries that have none, and signs the voter when they log in again.
- **Shutdown.** Services finish the requests in flight for up to 45 seconds after SIGTERM. A service does not start without `STIMMIG_KEY_ENCRYPTION_KEY` (and the registrar not without an SMTP server) unless a development flag is set.

## 11. Web client

The voting client is a static bundle that does all voter-side cryptography in the browser and works on desktop and mobile.

- **Delivery.** The bundle is served from the ballot-box origin without cookies. Its hash is published in the manifest and the build is reproducible (`make web`).
- **Crypto code.** The client uses the browser's built-in Web Crypto API wherever it offers the algorithm. Operations it lacks, such as RSA blinding or ML-DSA, fall back to the project's Go code compiled to WebAssembly.
- **Ranking interface.** Drag and drop, with tap-to-rank on touch screens and full keyboard operation. The interface enforces `max_ranks` and shows the ballot for confirmation before submission.
- **Credential storage.** The credential stays in browser storage between registration and voting. The client offers an encrypted export as file or QR code, for backup and for voting on another device.
- **Receipt.** In receipt mode full, the receipt can be downloaded, printed or shown as a QR code. Before the client shows that the ballot is cast, it recomputes the leaf hash itself and checks the receipt signature against the receipt key of the manifest. The client checks the receipt automatically after the close if the voter returns, and then also shows the voter their decrypted ballot from the log.
- **Key checks.** The client validates the issuing key and the election key of the manifest before it uses them.
- **Origin protection.** The page that holds the credential has a strict content security policy and loads no third-party scripts. All randomness comes from the browser's cryptographic generator.
- **Trust statement.** The interface tells the voter that the operator holds the election key until the close, and what the unranked candidates on a ballot mean.
- **Accessibility and languages.** The target is WCAG 2.1 AA. German and English ship first; all text is translatable.
- **Admin interface.** `stimmig admin-web` serves a separate page, in English only, that does what `stimmig admin` does: it lists the elections, shows the state of one as the verified log shows it, creates an election from the same JSON definition (title, receipt mode, tally rules, schedule) with a check that reports the number of possible ballots, publishes a roll, and performs the phase steps and the tally, each after a confirmation. It warns when the number of possible ballots exceeds the number of voters. The page is static and public. Its calls go to a JSON interface under `/api` and need the token of the admin web page (`STIMMIG_ADMINWEB_TOKEN`, at least 16 characters, compared in constant time) in an Authorization header; the page keeps it in `sessionStorage`. There is no cookie, so another site cannot drive the interface, and no CORS header. The tokens of the three services stay in the environment of the admin web server and never reach the browser. The server listens on 127.0.0.1:8090 by default (`STIMMIG_ADMINWEB_LISTEN`, not the services' `STIMMIG_LISTEN`) and speaks HTTP; it refuses another address than loopback unless `STIMMIG_ADMINWEB_ALLOW_REMOTE=1` is set, and then TLS and access control belong in front of it. The token must be generated, must differ from the three service admin tokens, and failed attempts are not limited. The roll is checked for plain email addresses, because it cannot change after it is published. Its content security policy allows scripts and styles from its own origin only. The registrar lists its elections for the admin at `GET /v1/elections`.

## 12. Verification and testing

Correctness of the result rests on public recomputation, so the verifier and the test vectors are first-class deliverables.

The verifier CLI takes a log export and checks, in order:

1. Tree head signatures and consistency between all tree heads.
2. Every issuance refers to a distinct roll entry, with consecutive sequence numbers.
3. Cast ≤ issued ≤ eligible, and the logged counts equal the numbers of entries.
4. Every ballot carries a valid registrar signature and ballot signature, no credential is used twice, and the ballots are in leaf-hash order.
5. The published election key matches the public key in the manifest, and every ballot has one plaintext entry that equals the recomputed decryption.
6. The recomputed tally equals the logged result, including tie-break events.

Testing:

- Published test vectors per method, covering cycles, ties, equal ranks and truncated ballots.
- Property tests, for example that a Condorcet winner wins under every Condorcet method and that ballot order never changes the result.
- Cross-checks against existing open source implementations of the same methods.
- Fuzzing of every parser that reads untrusted input.

Formal methods:

- A symbolic protocol model in ProVerif is in `model/` (milestone M8). It proves ballot privacy against a registrar and a ballot box that work together, up to timing, and the independence of votes and their secrecy until the close, and its control models find the attacks when blinding or the binding of the ciphertext to the credential is taken away. It does not check unforgeability of credentials or the count invariant, which ProVerif cannot express; those stay with the implementation and the verifier. See `model/README.md` for the assumptions.
- Code-level verification is optional and not required for v1. Go programs can be verified with Gobra from ETH Zurich; this is from memory and needs checking before it is planned. The tally package is the only sensible target.
- The data formats are fully specified, so independent verifiers in other languages are possible and welcome.

## 13. Milestones

Implementation starts with the parts that are pure and independently testable, and adds services and the interface afterwards.

1. **M0: Repository.** GitHub repository with this specification as `SPEC.md`, licence, CI and linting.
2. **M1: Tally library.** All v1 methods, tie-breaking, test vectors and the `tally` command.
3. **M2: Log.** Canonical encoding, Merkle tree, tree heads, proofs, export format and the `verify` command for log structure.
4. **M3: Cryptography.** Blind credential, ballot signatures, ballot encryption and key publication. The reviews of Belenios, Helios and Elekto are in section 14.
5. **M4: Services.** Registrar and ballot box on PostgreSQL, with the email identity plugin. End-to-end election from the command line.
6. **M5: Web client.** Voting client and admin interface.
7. **M6: Deployment.** Container image, Helm chart, autoscaling, HSM key store.
8. **M7: Identity.** OpenID Connect and ATProto plugins.
9. **M8: Review.** Protocol model (done, `model/`) and an external security review before any real election (open).

After v1: mixnet profile, SAML and BundID, threshold decryption, blind BLS and public-registration credential schemes, post-quantum credential scheme, witness co-signing.

## 14. Decisions

- **Project name.** Stimmig (German: "Stimme" is a vote, "stimmig" means coherent, it adds up). No voting product of that name was found in a web search on 2026-11-11.&#32;
- **Licence.** EUPL-1.2.
- **Canonical encoding.** Deterministic CBOR, with a JSON rendering for inspection.
- **Log formats.** Entry, election ID, tree head and export formats are fixed in section 7. The election ID is the leaf hash of the manifest entry. The export is a streamable sequence in which tree heads follow the entries they cover.
- **CBOR library.** The Go code uses `github.com/fxamacker/cbor/v2` and accepts only input that re-encodes to the same bytes. The golden export in `election/testdata` was also checked with an independent Python implementation.
- **Log storage.** M2 keeps the log in memory. PostgreSQL storage and the `log` service follow in M4 with the other services.
- **Client crypto.** Browser Web Crypto first, Go compiled to WebAssembly as fallback.
- **Lost credentials.** Not reissued, at least in v1.
- **Tie-breaking.** Non-random only: a chain of ballot-derived or fixed rules chosen at election creation. No seed, no external beacon.
- **Trustee key setup.** None in v1: the election key is published at the close, and early decryption is prevented by business logic.
- **Multi-winner elections.** Both the Schulze ranking and single transferable vote in v1.
- **Tally rules.** Winning votes as pairwise strength; Droop quota and weighted inclusive Gregory transfers for single transferable vote; equal ranks split a ballot's weight. Details are in section 8.
- **Existing systems.** Belenios was reviewed from source (4.0.0\~dev, November 2026) and is not used as a base: its credential authority knows the voter-to-credential mapping, storage is file-based on a single node, there is no rank limit, no configurable tie-breaking and no receipt mode, and identity schemes are compiled-in OCaml modules. It remains the reference for the later mixnet profile, for the public archive and in-browser verification, and for the ranking UX of its booth. Its code is AGPL-3.0, so copying it would make the combined work AGPL; it is used as a reference only.
- **Helios review.** Helios was reviewed from source (`benadida/helios-server` 4.0.0, commit `684a7b0`, November 2026; its documentation site was not reachable) and is not used as a base: it offers approval ballots only, the server authenticates the voter when the ballot is cast and stores the ballot under the voter's identity, and by default the operator is the only trustee. Its code is Apache-2.0. Lessons taken: ciphertexts are bound to the credential, which keeps votes independent where Helios publishes ballots under the voters' names and a copy reveals a vote ([Cortier and Smyth](https://eprint.iacr.org/2012/185)); in Stimmig ballots are anonymous, so there a copy is not a privacy attack; every signed message has a context text and the election ID, after the weak Fiat-Shamir transform of Helios ([Bernhard, Pereira and Warinschi](https://eprint.iacr.org/2016/771)), which still hashes the commitments alone with SHA-1; keys are validated and malformed ballots are logged as invalid instead of stopping the tally ([Chang-Fong and Essex](https://whisperlab.org/papers/Helios-ACSAC-16.pdf)). The Helios server can cast ballots for voters who abstain; in Stimmig the ballot box cannot, and the registrar can only for roll entries that never register, which the affected voter can see in the log.
- **Elekto review.** Elekto was reviewed from source (`elekto-io/elekto`, commit `da4c19c`, March 2026) and is not used as a base: the server receives every ballot in clear in the authenticated session, nothing is publicly verifiable, and the operator is fully trusted. Its code is Apache-2.0. It uses Schulze with winning votes and leaves ties unresolved, as Stimmig does by default. Lessons taken: uniqueness is enforced by database constraints and phases are checked on the server (section 10), decrypted rankings are validated strictly, and no voter-to-ballot link is stored. Worth borrowing for the interface: a random candidate order and an explicit "no opinion" wording for unranked candidates.
- **Message formats.** All signed and encrypted messages have a context text and the election ID (section 5.6). Ballot encryption is HPKE, a standard construction of the ECDH and AES-GCM named before. The credential uses the deterministic RFC 9474 variant, because the message contains a fresh public key; the signature is then a plain RSASSA-PSS signature that browsers verify natively.
- **Cryptography libraries.** Blind RSA and HPKE come from `github.com/cloudflare/circl`; no primitive is implemented in this project. The golden export in `election/testdata` was checked with an independent Python implementation (`cbor2`, `cryptography`, `pyhpke`): all signatures verify and all ballots decrypt to the logged plaintexts.
- **Protocol model (M8).** The model in `model/` (ProVerif 2.05) proves ballot privacy in the symbolic model against an attacker that controls the network and the registrar and sees every ballot, which includes a ballot box that works with the registrar, except for timing and the order of the casts, which the model leaves out. It proves the independence of votes and their secrecy until the close. Its controls find the attacks without blinding (privacy) and without the binding of the ciphertext to the credential (independence). Two findings for the specification: the binding of the ciphertext to the credential protects the independence of votes, not their privacy, because ballots are anonymous and a copy reveals nothing about whose it was (unlike Helios), so section 5.6's claim to answer the ballot-copying attacks on Helios is true for independence only; and the separation of registration and voting in time is an assumption that the privacy result rests on. Not machine-checked: unforgeability of credentials (the query does not terminate with the blind signature equation), and counting (ProVerif cannot express it). The external security review is still open, and no review has looked at the model yet."
- **Confirmation code.** After the login the registrar does not issue the credential at once. The voter types a code of 8 digits that the registrar gave to the voting client when the registration started. Without it, somebody could start a registration with a credential of their own, send the login link to a voter, and receive that voter's credential once the voter logs in; with single sign-on the voter might not even see a prompt. A session allows five attempts. This is the defence of the OAuth device flow, with the same remaining weakness: a voter who types a code that a stranger sent them gives their credential away, and the page warns about that. Steps 2 and 4 of section 5.1 changed accordingly: there is no redirect with the signature in the URL fragment.
- **Identity (M7).** The OpenID Connect provider uses the authorization code flow with PKCE and a nonce, both derived from the registration session with HMAC, so that it keeps no state; the ID token is verified with `github.com/coreos/go-oidc`. The subject ID is `<issuer>#<sub>`, and the roll file lists such voters as `oidc:<issuer>#<sub>`. One issuer per registrar is configured. It was tested against a fake issuer in the tests, not against a real identity provider.
- **ATProto is not built.** Its OAuth profile needs handle and DID resolution, discovery of the user's server, pushed authorization requests, DPoP and a public client metadata document. That is a large amount of security-critical code that cannot be tested against real servers from the development sandbox, so it is left for a later step rather than shipped unverified.
- **Deployment (M6).** One container image holds the binary for all roles and the voting client's bundle; it runs as a non-root user on a distroless base. The Helm chart in `deploy/helm/stimmig` creates a Deployment, a Service and a HorizontalPodAutoscaler per role, and an Ingress for every role that has a host name. Roles can be switched off, so that registrar and ballot box run in different clusters. Secrets come from existing Kubernetes Secrets. The services create their tables at start under a database lock, so that replicas can start together.
- **Key store (M6).** The services encrypt their private keys before they store them, with AES-256-GCM under a key-encryption key from the environment, bound to the public key they belong to. This is the software key store. It protects against a copied database, not against a compromised service process. An HSM through PKCS#11 is not built: it needs native code and a device or simulator to test against. Tree head and receipt signing already go through Go's `crypto.Signer` interface, where an HSM can be attached; blind signing needs the raw RSA operation of the HSM, and the election key must stay exportable because it is published at the close.
- **Open points from M6.** The image was built and started in the development sandbox with vendored dependencies; the module download step of the Dockerfile and a registry push were not exercised. The chart passes `helm lint` and renders, but it was not installed in a cluster. It has no network policies, no pod disruption budgets and no PostgreSQL; the readiness probe only checks that the port is open. Autoscaling is on CPU only. There is no key rotation for the key-encryption key.
- **Web client (M5).** The voting client is a static page without dependencies plus the Go client package compiled to WebAssembly; the same code runs in the command line client. All voter-side cryptography runs in the WebAssembly module and none in the browser's Web Crypto API, so there is one implementation to review; this departs from the "Web Crypto first" rule of section 11. Web Crypto is used only for the backup file (PBKDF2-SHA256 with 600000 rounds and AES-256-GCM). The ballot box serves the bundle from a directory with a content security policy that allows code from its own origin only. The manifest field `client_hash` is SHA-256 over the canonical encoding of the array of `[name, SHA-256 of the content]` of the bundle's files, sorted by name.
- **Registration in the browser.** The page does not redirect to the registrar. It shows the login link, which opens in a new tab, and waits. Before that it stores the credential key and a seed from which the blinding is derived, so that a reload or a closed tab does not lose the credential: the client rebuilds the same request and fetches the signature that the registrar keeps for it. The link that the voter opens names the election ID and nothing else. The log and the registrar come from the ballot box that served the page (`GET /v1/config`, set by the operator), because a link that named another registrar could pass on the voter's login URL and confirmation code of a registration that the link's author controls, and receive the voter's credential. The ballot box also refuses election IDs it does not know. The client verifies the whole log against the ID before it uses anything from it.
- **Cast state.** A ballot counts as cast when the ballot box has answered with a receipt, or in receipt mode none when the client has deleted it. An answer that refuses the ballot deletes the stored ballot. Only after a failure without an answer the client keeps the ballot and sends it again, and then refuses to send another ranking until that attempt is resolved.
- **Open points from M5.** The admin web interface came later (see below). Not built: QR codes for credential and receipt, printing, automatic receipt check on return (the voter presses a button). The page was checked by hand in headless Chromium through a complete election, including reload, keyboard, drag and drop and backup; that check is a script in `web/check` that is not part of CI, and no accessibility audit against WCAG 2.1 AA was run. The WebAssembly module is about 12 MB (3 MB compressed). The reproducible build was confirmed on one machine only. In receipt mode none the page deletes credential and ballot from its storage, but an earlier backup file still holds the credential.
- **Services (M4).** The interfaces and rules are in section 10. PostgreSQL is the only store; the tests that need it run against a real database and are skipped without one. The driver is `github.com/jackc/pgx/v5`. The voter's side is the `client` package with a command line front end; the web client of M5 is meant to run the same code.
- **Re-voting for the sake of coercion resistance (not built).** Section 5.2 offers last-ballot-wins as an option, but the log would show all versions under one credential key, and a receipt names that key (section 5.5), so a coercer who demanded a receipt could see afterwards whether the voter voted again. Estonia's online re-voting works because its ballot box does not reveal this; to match it, the ballot box would have to de-duplicate and publish only final ballots, which gives up public verification of the de-duplication, or the tally would need a mixnet with hidden re-votes. Even then, whoever holds the credential key (also from the backup file) or controls the voter's mailbox decides the last ballot, and there is no paper override. A decision on whether to build any of this is open.
- **Admin web page.** The admin logic moved from the command into the package `admin`, which the command and the page share. Decisions: the new election is entered as the JSON definition of the command line, with a template, not as a form with a field for every rule, because the tie-break chain and the fixed order do not fit a simple form and one format means one set of checks; the page is a thin client, and its server calls the three services with their admin tokens, so the browser holds a token of its own that opens nothing but the admin web server; a single shared token, no accounts and no audit trail, as with the command line (every step is public in the log anyway); the status comes from the log export that the server verifies completely, so the page shows what a voter's verifier would. Not built: accounts and roles, a form for the definition, German texts, TLS in the server itself, a role in the Helm chart (run it where the admin works, or with a port forward). The page was checked in headless Chromium (`web/check`, with the services of the voting page).
- **Schedule (M4 follow-up).** The services open and close the phases at the times of the manifest's `schedule` (section 7), driven by their own clocks. Replicas may all run the check; the steps are idempotent and a conflict is skipped. Overlapping registration and voting is still not implemented, and the schedule requires them to be apart. The registrar marks an election as tallied in its database (migration step 3) so that it does not look at it again.
- **Review of M3 to M7.** A second model reviewed the code read-only after M7, and found the following, all checked against the code. Fixed: the client counted a refused cast as cast and then resent the old ranking; the registrar URL of the page came from the voter's link, so a link could pass on a login and its code; a client that disconnected during an issuance left the registrar behind the log, which then refused all further appends for that election (writes are now independent of the client, and a size conflict is reconciled when the log already holds the identical entry); field names of entries matched case-insensitively and the verifier hashed a re-encoding of a ballot instead of the logged bytes (decoding is strict now and the verifier uses the log's leaf hash); the services did not check that the log answered for the election they asked about; the receipt check asked the log service for one leaf and so told its operator which ballot the client holds (the proof is computed locally); the email form revealed roll membership by timing and mail failures, and could be used to flood addresses (answers are uniform, mail goes in the background, one mail per address and minute); a writer token could append entries out of their place and make the log unverifiable for good (the log service enforces the lifecycle order); anonymous request bodies were limited to 256 MB (64 KiB now); the clients of the services had no timeout; a backup file could carry other server URLs; and the registrar's key could weaken blinding without the client being able to see it (the manifest now carries a proof, section 5.6).
- **Second review round.** Two reviewers, again read-only and each tracing the flows with the first round's fixes in mind, found the following. Fixed: the issuing key proof had 2^-64 soundness and now has 2^-128; credential keys of small order and non-canonical keys were accepted; a null inside a rank group was decrypted to the empty name and logged as a ranking, an empty array had two accepted encodings, and the tally's invalid ballots were named by a position, not a log index; an issuance whose transaction was lost after the log accepted it blocked all later issuances and the close of the registration until the voter returned (the registrar now catches up, and services shut down gracefully); a ballot that the ballot box stored was refused after the close and the client then deleted its only copy, and a client that was killed while it sent a ballot had no record of it (the ballot is stored before it is sent, and only a refusal deletes it); the client never looked for its roll entry and issuance in the log; a stored state kept URLs from an older page version; the log service's order check could race a writer that did not name the size; the login mail limit kept a row for any string posted; and the defaults let a mistyped secret store the election key in clear, print the voters' addresses, log client addresses of the ballot box through the HTTP server's error log, and serve a page over HTTP. Not changed: the tally methods, which the first reviewer checked against 60000 random elections, an independent instant-runoff and the Condorcet property without finding an error.
- **Limits found in the second round and not fixed.** (1) Fixed after the audit: the log service now checks the content of every entry before it signs (section 10). What remains is that a leaked writer token can still append valid entries that the writer should not have, for example issuances for the voters on the roll or ballots with valid credentials that the ballot box did not accept, which the log cannot tell from honest ones. (2) The registrar holds a database lock across the call to the log service during an issuance; a slow log delays issuance and the creation of sessions for that election. (3) Anybody who knows an address on the roll can use up its mail minute and so keep the voter from getting a login mail; a limit per client at the ingress makes this expensive, and the registrar has none. (4) The container image and the CI actions are pinned by tag, not by digest, and a change of the Go version changes the WebAssembly bytes and so `client_hash`. (5) A hot row: every cast takes a shared lock on the election row of the ballot box. (6) The tree heads between phases are not required (section 7).
- **Limits found in that review and not fixed.** (1) A registrar can sign credentials without logging them and use them for voters who registered and did not vote. The verifier sees cast <= issued and cannot tell. This is inherent to blind signatures without per-credential accountability; the public registration of the later credential schemes (section 6) removes it. In receipt mode none, a ballot box that drops a ballot cannot be caught either. (2) Whoever runs the log service sees the addresses that download the export, and the registrar's identity logs are linkable to them if both are run by one party; the log operator is therefore inside the anonymity trust set, as are registrar and ballot box. (3) The anonymity of the credential rests on the registrar's key being honestly generated. The proof in the manifest catches one flaw, a modulus whose group order is divisible by 65537; it is not a proof of an honest key in general. (4) The manifest's `client_hash` cannot be checked by the voter in the browser: a ballot box that serves other code defeats the page. (5) Rows in the ballot box's database keep their arrival order. (6) The time that the email form takes still differs slightly between eligible and other addresses, by one database query.
- **Open points from M4.** The log service computes proofs from all leaf hashes and does not store inner Merkle nodes. The export is built in memory per request. The ballots of a close and the entries of a tally go to the log in one request, which bounds an election to roughly 100000 ballots. The browser client downloads and verifies the whole export on every action. Anyone can open registration sessions without limit; only old ones are purged. There is no periodic tree head, no SMTP authentication, and no redirect back to a web client after the login.
- **Open points from M3.** Re-voting is not implemented. The verifier does not reject two ballots with the same ciphertext, because the binding to the credential makes a copy undecryptable. The reasons that the tally gives for invalid ballots are English text of the Go implementation and part of the result entry, so an independent verifier must reproduce them; fixed reason codes would be better. The blinding state of the circl library cannot be serialised, which the web client needs if issuance uses a full-page redirect (M5). The roll is one log entry, which limits it to about 16 million references in the current decoder settings and makes large rolls a large entry.
