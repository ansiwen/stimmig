# pyverify: independent Stimmig log verifier

`verify.py` checks a Stimmig log export (SPEC.md sections 5 to 8 and 12). It was written from SPEC.md alone, without reading the Go code. It is one file and needs Python 3.11+ and `cryptography`.

```
pip install cryptography
python3 pyverify/verify.py election/testdata/election-v1.cbor
```

The exit code is 0 for a valid log, 1 for an invalid one, and 2 for a usage error or a log it cannot verify (a tally method other than Schulze).

## What it checks

- **Export and encoding.** It checks the RFC 8742 sequence, the header and the record shapes. The CBOR is strict deterministic CBOR: shortest heads, sorted unique text keys, and no floats, tags or indefinite lengths. Every item must re-encode to its own bytes. The last record must be a tree head.
- **Merkle tree and tree heads.** Leaf hashes are SHA-256 over `0x00` plus the entry, and the root follows RFC 6962. Every tree head is checked for:
  - the election ID;
  - size equal to the number of entries before it;
  - the recomputed root;
  - timestamps that never decrease;
  - its Ed25519 signature under the manifest's `log_key`.
- **Manifest.** It checks the exact field set and algorithm identifiers, and nonce >= 16 bytes. The tally map is checked for its keys, the limits (at most 500 candidates) and the tie-break chain rules. Default values must be absent. The keys are checked as follows:
  - `log_key` and `receipt_key`: canonical, not of small order, and different from each other.
  - `issuing_key`: canonical DER, RSA with 3072 to 8192 bits, e = 65537, no prime factor below 100, and all eight `issuing_key_proof` values.
  - `election_key`: a valid uncompressed P-256 point.
  - Optional `schedule`: in strict order. Optional `client_hash`: 32 bytes.
- **Lifecycle, roll and counts.**
  - Entries come in lifecycle order (a phase with zero entries may be skipped).
  - The roll holds 32-byte references in strictly ascending order.
  - Issuances use distinct references from the roll, with consecutive sequence numbers.
  - The `issued` and `cast` counts are checked, so cast <= issued <= eligible.
- **Ballots.** For every ballot:
  - the credential key is canonical and not of small order;
  - the registrar signature is RSASSA-PSS-SHA384 with MGF1-SHA384 and salt length 48 over the credential message (RFC 9474 PSS-Deterministic);
  - the Ed25519 ballot signature is valid;
  - its credential is not used by another ballot;
  - ballots are in strict leaf-hash order;
  - the ciphertext is 65 + 4 + P + 16 bytes long.
- **Decryption.** The published scalar must give the manifest's election key. Every ballot is decrypted with HPKE base mode (DHKEM P-256, HKDF-SHA256, AES-256-GCM), which is implemented here on top of the `cryptography` primitives. The padding and the ranking format are checked: a non-canonical inner encoding, trailing bytes, non-text items or non-zero padding give `malformed`. Every `ballot_plain` entry must equal, byte for byte, the encoding of the recomputed result.
- **Tally (Schulze only).** It recomputes the ballot rules and invalid reasons, the pairwise matrix and the strongest paths. It then builds the ranking and applies the whole tie-break chain (first-ranks, head-to-head, borda, fixed-order, declare-tie). Winners and tie are compared first, then the whole result entry byte for byte, trace and tie-break events included.

## What it does not check

- The tally methods ranked-pairs, minimax, copeland, irv, borda and stv: such a log gets `NOT VERIFIED`, exit 2.
- Receipts and inclusion or consistency proofs served by the log, which are not part of the export.
- `client_hash` against a bundle, roll references against identities, and entry times against the schedule (the spec says the verifier does not check the times).
- Exact agreement with Go's `crypto/ed25519` on edge cases. Signatures are verified with OpenSSL, which also checks without the cofactor and rejects S >= L.
- Resource limits beyond a CBOR nesting depth of 64. The whole file is read into memory.
- A head-to-head tie-break that splits a group was never produced in the cross-check, so it is implemented but not confirmed against Go.

## Rules settled after it was written

The first version found eight manifest rules that the specification left
open, on which this verifier and the Go verifier disagreed. They are now
settled in SPEC.md section 7, and both verifiers follow them: a value equal
to its default is absent, `fixed_order` comes only with the `fixed-order`
rule, the receipt key differs from the log key, candidate IDs are not empty,
and `fixed-order` or `declare-tie` end the tie-break chain, with no rule
named twice.

## Where the result format comes from

The format of `tie_breaks` events (`context`, `rule`, `tied`, `order`) and a few result conventions were not in SPEC.md when this was written, and were inferred from the golden export; SPEC.md section 7 now describes them.

They were then confirmed by making synthetic elections with fresh keys and checking that the Go verifier accepts the results this tally computes. That covered 60 random Schulze elections plus targeted cases (ties across the last seat, ballot rule violations, malformed plaintexts). The scripts for this are not part of this directory.
