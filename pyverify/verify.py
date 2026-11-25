#!/usr/bin/env python3
"""Independent verifier for Stimmig election log exports, written from SPEC.md alone."""
import sys


class Invalid(Exception):
    pass


def need(cond, msg):
    if not cond:
        raise Invalid(msg)


# ---------------------------------------------------------------- CBOR (SPEC 7)

def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError("integer too large")


def enc(v):
    """Deterministic CBOR (RFC 8949 4.2.1) for the allowed subset."""
    if v is None:
        return b"\xf6"
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return _head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode()
        return _head(3, len(b)) + b
    if isinstance(v, (list, tuple)):
        return _head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        items = sorted((enc(k), enc(x)) for k, x in v.items())
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(type(v))


class Decoder:
    def __init__(self, data):
        self.d = data
        self.i = 0

    def _take(self, n):
        need(self.i + n <= len(self.d), "CBOR: truncated")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def _arg(self, ai):
        if ai < 24:
            return ai
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        need(ai in sizes, "CBOR: indefinite length or reserved additional info")
        n = int.from_bytes(self._take(sizes[ai]), "big")
        need(n >= (24 if ai == 24 else 1 << (4 * sizes[ai])), "CBOR: non-shortest integer or length")
        return n

    def item(self, depth=0):
        need(depth < 64, "CBOR: nesting too deep")
        ib = self._take(1)[0]
        major, ai = ib >> 5, ib & 31
        if major == 7:
            need(ai in (20, 21, 22), "CBOR: float, undefined or simple value not allowed")
            return {20: False, 21: True, 22: None}[ai]
        need(major != 6, "CBOR: tags not allowed")
        n = self._arg(ai)
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major == 2:
            return bytes(self._take(n))
        if major == 3:
            try:
                return self._take(n).decode("utf-8")
            except UnicodeDecodeError:
                raise Invalid("CBOR: invalid UTF-8")
        if major == 4:
            return [self.item(depth + 1) for _ in range(n)]
        # major 5: map with text keys, sorted bytewise by encoding, no duplicates
        out, prev = {}, None
        for _ in range(n):
            start = self.i
            k = self.item(depth + 1)
            kb = self.d[start:self.i]
            need(isinstance(k, str), "CBOR: map key is not text")
            need(prev is None or kb > prev, "CBOR: map keys not sorted or duplicated")
            prev = kb
            out[k] = self.item(depth + 1)
        return out


def decode_seq(data):
    """Yield (item, raw_bytes) for an RFC 8742 sequence, rejecting non-canonical items."""
    dec = Decoder(data)
    while dec.i < len(data):
        start = dec.i
        v = dec.item()
        raw = bytes(data[start:dec.i])
        need(enc(v) == raw, "CBOR: item is not in canonical encoding")
        yield v, raw


# ---------------------------------------------------------------- hashes, Merkle (SPEC 7, RFC 6962)

import hashlib
import hmac

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def sha256(b):
    return hashlib.sha256(b).digest()


def leaf_hash(entry_bytes):
    return sha256(b"\x00" + entry_bytes)


def merkle_root(leaves):
    if not leaves:
        return sha256(b"")
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return sha256(b"\x01" + merkle_root(leaves[:k]) + merkle_root(leaves[k:]))


# ---------------------------------------------------------------- Ed25519 key checks (SPEC 5.6, 7)

_P = 2**255 - 19
_D = -121665 * pow(121666, -1, _P) % _P


def _ed_add(a, b):
    (x1, y1), (x2, y2) = a, b
    t = _D * x1 * x2 * y1 * y2 % _P
    return ((x1 * y2 + x2 * y1) * pow(1 + t, -1, _P) % _P,
            (y1 * y2 + x1 * x2) * pow(1 - t, -1, _P) % _P)


def check_ed25519_key(b, what):
    """Canonical point encoding, not of small order (8*A != identity)."""
    need(isinstance(b, bytes) and len(b) == 32, f"{what}: not 32 bytes")
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    sign = b[31] >> 7
    need(y < _P, f"{what}: non-canonical y")
    x2 = (y * y - 1) * pow(_D * y * y + 1, -1, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if x * x % _P != x2:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    need(x * x % _P == x2, f"{what}: not a curve point")
    need(not (x == 0 and sign), f"{what}: non-canonical sign of x = 0")
    if x & 1 != sign:
        x = _P - x
    pt = (x, y)
    for _ in range(3):
        pt = _ed_add(pt, pt)
    need(pt != (0, 1), f"{what}: small-order point")
    return Ed25519PublicKey.from_public_bytes(b)


def ed25519_ok(key, sig, msg):
    if not isinstance(sig, bytes) or len(sig) != 64:
        return False
    try:
        key.verify(sig, msg)
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------- manifest (SPEC 5.6, 6, 7, 8)

ALGS = {
    "log_hash": "sha256-rfc6962-v1",
    "tree_head_signature": "ed25519-v1",
    "credential": "rsabssa-sha384-pss-deterministic-v1",
    "ballot_signature": "ed25519-v1",
    "ballot_encryption": "hpke-p256-hkdf-sha256-aes256gcm-v1",
}
METHODS = ("schulze", "ranked-pairs", "minimax", "copeland", "irv", "borda", "stv")
RULES = ("first-ranks", "head-to-head", "borda", "fixed-order", "declare-tie")
SMALL_PRIMES = [p for p in range(2, 100) if all(p % q for q in range(2, p))]


def keys_ok(m, required, optional, what):
    need(isinstance(m, dict), f"{what}: not a map")
    extra = set(m) - set(required) - set(optional)
    need(not extra, f"{what}: unknown fields {sorted(extra)}")
    missing = set(required) - set(m)
    need(not missing, f"{what}: missing fields {sorted(missing)}")


def is_text_list(v):
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def check_issuing_key(der, proof):
    need(isinstance(der, bytes), "issuing_key: not bytes")
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, UnsupportedAlgorithm):
        raise Invalid("issuing_key: not a DER SubjectPublicKeyInfo")
    need(isinstance(key, rsa.RSAPublicKey), "issuing_key: not RSA")
    need(key.public_bytes(serialization.Encoding.DER,
                          serialization.PublicFormat.SubjectPublicKeyInfo) == der,
         "issuing_key: not in canonical DER form")
    nums = key.public_numbers()
    N = nums.n
    need(3072 <= N.bit_length() <= 8192, "issuing_key: size outside 3072..8192 bits")
    need(nums.e == 65537, "issuing_key: exponent is not 65537")
    need(all(N % p for p in SMALL_PRIMES), "issuing_key: modulus has a prime factor below 100")
    k = (N.bit_length() + 7) // 8
    need(isinstance(proof, list) and len(proof) == 8, "issuing_key_proof: not eight values")
    nbytes = N.to_bytes(k, "big")
    for i, v in enumerate(proof):
        need(isinstance(v, bytes) and len(v) == k, f"issuing_key_proof[{i}]: wrong length")
        out, ctr = b"", 0
        while len(out) < k + 16:
            out += sha256(b"stimmig-issuing-key-proof-v1" + bytes([i]) + ctr.to_bytes(2, "big") + nbytes)
            ctr += 1
        y = int.from_bytes(out[:k + 16], "big") % N
        x = int.from_bytes(v, "big")
        need(1 <= x <= N - 1, f"issuing_key_proof[{i}]: out of range")
        need(pow(x, 65537, N) == y, f"issuing_key_proof[{i}]: wrong root")
    return key


def check_tally_config(t):
    keys_ok(t, ["candidates", "method"],
            ["seats", "max_ranks", "no_equal_ranks", "allow_empty", "tie_break", "fixed_order"], "tally")
    c = t["candidates"]
    need(is_text_list(c) and 1 <= len(c) <= 500, "tally.candidates: not 1..500 texts")
    need(len(set(c)) == len(c), "tally.candidates: duplicate IDs")
    need(all(c), "tally.candidates: empty ID")
    need(t["method"] in METHODS, "tally.method: unknown")
    # "absent for <default>": a present default value would be a second encoding, so it is refused
    if "seats" in t:
        s = t["seats"]
        need(isinstance(s, int) and not isinstance(s, bool) and 2 <= s <= len(c), "tally.seats: invalid")
        need(t["method"] in ("schulze", "stv"), "tally.seats: method fills one seat only")
    if "max_ranks" in t:
        r = t["max_ranks"]
        need(isinstance(r, int) and not isinstance(r, bool) and 1 <= r < len(c), "tally.max_ranks: invalid")
    for b in ("no_equal_ranks", "allow_empty"):
        if b in t:
            need(t[b] is True, f"tally.{b}: must be true when present")
    if "tie_break" in t:
        tb = t["tie_break"]
        need(is_text_list(tb) and tb and all(r in RULES for r in tb), "tally.tie_break: invalid")
        need(tb[-1] in ("fixed-order", "declare-tie"), "tally.tie_break: must end with fixed-order or declare-tie")
        need(all(r not in ("fixed-order", "declare-tie") for r in tb[:-1]), "tally.tie_break: fixed-order or declare-tie before the end")
        need(len(set(tb)) == len(tb), "tally.tie_break: a rule named twice")
        need(tb != ["first-ranks", "declare-tie"], "tally.tie_break: default must be absent")
    if "fixed_order" in t:
        need(is_text_list(t["fixed_order"]) and sorted(t["fixed_order"]) == sorted(c),
             "tally.fixed_order: not a permutation of the candidates")
    need(("fixed_order" in t) == ("fixed-order" in t.get("tie_break", [])),
         "tally.fixed_order: present iff the chain uses fixed-order")


def check_manifest(m):
    mode = m.get("receipt_mode") if isinstance(m, dict) else None
    need(mode in ("full", "none"), "manifest.receipt_mode: invalid")
    req = ["version", "title", "nonce", "tally", "algorithms", "receipt_mode", "log_key",
           "issuing_key", "issuing_key_proof", "election_key"] + (["receipt_key"] if mode == "full" else [])
    keys_ok(m, req, ["schedule", "client_hash"], "manifest")
    need(m["version"] == 1 and not isinstance(m["version"], bool), "manifest.version: not 1")
    need(isinstance(m["title"], str), "manifest.title: not text")
    need(isinstance(m["nonce"], bytes) and len(m["nonce"]) >= 16, "manifest.nonce: shorter than 16 bytes")
    check_tally_config(m["tally"])
    algs = dict(ALGS, **({"receipt_signature": "ed25519-v1"} if mode == "full" else {}))
    need(m["algorithms"] == algs, "manifest.algorithms: unknown or missing identifiers")
    log_key = check_ed25519_key(m["log_key"], "log_key")
    if mode == "full":
        check_ed25519_key(m["receipt_key"], "receipt_key")
        need(m["receipt_key"] != m["log_key"], "receipt_key equals log_key")
    issuing = check_issuing_key(m["issuing_key"], m["issuing_key_proof"])
    ek = m["election_key"]
    need(isinstance(ek, bytes) and len(ek) == 65 and ek[0] == 4, "election_key: not an uncompressed point")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ek)
    except ValueError:
        raise Invalid("election_key: not a P-256 point")
    if "schedule" in m:
        s = m["schedule"]
        keys_ok(s, [], ["registration_close", "voting_open", "voting_close"], "schedule")
        times = [s[k] for k in ("registration_close", "voting_open", "voting_close") if k in s]
        need(all(isinstance(x, int) and not isinstance(x, bool) for x in times), "schedule: not integers")
        need(all(a < b for a, b in zip(times, times[1:])), "schedule: times not strictly ordered")
    if "client_hash" in m:
        need(isinstance(m["client_hash"], bytes) and len(m["client_hash"]) == 32, "client_hash: not 32 bytes")
    return log_key, issuing


def padded_size(candidates):
    # SPEC 5.6 "twice the length in bytes of its ID plus 5": the golden export fits 2*(len+5) only
    return 16 + sum(2 * (len(c.encode()) + 5) for c in candidates)


# ---------------------------------------------------------------- HPKE base mode (RFC 9180)

KEM_ID, KDF_ID, AEAD_ID = 0x0010, 0x0001, 0x0002


def _extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def _lextract(suite, salt, label, ikm):
    return _extract(salt, b"HPKE-v1" + suite + label + ikm)


def _lexpand(suite, prk, label, info, n):
    return _expand(prk, n.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info, n)


def hpke_open(sk, pk_r, ct, info):
    """Single-shot base-mode open; raises ValueError / InvalidTag on failure."""
    enc_, body = ct[:65], ct[65:]
    pk_e = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), enc_)
    dh = sk.exchange(ec.ECDH(), pk_e)
    kem_suite = b"KEM" + KEM_ID.to_bytes(2, "big")
    eae_prk = _lextract(kem_suite, b"", b"eae_prk", dh)
    shared = _lexpand(kem_suite, eae_prk, b"shared_secret", enc_ + pk_r, 32)
    suite = b"HPKE" + KEM_ID.to_bytes(2, "big") + KDF_ID.to_bytes(2, "big") + AEAD_ID.to_bytes(2, "big")
    ctx = b"\x00" + _lextract(suite, b"", b"psk_id_hash", b"") + _lextract(suite, b"", b"info_hash", info)
    secret = _lextract(suite, shared, b"secret", b"")
    key = _lexpand(suite, secret, b"key", ctx, 32)
    nonce = _lexpand(suite, secret, b"base_nonce", ctx, 12)
    return AESGCM(key).decrypt(nonce, body, b"")


def decode_plain(pt, P):
    """SPEC 5.6 padding and ranking format -> ranking or the text 'malformed'."""
    if len(pt) != 4 + P:
        return "malformed"
    n = int.from_bytes(pt[:4], "big")
    if n > P or any(pt[4 + n:]):
        return "malformed"
    body = pt[4:4 + n]
    try:
        items = list(decode_seq(body))
    except Invalid:
        return "malformed"
    if len(items) != 1:
        return "malformed"
    r = items[0][0]
    if not (isinstance(r, list) and all(is_text_list(g) for g in r)):
        return "malformed"
    return r


# ---------------------------------------------------------------- tally (SPEC 7, 8)

class Unsupported(Exception):
    pass


def ballot_error(r, t):
    """First broken ballot rule (SPEC 7 'Invalid reasons'), or None. Check order is a guess."""
    cands = t["candidates"]
    if not r:
        return None if t.get("allow_empty") else "empty ballot"
    m = t.get("max_ranks", len(cands))
    if len(r) > m:
        return f"{len(r)} ranks, maximum is {m}"
    seen = set()
    for k, g in enumerate(r, 1):
        if not g:
            return f"rank {k} is empty"
        if t.get("no_equal_ranks") and len(g) > 1:
            return f"rank {k} holds {len(g)} candidates, equal ranks are disabled"
        for c in g:
            if c not in cands:
                return f'unknown candidate "{c}"'
            if c in seen:
                return f'candidate "{c}" ranked twice'
            seen.add(c)
    return None


def positions(r, cands):
    """Rank group index per candidate; unranked = len(r)."""
    pos = {c: len(r) for c in cands}
    for k, g in enumerate(r):
        for c in g:
            pos[c] = k
    return pos


def tie_break_chain(group, ballots, t, d, events, trace, context):
    """Order a tied group with the manifest's chain. Returns a list of groups."""
    cands = t["candidates"]
    idx = {c: i for i, c in enumerate(cands)}
    chain = t.get("tie_break", ["first-ranks", "declare-tie"])
    order = [list(group)]
    for rule in chain:
        new = []
        for g in order:
            if len(g) == 1:
                new.append(g)
                continue
            if rule == "first-ranks":
                m = t.get("max_ranks", len(cands))
                key = {c: tuple(-sum(1 for b in ballots if len(b) > k and c in b[k]) for k in range(m)) for c in g}
                res = _group_by(g, key)
            elif rule == "borda":
                key = {c: -_borda2(c, ballots, cands) for c in g}
                res = _group_by(g, key)
            elif rule == "fixed-order":
                fo = t["fixed_order"]
                res = [[c] for c in sorted(g, key=fo.index)]
            elif rule == "head-to-head":
                res = _head_to_head(g, d, idx)
            else:
                res = [g]
            trace.append({"op": "tie-break", "note": f"{context}: {rule}", "candidates": g})
            events.append({"context": context, "rule": rule, "tied": g, "order": res})
            new.extend(res)
        order = new
        if all(len(g) == 1 for g in order):
            break
    return order


def _group_by(g, key):
    out = []
    for c in sorted(g, key=lambda c: key[c]):  # stable: manifest order within equal keys
        if out and key[out[-1][0]] == key[c]:
            out[-1].append(c)
        else:
            out.append([c])
    return out


def _borda2(c, ballots, cands):
    s = 0
    for b in ballots:
        pos = positions(b, cands)
        s += sum(2 if pos[c] < pos[o] else 1 if pos[c] == pos[o] else 0 for o in cands if o != c)
    return s


def _head_to_head(g, d, idx):
    top, bottom, rest = [], [], list(g)
    while len(rest) > 1:
        win = [c for c in rest if all(d[idx[c]][idx[o]] > d[idx[o]][idx[c]] for o in rest if o != c)]
        lose = [c for c in rest if all(d[idx[c]][idx[o]] < d[idx[o]][idx[c]] for o in rest if o != c)]
        if not win and not lose:
            break
        for c in win:
            top.append([c]); rest.remove(c)
        for c in lose:
            bottom.insert(0, [c]); rest.remove(c)
    return top + ([rest] if rest else []) + bottom


def tally(t, plains):
    """plains: list of (ballot log index, ranking). Returns the result body."""
    if t["method"] != "schulze":
        raise Unsupported(f"tally method {t['method']} is not implemented")
    cands = t["candidates"]
    n = len(cands)
    seats = t.get("seats", 1)
    invalid, valid = [], []
    for idx, r in plains:
        e = ballot_error(r, t)
        if e:
            invalid.append({"index": idx, "reason": e})
        else:
            valid.append(r)
    abstentions = sum(1 for r in valid if not r)
    d = [[0] * n for _ in range(n)]
    for r in valid:
        pos = positions(r, cands)
        for i in range(n):
            for j in range(n):
                if pos[cands[i]] < pos[cands[j]]:
                    d[i][j] += 1
    p = [[d[i][j] if d[i][j] > d[j][i] else 0 for j in range(n)] for i in range(n)]
    for i in range(n):
        for j in range(n):
            if i != j:
                for k in range(n):
                    if k != i and k != j:
                        p[j][k] = max(p[j][k], min(p[j][i], p[i][k]))
    trace = [{"op": "pairwise", "matrix": d}, {"op": "strongest-paths", "matrix": p}]
    events, ranking, rest = [], [], list(range(n))
    while rest:
        top = [i for i in rest if not any(p[j][i] > p[i][j] for j in rest)]
        need(top, "tally: Schulze relation has no maximal element")
        rest = [i for i in rest if i not in top]
        grp = [cands[i] for i in top]
        ranking.extend(tie_break_chain(grp, valid, t, d, events, trace, "ranking") if len(grp) > 1 else [grp])
    winners, tie = [], None
    for g in ranking:
        if len(winners) + len(g) <= seats:
            winners += g
        else:
            if len(winners) < seats:
                tie = {"context": "ranking", "candidates": g}
            break
    res = {"method": "schulze", "seats": seats, "candidates": cands, "ballots": len(plains),
           "valid": len(valid), "abstentions": abstentions, "winners": winners, "ranking": ranking,
           "pairwise": d, "trace": trace}
    if invalid:
        res["invalid"] = invalid
    if tie:
        res["tie"] = tie
    if events:
        res["tie_breaks"] = events
    return res


# ---------------------------------------------------------------- export walk (SPEC 7, 12)

ORDER = ["manifest", "roll_commit", "issuance", "registration_close", "ballot",
         "voting_close", "election_key", "ballot_plain", "result"]
REPEATS = {"issuance", "ballot", "ballot_plain"}
BODY_FIELDS = {
    "roll_commit": ["references"], "issuance": ["roll_reference", "sequence"],
    "registration_close": ["issued"],
    "ballot": ["credential_key", "credential_signature", "ciphertext", "signature"],
    "voting_close": ["cast"], "election_key": ["private_key"],
}


def is_uint(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


class Verifier:
    def __init__(self):
        self.leaves, self.types = [], []
        self.eid = None
        self.last_ts = None
        self.notes = []

    def entry(self, e, raw):
        need(isinstance(e, list) and len(e) == 2 and isinstance(e[0], str) and isinstance(e[1], dict),
             "entry: not [type, body]")
        typ, body = e
        need(typ in ORDER, f"entry: unknown type {typ!r}")
        i = len(self.leaves)
        # lifecycle order: each type is the same repeatable type or a later one, no skips
        prev = self.types[-1] if self.types else None
        if prev is None:
            need(typ == "manifest", "entry 0 is not the manifest")
        else:
            pi, ti = ORDER.index(prev), ORDER.index(typ)
            ok = (ti == pi and typ in REPEATS) or ti == pi + 1 or \
                 (ti == pi + 2 and ORDER[pi + 1] in REPEATS)  # zero entries of a repeatable type
            need(ok, f"entry {i}: {typ} cannot follow {prev}")
        lh = leaf_hash(raw)
        self.leaves.append(lh)
        self.types.append(typ)
        if typ in BODY_FIELDS:
            keys_ok(body, BODY_FIELDS[typ], [], f"entry {i} ({typ})")
        getattr(self, "e_" + typ)(i, body, lh)

    def e_manifest(self, i, m, lh):
        self.m = m
        self.log_key, self.issuing = check_manifest(m)
        self.eid = lh
        self.cands = m["tally"]["candidates"]
        self.ct_len = 65 + 4 + padded_size(self.cands) + 16

    def e_roll_commit(self, i, b, lh):
        refs = b["references"]
        need(isinstance(refs, list) and all(isinstance(r, bytes) and len(r) == 32 for r in refs),
             "roll_commit: references are not 32-byte strings")
        need(all(a < c for a, c in zip(refs, refs[1:])), "roll_commit: references not strictly ascending")
        self.roll = set(refs)
        self.issued_refs = set()

    def e_issuance(self, i, b, lh):
        r, s = b["roll_reference"], b["sequence"]
        need(isinstance(r, bytes), f"issuance {i}: roll reference is not bytes")
        need(r in self.roll, f"issuance {i}: roll reference not on the roll")
        need(r not in self.issued_refs, f"issuance {i}: roll reference issued twice")
        need(is_uint(s) and s == len(self.issued_refs), f"issuance {i}: sequence {s} is not consecutive")
        self.issued_refs.add(r)

    def e_registration_close(self, i, b, lh):
        need(is_uint(b["issued"]) and b["issued"] == len(self.issued_refs),
             "registration_close: issued count differs from the issuances")
        self.ballots, self.creds, self.ballot_body = [], set(), {}

    def e_ballot(self, i, b, lh):
        ck, cs, ct, sig = b["credential_key"], b["credential_signature"], b["ciphertext"], b["signature"]
        key = check_ed25519_key(ck, f"ballot {i} credential_key")
        need(ck not in self.creds, f"ballot {i}: credential used twice")
        need(isinstance(ct, bytes) and len(ct) == self.ct_len,
             f"ballot {i}: ciphertext is not {self.ct_len} bytes")
        msg = enc(["stimmig-credential-v1", self.eid, ck])
        need(isinstance(cs, bytes) and len(cs) == self.issuing.key_size // 8 + (self.issuing.key_size % 8 > 0),
             f"ballot {i}: credential signature has the wrong length")
        try:
            self.issuing.verify(cs, msg, padding.PSS(padding.MGF1(hashes.SHA384()), 48), hashes.SHA384())
        except InvalidSignature:
            raise Invalid(f"ballot {i}: invalid registrar signature")
        need(ed25519_ok(key, sig, enc(["stimmig-ballot-v1", self.eid, ct])), f"ballot {i}: invalid ballot signature")
        if self.ballots:
            need(self.leaves[self.ballots[-1]] < lh, f"ballot {i}: not in leaf-hash order")
        need(len(self.ballots) < len(self.issued_refs), f"ballot {i}: more ballots than credentials issued")
        self.creds.add(ck)
        self.ballots.append(i)
        self.ballot_body[i] = b

    def e_voting_close(self, i, b, lh):
        need(is_uint(b["cast"]) and b["cast"] == len(self.ballots), "voting_close: cast count differs from the ballots")

    def e_election_key(self, i, b, lh):
        sk = b["private_key"]
        need(isinstance(sk, bytes) and len(sk) == 32, "election_key: not 32 bytes")
        try:
            self.sk = ec.derive_private_key(int.from_bytes(sk, "big"), ec.SECP256R1())
        except ValueError:
            raise Invalid("election_key: scalar out of range")
        pub = self.sk.public_key().public_bytes(serialization.Encoding.X962,
                                                serialization.PublicFormat.UncompressedPoint)
        need(pub == self.m["election_key"], "election_key: does not match the manifest's election key")
        self.plains = []

    def e_ballot_plain(self, i, b, lh):
        k = len(self.plains)
        need(k < len(self.ballots), f"ballot_plain {i}: more plaintexts than ballots")
        bi = self.ballots[k]
        bb = self.ballot_body[bi]
        info = enc(["stimmig-ballot-encryption-v1", self.eid, bb["credential_key"]])
        try:
            pt = hpke_open(self.sk, self.m["election_key"], bb["ciphertext"], info)
            r = decode_plain(pt, padded_size(self.cands))
        except (ValueError, InvalidTag):
            r = "decryption-failed"
        mine = {"ballot": bi, **({"invalid": r} if isinstance(r, str) else {"ranking": r})}
        need(enc(["ballot_plain", b]) == enc(["ballot_plain", mine]),
             f"ballot_plain {i}: differs from the recomputed decryption of ballot {bi}")
        self.plains.append((bi, r))

    def e_result(self, i, b, lh):
        need(len(self.plains) == len(self.ballots), "result: not every ballot has a ballot_plain entry")
        mine = tally(self.m["tally"], [p for p in self.plains if not isinstance(p[1], str)])
        for k in ("winners", "ranking", "pairwise"):
            need(b.get(k) == mine[k], f"result: {k} differs (logged {b.get(k)!r}, computed {mine[k]!r})")
        need(b.get("tie") == mine.get("tie"), f"result: tie differs (logged {b.get('tie')!r}, computed {mine.get('tie')!r})")
        need(enc(b) == enc(mine), "result: differs from the recomputed result in other fields (trace, counts)")
        self.notes.append("result matches the recomputed tally byte for byte")

    def tree_head(self, h):
        keys_ok(h, ["election_id", "size", "root", "timestamp", "signature"], [], "tree head")
        need(self.eid is not None, "tree head before the manifest")
        need(h["election_id"] == self.eid, "tree head: wrong election ID")
        need(is_uint(h["size"]) and h["size"] == len(self.leaves),
             "tree head: size is not the number of entries before it")
        need(h["root"] == merkle_root(self.leaves), f"tree head at size {h['size']}: wrong root")
        need(is_uint(h["timestamp"]), "tree head: bad timestamp")
        need(self.last_ts is None or h["timestamp"] >= self.last_ts, "tree head: timestamp decreases")
        self.last_ts = h["timestamp"]
        msg = enc(["stimmig-tree-head-v1", self.eid, h["size"], h["root"], h["timestamp"]])
        need(ed25519_ok(self.log_key, h["signature"], msg), f"tree head at size {h['size']}: invalid signature")


def verify(data):
    v = Verifier()
    items = decode_seq(data)
    first = next(items, None)
    need(first is not None and first[0] == {"format": "stimmig-log-export-v1"}, "export: missing or wrong header")
    last = None
    heads = 0
    for rec, raw in items:
        need(isinstance(rec, list) and len(rec) == 2 and rec[0] in ("entry", "tree_head"), "export: bad record")
        if rec[0] == "entry":
            # the record is canonical, so the entry's own bytes are the canonical encoding
            v.entry(rec[1], enc(rec[1]))
        else:
            v.tree_head(rec[1])
            heads += 1
        last = rec[0]
    need(last == "tree_head", "export: the last record is not a tree head")
    return v, heads


def main(argv):
    if len(argv) != 2:
        print("usage: verify.py EXPORT_FILE", file=sys.stderr)
        return 2
    data = open(argv[1], "rb").read()
    try:
        v, heads = verify(data)
    except Invalid as e:
        print(f"INVALID: {e}")
        return 1
    except Unsupported as e:
        print(f"NOT VERIFIED: {e}")
        return 2
    print(f"OK: {len(v.leaves)} entries, {heads} tree heads, last phase {v.types[-1]}")
    for n in v.notes:
        print("  " + n)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
