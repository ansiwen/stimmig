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
