package api

import "github.com/ansiwen/stimmig/canon"

// Log service.

// LogKey is the response of POST /v1/keys of the log service.
type LogKey struct {
	LogKey []byte `cbor:"log_key"`
}

// Append is the body of POST /v1/elections/{id}/entries. Each entry is an
// encoded log entry. If ExpectSize is present, the log must have exactly
// that many entries before.
type Append struct {
	Entries    []canon.Raw `cbor:"entries"`
	ExpectSize *uint64     `cbor:"expect_size,omitempty"`
}

// Proof is the response of the inclusion and consistency proof endpoints.
// Index is used by inclusion proofs only.
type Proof struct {
	Index  uint64   `cbor:"index"`
	Hashes [][]byte `cbor:"hashes"`
}
