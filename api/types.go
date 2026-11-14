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

// Created is the response of POST /v1/elections of the registrar and the
// ballot box.
type Created struct {
	ElectionID []byte `cbor:"election_id"`
}

// Registrar.

// RegistrarKeys is the response of POST /v1/keys of the registrar.
type RegistrarKeys struct {
	IssuingKey  []byte `cbor:"issuing_key"`
	ElectionKey []byte `cbor:"election_key"`
}

// Voter is one eligible voter: an identity provider and the subject ID
// that the provider reports for the voter.
type Voter struct {
	Provider string `cbor:"provider"`
	Subject  string `cbor:"subject"`
}

// Roll is the body of PUT /v1/elections/{id}/roll.
type Roll struct {
	Voters []Voter `cbor:"voters"`
}

// SessionRequest is the body of POST /v1/elections/{id}/sessions: the
// blinded credential and, optionally, the identity provider to use.
type SessionRequest struct {
	Blinded  []byte `cbor:"blinded"`
	Provider string `cbor:"provider,omitempty"`
}

// Session is the response to a SessionRequest. The voter logs in at URL
// and then types Code at the registrar; afterwards the client fetches the
// credential with the session.
type Session struct {
	Session string `cbor:"session"`
	URL     string `cbor:"url"`
	Code    string `cbor:"code"`
}

// Credential is the response of GET /v1/sessions/{session} once the voter
// has logged in.
type Credential struct {
	BlindSignature []byte `cbor:"blind_signature"`
	RollReference  []byte `cbor:"roll_reference"`
}

// Ballot box.

// BallotBoxKey is the response of POST /v1/keys of the ballot box.
type BallotBoxKey struct {
	ReceiptKey []byte `cbor:"receipt_key"`
}

// Receipt is the response to a cast ballot. It is empty in receipt mode
// none.
type Receipt struct {
	Receipt []byte `cbor:"receipt,omitempty"`
}

// Status is the response of GET /v1/elections/{id} of the ballot box: the
// public statistics during voting.
type Status struct {
	Phase string `cbor:"phase"`
	Cast  uint64 `cbor:"cast"`
}

// ClientBundle is the response of GET /v1/client of the ballot box.
type ClientBundle struct {
	Hash []byte `cbor:"hash"`
}
