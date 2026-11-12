package publog

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/merkle"
)

// treeHeadContext separates tree head signatures from all other signatures
// made with the same key.
const treeHeadContext = "stimmig-tree-head-v1"

// TreeHead is a signed tree head: the log's commitment to its first Size
// entries.
type TreeHead struct {
	ElectionID []byte `cbor:"election_id"`
	Size       uint64 `cbor:"size"`
	Root       []byte `cbor:"root"`
	// Timestamp is in seconds since the Unix epoch.
	Timestamp uint64 `cbor:"timestamp"`
	// Signature covers the canonical encoding of the array
	// ["stimmig-tree-head-v1", election_id, size, root, timestamp].
	Signature []byte `cbor:"signature"`
}

func (h TreeHead) signedBytes() ([]byte, error) {
	if len(h.ElectionID) != merkle.HashSize || len(h.Root) != merkle.HashSize {
		return nil, errors.New("publog: tree head hash has the wrong size")
	}
	return canon.Marshal([]any{treeHeadContext, h.ElectionID, h.Size, h.Root, h.Timestamp})
}

// SignTreeHead creates a signed tree head. The signer must hold an Ed25519
// key; it can be backed by an HSM.
func SignTreeHead(signer crypto.Signer, electionID merkle.Hash, size uint64, root merkle.Hash, timestamp uint64) (TreeHead, error) {
	h := TreeHead{ElectionID: electionID[:], Size: size, Root: root[:], Timestamp: timestamp}
	msg, err := h.signedBytes()
	if err != nil {
		return TreeHead{}, err
	}
	if _, ok := signer.Public().(ed25519.PublicKey); !ok {
		return TreeHead{}, errors.New("publog: log signer is not an Ed25519 key")
	}
	if h.Signature, err = signer.Sign(rand.Reader, msg, crypto.Hash(0)); err != nil {
		return TreeHead{}, err
	}
	return h, nil
}

// Verify checks the signature of the tree head against the log key.
func (h TreeHead) Verify(logKey []byte) error {
	if len(logKey) != ed25519.PublicKeySize {
		return errors.New("publog: log key has the wrong size")
	}
	msg, err := h.signedBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(logKey), msg, h.Signature) {
		return errors.New("publog: tree head signature is invalid")
	}
	return nil
}
