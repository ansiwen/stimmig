// Package merkle implements the Merkle tree of the public log: tree hashes,
// inclusion proofs and consistency proofs as defined in RFC 6962 and
// RFC 9162, with SHA-256.
package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/bits"
)

// HashSize is the size of a tree hash in bytes.
const HashSize = sha256.Size

// Hash is a leaf hash, a node hash or a root hash.
type Hash [HashSize]byte

// LeafHash is SHA-256 over the domain-separation byte 0x00 and the entry.
func LeafHash(entry []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(entry)
	return Hash(h.Sum(nil))
}

// NodeHash is SHA-256 over the domain-separation byte 0x01 and both
// children.
func NodeHash(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(left[:])
	h.Write(right[:])
	return Hash(h.Sum(nil))
}

// EmptyRoot is the root of the tree without leaves.
func EmptyRoot() Hash { return sha256.Sum256(nil) }

// Tree computes the root of a growing tree. It keeps only one hash per
// level, so it works on logs of any size. The zero value is the empty tree.
type Tree struct {
	size  uint64
	stack []Hash // roots of the complete subtrees, largest first
}

// Append adds a leaf hash.
func (t *Tree) Append(leaf Hash) {
	t.stack = append(t.stack, leaf)
	t.size++
	// One merge for every trailing zero bit of the new size.
	for n := t.size; n&1 == 0; n >>= 1 {
		k := len(t.stack)
		t.stack[k-2] = NodeHash(t.stack[k-2], t.stack[k-1])
		t.stack = t.stack[:k-1]
	}
}

// Size returns the number of leaves.
func (t *Tree) Size() uint64 { return t.size }

// Root returns the root hash of the current tree.
func (t *Tree) Root() Hash {
	if t.size == 0 {
		return EmptyRoot()
	}
	k := len(t.stack)
	r := t.stack[k-1]
	for i := k - 2; i >= 0; i-- {
		r = NodeHash(t.stack[i], r)
	}
	return r
}

// Root returns the root hash of the tree over the given leaf hashes.
func Root(leaves []Hash) Hash {
	var t Tree
	for _, l := range leaves {
		t.Append(l)
	}
	return t.Root()
}

// split returns the largest power of two smaller than n, for n > 1.
func split(n uint64) uint64 {
	return 1 << (bits.Len64(n-1) - 1)
}

// InclusionProof returns the audit path for leaf index in the tree over the
// given leaf hashes.
func InclusionProof(leaves []Hash, index uint64) ([]Hash, error) {
	if index >= uint64(len(leaves)) {
		return nil, errors.New("merkle: index out of range")
	}
	return path(leaves, index), nil
}

func path(leaves []Hash, index uint64) []Hash {
	n := uint64(len(leaves))
	if n == 1 {
		return nil
	}
	k := split(n)
	if index < k {
		return append(path(leaves[:k], index), Root(leaves[k:]))
	}
	return append(path(leaves[k:], index-k), Root(leaves[:k]))
}

// VerifyInclusion checks that the leaf hash is at index in the tree of the
// given size and root (RFC 9162, section 2.1.3.2).
func VerifyInclusion(leaf Hash, index, size uint64, proof []Hash, root Hash) error {
	if index >= size {
		return errors.New("merkle: index out of range")
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return errors.New("merkle: inclusion proof too long")
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return errors.New("merkle: inclusion proof too short")
	}
	if !bytes.Equal(r[:], root[:]) {
		return errors.New("merkle: inclusion proof does not match the root")
	}
	return nil
}

// ConsistencyProof returns the proof that the tree over the first oldSize
// leaves is a prefix of the tree over all given leaves.
func ConsistencyProof(leaves []Hash, oldSize uint64) ([]Hash, error) {
	n := uint64(len(leaves))
	if oldSize == 0 || oldSize > n {
		return nil, errors.New("merkle: old size out of range")
	}
	if oldSize == n {
		return nil, nil
	}
	return subproof(leaves, oldSize, true), nil
}

func subproof(leaves []Hash, m uint64, whole bool) []Hash {
	n := uint64(len(leaves))
	if m == n {
		if whole {
			return nil
		}
		return []Hash{Root(leaves)}
	}
	k := split(n)
	if m <= k {
		return append(subproof(leaves[:k], m, whole), Root(leaves[k:]))
	}
	return append(subproof(leaves[k:], m-k, false), Root(leaves[:k]))
}

// VerifyConsistency checks that the tree with oldSize and oldRoot is a
// prefix of the tree with newSize and newRoot (RFC 9162, section 2.1.4.2).
func VerifyConsistency(oldSize, newSize uint64, oldRoot, newRoot Hash, proof []Hash) error {
	if oldSize == 0 || oldSize > newSize {
		return errors.New("merkle: old size out of range")
	}
	if oldSize == newSize {
		if len(proof) != 0 {
			return errors.New("merkle: consistency proof for equal sizes must be empty")
		}
		if oldRoot != newRoot {
			return errors.New("merkle: roots differ for equal sizes")
		}
		return nil
	}
	if len(proof) == 0 {
		return errors.New("merkle: empty consistency proof")
	}
	// If the old size is a power of two, the old root itself starts the
	// path.
	if oldSize&(oldSize-1) == 0 {
		proof = append([]Hash{oldRoot}, proof...)
	}
	fn, sn := oldSize-1, newSize-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return errors.New("merkle: consistency proof too long")
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return errors.New("merkle: consistency proof too short")
	}
	if fr != oldRoot {
		return errors.New("merkle: consistency proof does not match the old root")
	}
	if sr != newRoot {
		return errors.New("merkle: consistency proof does not match the new root")
	}
	return nil
}
