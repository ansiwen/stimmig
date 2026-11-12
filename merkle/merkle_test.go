package merkle

import (
	"encoding/hex"
	"testing"
)

// Leaf inputs and roots of the Certificate Transparency reference test
// vectors for RFC 6962.
var ctLeaves = []string{
	"", "00", "10", "2021", "3031", "40414243", "5051525354555657",
	"606162636465666768696a6b6c6d6e6f",
}

var ctRoots = []string{
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func TestCTVectors(t *testing.T) {
	if got := hex.EncodeToString(func() []byte { r := EmptyRoot(); return r[:] }()); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("empty root = %s", got)
	}
	var tree Tree
	for i, l := range ctLeaves {
		data, _ := hex.DecodeString(l)
		tree.Append(LeafHash(data))
		r := tree.Root()
		if got := hex.EncodeToString(r[:]); got != ctRoots[i] {
			t.Errorf("root of %d leaves = %s, want %s", i+1, got, ctRoots[i])
		}
	}
}

func testLeaves(n int) []Hash {
	leaves := make([]Hash, n)
	for i := range leaves {
		leaves[i] = LeafHash([]byte{byte(i), byte(i >> 8)})
	}
	return leaves
}

func TestInclusionProofs(t *testing.T) {
	other := LeafHash([]byte("other"))
	for n := 1; n <= 70; n++ {
		leaves := testLeaves(n)
		root := Root(leaves)
		for i := 0; i < n; i++ {
			proof, err := InclusionProof(leaves, uint64(i))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyInclusion(leaves[i], uint64(i), uint64(n), proof, root); err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if VerifyInclusion(other, uint64(i), uint64(n), proof, root) == nil {
				t.Fatalf("n=%d i=%d: wrong leaf accepted", n, i)
			}
			if n > 1 && VerifyInclusion(leaves[i], uint64((i+1)%n), uint64(n), proof, root) == nil && leaves[i] != leaves[(i+1)%n] {
				t.Fatalf("n=%d i=%d: wrong index accepted", n, i)
			}
			if VerifyInclusion(leaves[i], uint64(i), uint64(n), append(proof, other), root) == nil {
				t.Fatalf("n=%d i=%d: long proof accepted", n, i)
			}
			if len(proof) > 0 && VerifyInclusion(leaves[i], uint64(i), uint64(n), proof[1:], root) == nil {
				t.Fatalf("n=%d i=%d: short proof accepted", n, i)
			}
		}
		if _, err := InclusionProof(leaves, uint64(n)); err == nil {
			t.Fatal("index out of range accepted")
		}
	}
}

func TestConsistencyProofs(t *testing.T) {
	other := LeafHash([]byte("other"))
	for n := 1; n <= 70; n++ {
		leaves := testLeaves(n)
		root := Root(leaves)
		for m := 1; m <= n; m++ {
			oldRoot := Root(leaves[:m])
			proof, err := ConsistencyProof(leaves, uint64(m))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyConsistency(uint64(m), uint64(n), oldRoot, root, proof); err != nil {
				t.Fatalf("m=%d n=%d: %v", m, n, err)
			}
			if VerifyConsistency(uint64(m), uint64(n), other, root, proof) == nil {
				t.Fatalf("m=%d n=%d: wrong old root accepted", m, n)
			}
			if VerifyConsistency(uint64(m), uint64(n), oldRoot, other, proof) == nil {
				t.Fatalf("m=%d n=%d: wrong new root accepted", m, n)
			}
			if VerifyConsistency(uint64(m), uint64(n), oldRoot, root, append(proof, other)) == nil {
				t.Fatalf("m=%d n=%d: long proof accepted", m, n)
			}
			if len(proof) > 0 && VerifyConsistency(uint64(m), uint64(n), oldRoot, root, proof[1:]) == nil {
				t.Fatalf("m=%d n=%d: short proof accepted", m, n)
			}
		}
		if _, err := ConsistencyProof(leaves, 0); err == nil {
			t.Fatal("old size 0 accepted")
		}
		if _, err := ConsistencyProof(leaves, uint64(n+1)); err == nil {
			t.Fatal("old size beyond the tree accepted")
		}
	}
}

// A history rewrite is detected: a tree whose early leaf differs is not
// consistent with the old root.
func TestConsistencyDetectsRewrite(t *testing.T) {
	leaves := testLeaves(20)
	oldRoot := Root(leaves[:7])
	forged := append([]Hash(nil), leaves...)
	forged[3] = LeafHash([]byte("forged"))
	proof, _ := ConsistencyProof(forged, 7)
	if VerifyConsistency(7, 20, oldRoot, Root(forged), proof) == nil {
		t.Fatal("rewritten history accepted")
	}
}
