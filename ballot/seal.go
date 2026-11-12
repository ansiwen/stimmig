// Package ballot implements the voter-side and ballot-box-side cryptography
// of a ballot in assurance profile A: encryption to the election key,
// the ballot signature with the credential key, and the receipt
// (SPEC.md sections 5.2 to 5.4).
package ballot

import (
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"

	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/tally"
)

// EncryptionAlgorithm is the identifier of the ballot encryption in the
// manifest: HPKE (RFC 9180) in base mode with DHKEM(P-256, HKDF-SHA256),
// HKDF-SHA256 and AES-256-GCM. This is ECDH on P-256 plus AES-GCM in a
// standard construction.
const EncryptionAlgorithm = "hpke-p256-hkdf-sha256-aes256gcm-v1"

const (
	sealContext = "stimmig-ballot-encryption-v1"
	encSize     = 65 // uncompressed P-256 point
)

var (
	suite     = hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	kemScheme = hpke.KEM_P256_HKDF_SHA256.Scheme()
)

// ErrDecrypt reports a ciphertext that the election key does not open.
var ErrDecrypt = errors.New("ballot: ciphertext does not decrypt")

// ErrMalformed reports a plaintext that is not an encoded ranking.
var ErrMalformed = errors.New("ballot: plaintext is not a ranking")

// GenerateElectionKey creates the election key pair. The public key is an
// uncompressed P-256 point of 65 bytes, the private key a scalar of 32
// bytes.
func GenerateElectionKey() (public, private []byte, err error) {
	pk, sk, err := kemScheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	if public, err = pk.MarshalBinary(); err != nil {
		return nil, nil, err
	}
	if private, err = sk.MarshalBinary(); err != nil {
		return nil, nil, err
	}
	return public, private, nil
}

func parsePublic(public []byte) (kem.PublicKey, error) {
	pk, err := kemScheme.UnmarshalBinaryPublicKey(public)
	if err != nil || len(public) != encSize {
		return nil, errors.New("ballot: election key is not an uncompressed P-256 point")
	}
	return pk, nil
}

// CheckElectionKey reports whether public is a valid election public key.
func CheckElectionKey(public []byte) error {
	_, err := parsePublic(public)
	return err
}

// MatchElectionKey reports whether the published private key belongs to the
// election public key.
func MatchElectionKey(public, private []byte) error {
	sk, err := kemScheme.UnmarshalBinaryPrivateKey(private)
	if err != nil {
		return errors.New("ballot: election private key is malformed")
	}
	derived, err := sk.Public().MarshalBinary()
	if err != nil {
		return err
	}
	if string(derived) != string(public) {
		return errors.New("ballot: election private key does not match the public key")
	}
	return nil
}

// sealInfo binds a ciphertext to one election.
func sealInfo(electionID merkle.Hash) ([]byte, error) {
	return canon.Marshal([]any{sealContext, electionID[:]})
}

// Seal encrypts a ranking to the election key. The ciphertext is the HPKE
// encapsulated key followed by the AEAD ciphertext of the canonically
// encoded ranking.
func Seal(random io.Reader, electionID merkle.Hash, electionKey []byte, ranking tally.Ballot) ([]byte, error) {
	pk, err := parsePublic(electionKey)
	if err != nil {
		return nil, err
	}
	if ranking == nil {
		ranking = tally.Ballot{} // an empty ballot is an empty array, not null
	}
	plain, err := canon.Marshal(ranking)
	if err != nil {
		return nil, err
	}
	info, err := sealInfo(electionID)
	if err != nil {
		return nil, err
	}
	sender, err := suite.NewSender(pk, info)
	if err != nil {
		return nil, err
	}
	enc, sealer, err := sender.Setup(random)
	if err != nil {
		return nil, err
	}
	ct, err := sealer.Seal(plain, nil)
	if err != nil {
		return nil, err
	}
	return append(enc, ct...), nil
}

// Open decrypts a ciphertext with the published election private key. It
// returns ErrDecrypt or ErrMalformed for ballots that must be logged as
// invalid.
func Open(electionID merkle.Hash, private, ciphertext []byte) (tally.Ballot, error) {
	sk, err := kemScheme.UnmarshalBinaryPrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("ballot: election private key: %w", err)
	}
	info, err := sealInfo(electionID)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < encSize {
		return nil, ErrDecrypt
	}
	receiver, err := suite.NewReceiver(sk, info)
	if err != nil {
		return nil, err
	}
	opener, err := receiver.Setup(ciphertext[:encSize])
	if err != nil {
		return nil, ErrDecrypt
	}
	plain, err := opener.Open(ciphertext[encSize:], nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	ranking := tally.Ballot{}
	if err := canon.Unmarshal(plain, &ranking); err != nil || ranking == nil {
		return nil, ErrMalformed
	}
	for _, group := range ranking {
		if group == nil {
			return nil, ErrMalformed
		}
	}
	return ranking, nil
}
