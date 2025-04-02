package noise

import (
	"crypto"
	"io"

	"golang.org/x/crypto/hkdf"
)

// hashKey allows indexing supported hash algorithm
type hashKey int

const (
	HASH_SHA256 hashKey = iota
	HASH_SHA512
	HASH_BLAKE2B
	HASH_BLAKE2S
)

func GetHash(hk hashKey) (crypto.Hash, error) {
	var algo crypto.Hash
	switch hk {
	case HASH_SHA256:
		algo = crypto.SHA256
	case HASH_SHA512:
		algo = crypto.SHA512
	case HASH_BLAKE2B:
		algo = crypto.BLAKE2b_512
	case HASH_BLAKE2S:
		algo = crypto.BLAKE2s_256
	default:
		return crypto.MD5, ErrUnsupportedHash
	}

	var err error
	if !algo.Available() {
		err = ErrUnsupportedHash
	}
	return algo, err
}

func Hkdf(hash crypto.Hash, ikm, salt []byte) io.Reader {
	return hkdf.New(hash.New, ikm, salt, nil)
}
