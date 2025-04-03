package noise

import (
	"crypto"

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

func fillKeys(hash crypto.Hash, ikm, salt []byte, keys ...[]byte) error {
	var err error
	rdr := hkdf.New(hash.New, ikm, salt, nil)
	for _, key := range keys {
		_, err = rdr.Read(key)
		if nil != err {
			return err
		}
	}
	return nil
}
