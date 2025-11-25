package algos

import (
	"crypto"

	_ "crypto/sha256"
	_ "crypto/sha512"
	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"
	_ "golang.org/x/crypto/sha3"

	"code.kerpass.org/golang/internal/utils"
)

const (
	HASH_SHA256     = "SHA256"
	HASH_SHA512     = "SHA512"
	HASH_SHA512_256 = "SHA512/256"
	HASH_SHA3_256   = "SHA3/256"
	HASH_SHA3_512   = "SHA3/512"
	HASH_BLAKE2B    = "BLAKE2b"
	HASH_BLAKE2S    = "BLAKE2s"
)

var hashRegistry *utils.Registry[string, crypto.Hash]

// MustRegisterHash adds hash to the Hash registry. It panics if name is already in use or hash is invalid.
func MustRegisterHash(name string, hash crypto.Hash) {
	err := RegisterHash(name, hash)
	if nil != err {
		panic(err)
	}
}

// RegisterHash adds hash to the Hash registry. It errors if name is already in use or hash is invalid.
func RegisterHash(name string, hash crypto.Hash) error {
	if !hash.Available() {
		return newError("missing implementation for Hash %s", name)
	}
	return wrapError(
		utils.RegistrySet(hashRegistry, name, hash),
		"failed registering Hash algorithm, %s",
		name,
	)
}

// GetHash loads Hash implementation from the registry. It errors if no hash was registered with name.
func GetHash(name string) (crypto.Hash, error) {
	hash, found := utils.RegistryGet(hashRegistry, name)
	if !found {
		return hash, newError("unsupported Hash algorithm, %s", name)
	}
	return hash, nil

}

// ListHashes returns a slice containing the names of the registered Hash algorithms.
func ListHashes() []string {
	hashIdx := utils.RegistryEntries(hashRegistry)
	rv := make([]string, 0, len(hashIdx))
	for name, _ := range hashIdx {
		rv = append(rv, name)
	}
	return rv
}

func init() {
	hashRegistry = utils.NewRegistry[string, crypto.Hash]()
	MustRegisterHash(HASH_SHA256, crypto.SHA256)
	MustRegisterHash(HASH_SHA512, crypto.SHA512)
	MustRegisterHash(HASH_SHA512_256, crypto.SHA512_256)
	MustRegisterHash(HASH_SHA3_256, crypto.SHA3_256)
	MustRegisterHash(HASH_SHA3_512, crypto.SHA3_512)
	MustRegisterHash(HASH_BLAKE2B, crypto.BLAKE2b_512)
	MustRegisterHash(HASH_BLAKE2S, crypto.BLAKE2s_256)
}
