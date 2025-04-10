package noise

import (
	"crypto"

	"golang.org/x/crypto/hkdf"
)

const (
	HASH_SHA256  = "SHA256"
	HASH_SHA512  = "SHA512"
	HASH_BLAKE2B = "BLAKE2b"
	HASH_BLAKE2S = "BLAKE2s"
)

var hashRegistry *registry[Hash]

type Hash struct {
	crypto.Hash
}

func (self Hash) Kdf(ck, ikm []byte, keys ...[]byte) error {
	var err error
	rdr := hkdf.New(self.New, ck, ikm, nil)
	for _, key := range keys {
		_, err = rdr.Read(key)
		if nil != err {
			return err
		}
	}
	return nil
}

func MustRegisterHash(name string, algo crypto.Hash) {
	err := RegisterHash(name, algo)
	if nil != err {
		panic(err)
	}
}

func RegisterHash(name string, algo crypto.Hash) error {
	return registrySet(hashRegistry, name, Hash{Hash: algo})
}

func GetHash(name string) (Hash, error) {
	hash, found := registryGet(hashRegistry, name)
	if !found {
		return hash, ErrUnsupportedHash
	}
	var err error
	hsz := hash.Size()
	if !hash.Available() || hsz < hashMinSize || hsz > hashMaxSize {
		err = ErrUnsupportedHash
	}
	return hash, err

}

func init() {
	hashRegistry = newRegistry[Hash]()
	MustRegisterHash(HASH_SHA256, crypto.SHA256)
	MustRegisterHash(HASH_SHA512, crypto.SHA512)
	MustRegisterHash(HASH_BLAKE2B, crypto.BLAKE2b_512)
	MustRegisterHash(HASH_BLAKE2S, crypto.BLAKE2s_256)
}
