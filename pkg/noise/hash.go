package noise

import (
	"crypto"

	_ "crypto/sha512"
	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"

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
	hsz := self.Size()
	// ikm is used as HKDF secret & ck as HKDF salt
	rdr := hkdf.New(self.New, ikm, ck, nil)
	var rsz int
	for _, key := range keys {
		rsz, err = rdr.Read(key)
		if nil != err {
			return err
		}
		if rsz != hsz {
			return ErrInvalidKeySize
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
	MustRegisterHash(HASH_SHA512, crypto.SHA512)
	MustRegisterHash(HASH_SHA256, crypto.SHA256)
	MustRegisterHash(HASH_BLAKE2B, crypto.BLAKE2b_512)
	MustRegisterHash(HASH_BLAKE2S, crypto.BLAKE2s_256)
}
