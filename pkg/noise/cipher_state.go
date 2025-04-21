package noise

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	MAX_UINT64       = 0xFFFF_FFFF_FFFF_FFFF
	CIPHER_MAX_NONCE = MAX_UINT64 - 1
)

const (
	CIPHER_AES256_GCM        = "AESGCM"
	CIPHER_CHACHA20_POLY1305 = "ChaChaPoly"
)

var aeadRegistry *registry[AEADFactory]

// AEAD extends cipher.AEAD with methods usefull for noise protocol implementation.
type AEAD interface {
	cipher.AEAD
	Rekey(newkey []byte, nonce []byte) error
	FillNonce(nonce []byte, n uint64)
}

type AEADFactory interface {
	New(key []byte) (AEAD, error)
}

func MustRegisterAEAD(name string, factory AEADFactory) {
	err := RegisterAEAD(name, factory)
	if nil != err {
		panic(err)
	}
}

func RegisterAEAD(name string, factory AEADFactory) error {
	return registrySet(aeadRegistry, name, factory)
}

func GetAEADFactory(name string) (AEADFactory, error) {
	factory, found := registryGet(aeadRegistry, name)
	if !found || nil == factory {
		return nil, newError("Unsupported cipher %s", name)
	}
	return factory, nil
}

type AEADFactoryFunc func([]byte) (AEAD, error)

func (self AEADFactoryFunc) New(key []byte) (AEAD, error) {
	return self(key)
}

type CipherState struct {
	factory AEADFactory
	aead    AEAD
	kb      [cipherKeySize]byte
	n       uint64
	nonceb  [cipherNonceSize]byte
}

func (self *CipherState) HasKey() bool {
	return (nil != self.aead)
}

func (self *CipherState) Init(cipherFactory AEADFactory) error {
	self.factory = cipherFactory
	return self.InitializeKey(nil)
}

func (self *CipherState) InitializeKey(newkey []byte) error {
	var aead AEAD
	var err error
	switch len(newkey) {
	case 0:
		// if newkey has length 0, we assume it corresponds to the "empty" key mentionned in noise specs 5.2
		aead = nil
		zeros := make([]byte, cipherKeySize)
		copy(self.kb[:], zeros)
	case cipherKeySize:
		copy(self.kb[:], newkey)
		aead, err = self.factory.New(self.kb[:])
		if nil != err {
			return wrapError(err, "Failed AEAD construction")
		}
	default:
		return newError("Invalid key size %d", len(newkey))
	}
	self.aead = aead
	self.n = 0
	return nil
}

func (self *CipherState) SetNonce(n uint64) {
	self.n = n
}

func (self *CipherState) EncryptWithAd(ad, plaintext []byte) ([]byte, error) {
	if !self.HasKey() {
		// possible during noise Handshake
		return plaintext, nil
	}
	if CIPHER_MAX_NONCE == self.n {
		return nil, newError("Cipher key over use")
	}
	if (len(plaintext) + cipherTagSize) > msgMaxSize {
		// this enforce noise msgMaxSize for transport messages
		return nil, wrapError(errSizeLimit, "plaintext larger than %d bytes (noise protocol size limit)", msgMaxSize-cipherTagSize)
	}
	nonce := self.nonceb[:]
	self.aead.FillNonce(nonce, self.n)
	ciphertext := self.aead.Seal(nil, nonce, plaintext, ad)
	self.n += 1
	return ciphertext, nil
}

func (self *CipherState) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	if !self.HasKey() {
		// possible during noise Handshake
		return ciphertext, nil
	}
	if CIPHER_MAX_NONCE == self.n {
		return nil, newError("Cipher key over use")
	}
	if len(ciphertext) > msgMaxSize {
		// this enforce noise msgMaxSize for transport messages
		return nil, wrapError(errSizeLimit, "ciphertext larger than %d bytes (noise protocol size limit)", msgMaxSize)
	}
	nonce := self.nonceb[:]
	self.aead.FillNonce(nonce, self.n)
	plaintext, err := self.aead.Open(nil, nonce, ciphertext, ad)
	if nil != err {
		return nil, wrapError(err, "failed aead.Open")
	}
	self.n += 1 // spec says not to increment if Decrypt fails
	return plaintext, nil
}

func (self *CipherState) Rekey() error {
	if !self.HasKey() {
		return newError("Invalid CipherState, key is nil")
	}
	newkey := self.kb[:]
	err := self.aead.Rekey(newkey, self.nonceb[:])
	if nil != err {
		return wrapError(err, "failed aead.Rekey")
	}
	aead, err := self.factory.New(newkey)
	if nil != err {
		return wrapError(err, "failed aead construction")
	}
	self.aead = aead
	// RMQ: we keep n counter inchanged as the spec says nothing about it.
	return nil
}

type aesGCMAEAD struct {
	cipher.AEAD
}

func newAESGCM(key []byte) (AEAD, error) {
	if len(key) != cipherKeySize {
		return nil, newError("invalid Cipher key size %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if nil != err {
		return nil, wrapError(err, "failed AES cipher creation")
	}
	aead, err := cipher.NewGCM(block)
	if nil != err {
		return nil, wrapError(err, "failed AES GCM wrapping")
	}
	return aesGCMAEAD{AEAD: aead}, nil

}

func (self aesGCMAEAD) Rekey(newkey []byte, nonce []byte) error {
	self.FillNonce(nonce, CIPHER_MAX_NONCE)
	zeros := make([]byte, hashMaxSize)
	ciphertext := self.Seal(nil, nonce, zeros[:cipherKeySize], nil)
	numcopied := copy(newkey, ciphertext)
	if numcopied < cipherKeySize {
		return newError("Rekey low entropy %d bits", 8*numcopied)
	}
	copy(ciphertext, zeros)
	return nil
}

func (_ aesGCMAEAD) FillNonce(nonce []byte, n uint64) {
	if len(nonce) < cipherNonceSize {
		// if nonce does not have the correct size, this is an implementation error
		panic("Invalid nonce buffer size")
	}
	binary.BigEndian.PutUint32(nonce, 0)
	binary.BigEndian.PutUint64(nonce[4:], n)
}

type chachaPoly1305AEAD struct {
	aesGCMAEAD
}

func newChachaPoly1305(key []byte) (AEAD, error) {
	if len(key) != cipherKeySize {
		return nil, newError("invalid Cipher key size %d", len(key))
	}

	aead, err := chacha20poly1305.New(key)
	if nil != err {
		return nil, wrapError(err, "failed chacha20 poly1305 creation")
	}
	rv := chachaPoly1305AEAD{}
	rv.AEAD = aead
	return rv, nil
}

func (_ chachaPoly1305AEAD) FillNonce(nonce []byte, n uint64) {
	if len(nonce) < cipherNonceSize {
		// if nonce does not have the correct size, this is an implementation error
		panic("Invalid nonce buffer size")
	}
	binary.LittleEndian.PutUint32(nonce, 0)
	binary.LittleEndian.PutUint64(nonce[4:], n)
}

func init() {
	aeadRegistry = newRegistry[AEADFactory]()
	MustRegisterAEAD(CIPHER_AES256_GCM, AEADFactoryFunc(newAESGCM))
	MustRegisterAEAD(CIPHER_CHACHA20_POLY1305, AEADFactoryFunc(newChachaPoly1305))
}
