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
		return nil, ErrUnsupportedCipher
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
			return err
		}
	default:
		return ErrInvalidKeySize
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
		return plaintext, nil
	}
	if CIPHER_MAX_NONCE == self.n {
		return nil, ErrCipherKeyOverUse
	}
	nonce := self.nonceb[:]
	self.aead.FillNonce(nonce, self.n)
	ciphertext := self.aead.Seal(nil, nonce, plaintext, ad)
	self.n += 1
	return ciphertext, nil
}

func (self *CipherState) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	if !self.HasKey() {
		return ciphertext, nil
	}
	if CIPHER_MAX_NONCE == self.n {
		return nil, ErrCipherKeyOverUse
	}
	nonce := self.nonceb[:]
	self.aead.FillNonce(nonce, self.n)
	plaintext, err := self.aead.Open(nil, nonce, ciphertext, ad)
	if nil != err {
		return nil, err
	}
	self.n += 1 // spec says not to increment if Decrypt fails
	return plaintext, nil
}

func (self *CipherState) Rekey() error {
	if !self.HasKey() {
		return ErrInvalidCipherState
	}
	newkey := self.kb[:]
	err := self.aead.Rekey(newkey, self.nonceb[:])
	if nil != err {
		return err
	}
	aead, err := self.factory.New(newkey)
	if nil != err {
		return err
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
		return nil, ErrInvalidCipherKeySize
	}

	block, err := aes.NewCipher(key)
	if nil != err {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if nil != err {
		return nil, err
	}
	return aesGCMAEAD{AEAD: aead}, nil

}

func (self aesGCMAEAD) Rekey(newkey []byte, nonce []byte) error {
	self.FillNonce(nonce, CIPHER_MAX_NONCE)
	zeros := make([]byte, hashMaxSize)
	ciphertext := self.Seal(nil, nonce, zeros[:cipherKeySize], nil)
	numcopied := copy(newkey, ciphertext)
	if numcopied < cipherKeySize {
		return ErrRekeyLowEntropy
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
		return nil, ErrInvalidCipherKeySize
	}

	aead, err := chacha20poly1305.New(key)
	if nil != err {
		return nil, err
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
