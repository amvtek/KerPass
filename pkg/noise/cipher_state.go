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

type CipherState struct {
	factory aeadFactory
	aead    aeadIfce
	k       [cipherKeySize]byte
	n       uint64
	nonce   [cipherNonceSize]byte
}

func NewCipherState(algo string) (*CipherState, error) {

	var newAead aeadFactory
	switch algo {
	case CIPHER_AES256_GCM:
		newAead = newAESGCM
	case CIPHER_CHACHA20_POLY1305:
		newAead = newChachaPoly1305
	default:
		return nil, ErrUnsupportedCipher
	}
	return &CipherState{factory: newAead}, nil
}

func (self *CipherState) HasKey() bool {
	return (nil != self.aead)
}

func (self *CipherState) InitializeKey(newkey []byte) error {
	var aead aeadIfce
	var err error
	if len(newkey) == 0 {
		// if newkey has length 0, we assume it corresponds to the "empty" key mentionned in noise specs 5.2
		aead = nil
		zeros := make([]byte, cipherKeySize)
		copy(self.key(), zeros)
	} else {
		numbytes := copy(self.key(), newkey)
		if numbytes < cipherKeySize {
			return ErrRekeyLowEntropy
		}
		aead, err = self.factory(self.key())
		if nil != err {
			return err
		}
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
	nonce := self.nonce[:]
	self.aead.fillNonce(nonce, self.n)
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
	nonce := self.nonce[:]
	self.aead.fillNonce(nonce, self.n)
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
	newkey := self.k[:]
	err := self.aead.rekey(newkey, self.nonce[:])
	if nil != err {
		return err
	}
	aead, err := self.factory(newkey)
	if nil != err {
		return err
	}
	self.aead = aead
	// RMQ: we keep n counter inchanged as the spec says nothing about it.
	return nil
}

func (self *CipherState) key() []byte {
	return self.k[:]
}

// aeadIfce extends cipher.AEAD with methods usefull for noise protocol implementation.
type aeadIfce interface {
	cipher.AEAD
	rekey(newkey []byte, nonce []byte) error
	fillNonce(nonce []byte, n uint64)
}

type aeadFactory func([]byte) (aeadIfce, error)

type aesGCMAEAD struct {
	cipher.AEAD
}

func newAESGCM(key []byte) (aeadIfce, error) {
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

func (self aesGCMAEAD) rekey(newkey []byte, nonce []byte) error {
	self.fillNonce(nonce, CIPHER_MAX_NONCE)
	zeros := make([]byte, hashMaxSize)
	ciphertext := self.Seal(nil, nonce, zeros[:cipherKeySize], nil)
	numcopied := copy(newkey, ciphertext)
	if numcopied < cipherKeySize {
		return ErrRekeyLowEntropy
	}
	copy(ciphertext, zeros)
	return nil
}

func (_ aesGCMAEAD) fillNonce(nonce []byte, n uint64) {
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

func newChachaPoly1305(key []byte) (aeadIfce, error) {
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

func (_ chachaPoly1305AEAD) fillNonce(nonce []byte, n uint64) {
	if len(nonce) < cipherNonceSize {
		// if nonce does not have the correct size, this is an implementation error
		panic("Invalid nonce buffer size")
	}
	binary.LittleEndian.PutUint32(nonce, 0)
	binary.LittleEndian.PutUint64(nonce[4:], n)
}
