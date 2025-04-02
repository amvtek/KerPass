package noise

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

type cipherKey int

const (
	CIPHER_AES256_GCM cipherKey = iota
	CIPHER_CHACHA20_POLY1305
)

func GetCipher(ck cipherKey) (Cipher, error) {
	switch ck {
	case CIPHER_AES256_GCM:
		return aes256GCM{}, nil
	case CIPHER_CHACHA20_POLY1305:
		return chacha{}, nil
	default:
		return nil, ErrUnsupportedCipher
	}
}

type Cipher interface {
	Encrypt(key []byte, nonce uint64, ad []byte, plaintext []byte) ([]byte, error)
	Decrypt(key []byte, nonce uint64, ad []byte, ciphertext []byte) ([]byte, error)
}

type aes256GCM struct{}

func (self aes256GCM) Encrypt(key []byte, nonce uint64, ad []byte, plaintext []byte) ([]byte, error) {
	aead, err := self.getCipher(key)
	if nil != err {
		return nil, err
	}

	nonce96 := make([]byte, 12)
	self.fillNonceBuffer(nonce96, nonce)

	ciphertext := aead.Seal(nil, nonce96, plaintext, ad)
	return ciphertext, nil
}

func (self aes256GCM) Decrypt(key []byte, nonce uint64, ad []byte, ciphertext []byte) ([]byte, error) {
	aead, err := self.getCipher(key)
	if nil != err {
		return nil, err
	}

	nonce96 := make([]byte, 12)
	self.fillNonceBuffer(nonce96, nonce)

	return aead.Open(nil, nonce96, ciphertext, ad)
}

func (_ aes256GCM) getCipher(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrInvalidCipherKeySize
	}

	block, err := aes.NewCipher(key)
	if nil != err {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (_ aes256GCM) fillNonceBuffer(dst []byte, value uint64) {
	if len(dst) < 12 {
		panic("Invalid nonce buffer size")
	}
	binary.BigEndian.PutUint32(dst, 0)
	binary.BigEndian.PutUint64(dst[4:], value)
}

type chacha struct{}

func (self chacha) Encrypt(key []byte, nonce uint64, ad []byte, plaintext []byte) ([]byte, error) {
	aead, err := self.getCipher(key)
	if nil != err {
		return nil, err
	}

	nonce96 := make([]byte, 12)
	self.fillNonceBuffer(nonce96, nonce)

	ciphertext := aead.Seal(nil, nonce96, plaintext, ad)
	return ciphertext, nil
}

func (self chacha) Decrypt(key []byte, nonce uint64, ad []byte, ciphertext []byte) ([]byte, error) {
	aead, err := self.getCipher(key)
	if nil != err {
		return nil, err
	}

	nonce96 := make([]byte, 12)
	self.fillNonceBuffer(nonce96, nonce)

	return aead.Open(nil, nonce96, ciphertext, ad)
}

func (_ chacha) getCipher(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrInvalidCipherKeySize
	}

	return chacha20poly1305.New(key)
}

func (_ chacha) fillNonceBuffer(dst []byte, value uint64) {
	if len(dst) < 12 {
		panic("Invalid nonce buffer size")
	}
	binary.LittleEndian.PutUint32(dst, 0)
	binary.LittleEndian.PutUint64(dst[4:], value)
}
