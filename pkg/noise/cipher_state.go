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

	// Rekey changes AEAD key to newkey. It errors if newkey is not compatible with AEAD algorithm.
	Rekey(newkey []byte, nonce []byte) error

	// FillNonce transfers nonce value n to nonce slice.
	FillNonce(nonce []byte, n uint64)
}

// AEADFactory allows obtaining an AEAD instance.
type AEADFactory interface {

	// New returns an AEAD instance. It errors if key is not compatible with AEAD algorithm.
	New(key []byte) (AEAD, error)
}

// MustRegisterAEAD adds factory to the AEAD registry. It panics if name is already in use or factory is invalid.
func MustRegisterAEAD(name string, factory AEADFactory) {
	err := RegisterAEAD(name, factory)
	if nil != err {
		panic(err)
	}
}

// RegisterAEAD adds factory to the AEAD registry. It errors if name is already in use or factory is invalid.
func RegisterAEAD(name string, factory AEADFactory) error {
	if nil == factory {
		return newError("AEAD factory can not be nil")
	}
	return registrySet(aeadRegistry, name, factory)
}

// GetAEADFactory loads an AEADFactory from the registry. It errors if no factory was registered with name.
func GetAEADFactory(name string) (AEADFactory, error) {
	factory, found := registryGet(aeadRegistry, name)
	if !found || nil == factory {
		return nil, newError("Unsupported cipher %s", name)
	}
	return factory, nil
}

// AEADFactoryFunc is an adapter to allow the use of ordinary functions as AEADFactory.
type AEADFactoryFunc func([]byte) (AEAD, error)

// New returns an AEAD instance. It errors if key is not compatible with AEAD algorithm.
func (self AEADFactoryFunc) New(key []byte) (AEAD, error) {
	return self(key)
}

// CipherState holds AEAD cipher usage state, ie nonce and key.
//
// CipherState appears in section 5.1 of the noise protocol specs.
type CipherState struct {

	// factory allows instantiating a new AEAD.
	// a valid CipherState has a non nil factory.
	factory AEADFactory

	// aead performs authenticated encryption operations.
	// aead is initialized during the noise protocol handshake.
	aead AEAD

	// kb contains the "bytes" of the aead key.
	kb [cipherKeySize]byte

	// n contains next nonce value.
	n uint64

	// nonceb contains binary encoding of nonce value.
	nonceb [cipherNonceSize]byte
}

// HasKey returns true if the CipherState contains an initialized aead.
//
// Haskey appears in section 5.1 of the noise protocol specs.
func (self *CipherState) HasKey() bool {
	return (nil != self.aead)
}

// Init set inner AEAD factory and zero the key.
//
// Init appears in section 5.1 of the noise protocol specs.
func (self *CipherState) Init(cipherFactory AEADFactory) error {
	self.factory = cipherFactory
	return self.InitializeKey(nil)
}

// InitializeKey creates internal aead using newkey.
// A nil newkey will zero the internal key and aead.
// InitializeKey errors if newkey is not correctly sized.
//
// InitializeKey appears in section 5.1 of the noise protocol specs.
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

// SetNonce set internal nonce value to n.
//
// SetNonce is usefull when the CipherState is used after completion of the noise protocol handshake.
// If transport messages are produced concurrently or maybe received out of order then application
// will transfert nonce value with transport message. Receiver shall verify that received nonce was
// not previously used and use SetNonce prior to attend decryption...
// SetNonce appears in section 5.1 of the noise protocol specs.
func (self *CipherState) SetNonce(n uint64) {
	self.n = n
}

// EncryptWithAd performs authenticated encryption of plaintext if the CipherState has a key otherwise
// it returns plaintext inchanged.
//
// The ad parameter maybe nil, it corresponds to AEAD "additional data" and it is used alongside plaintext
// and key to calculate the ciphertext authentication tag.
// EncryptWithAd appears in section 5.1 of the noise protocol specs.
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

// DecryptWithAd performs authenticated decryption of ciphertext if the CipherState has a key otherwise
// it returns ciphertext inchanged.
//
// The ad parameter maybe nil, it shall match the ad used for obtaining ciphertext. ad corresponds to AEAD
// "additional data" and it was used alongside plaintext and key to calculate the ciphertext authentication tag.
// DecryptWithAd appears in section 5.1 of the noise protocol specs.
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

// Rekey changes the CipherState internal key. It errors if the CipherState does not have a key.
//
// Rekey appears in section 5.1 of the noise protocol specs.
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

// aesGCMAEAD is an implementation of the AEAD interface that wraps the AESGCM cipher.
type aesGCMAEAD struct {
	cipher.AEAD
}

// newAESGCM returns an AEAD implemented by aesGCMAEAD.
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

// Rekey derives a new cipher key and copy it into newkey. It errors if newkey or nonce buffers are not
// correctly sized.
//
// Rekey implements the REKEY algorithm that appears in noise protocol specs, section 4.2.
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

// FillNonce marshals n value into the nonce buffer.
//
// The way n is transformed into binary is detailled in noise protocol specs, section 12.4.
func (_ aesGCMAEAD) FillNonce(nonce []byte, n uint64) {
	if len(nonce) < cipherNonceSize {
		// if nonce does not have the correct size, this is an implementation error
		panic("Invalid nonce buffer size")
	}
	binary.BigEndian.PutUint32(nonce, 0)
	binary.BigEndian.PutUint64(nonce[4:], n)
}

// chachaPoly1305AEAD is an implementation of the AEAD interface that wraps the CHACHA20_POLY1305 cipher.
type chachaPoly1305AEAD struct {
	aesGCMAEAD
}

// newChachaPoly1305 returns an AEAD implemented by chachaPoly1305AEAD.
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

// FillNonce marshals n value into the nonce buffer.
//
// The way n is transformed into binary is detailled in noise protocol specs, section 12.3.
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
