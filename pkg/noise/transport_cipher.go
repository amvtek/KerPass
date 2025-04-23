package noise

// TransportCipher is a CipherState that is used after handshake completion.
type TransportCipher struct {
	CipherState
}

// EncryptWithAd performs authenticated encryption of plaintext if the TransportCipher has a key otherwise
// it errors.
//
// The ad parameter maybe nil, it corresponds to AEAD "additional data" and it is used alongside plaintext
// and key to calculate the ciphertext authentication tag.
//
// The noise protocol specs suggests using CipherState.EncryptWithAd for transport encryption. The problem
// is that CipherState allows operating with a zero key which is necessary for starting the handshake, but
// would be insecure during the transport phase.
func (self *TransportCipher) EncryptWithAd(ad, plaintext []byte) ([]byte, error) {
	if !self.HasKey() {
		return nil, newError("missing cipher key")
	}
	return self.CipherState.EncryptWithAd(ad, plaintext)
}

// DecryptWithAd performs authenticated decryption of ciphertext if the TransportCipher has a key otherwise
// it errors.
//
// The ad parameter maybe nil, it shall match the ad used for obtaining ciphertext. ad corresponds to AEAD
// "additional data" and it was used alongside plaintext and key to calculate the ciphertext authentication tag.
//
// The noise protocol specs suggests using CipherState.DecryptWithAd for transport decryption. The problem
// is that CipherState allows operating with a zero key which is necessary for starting the handshake, but
// would be insecure during the transport phase.
func (self *TransportCipher) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	if !self.HasKey() {
		return nil, newError("missing cipher key")
	}
	return self.CipherState.DecryptWithAd(ad, ciphertext)
}

// TransportCipherPair holds TransportCipher used for transport encryption/decryption.
type TransportCipherPair struct {
	ciphers [2]TransportCipher
}

// Encryptor returns the TransportCipher to be used for transport encryption.
func (self *TransportCipherPair) Encryptor() *TransportCipher {
	return &self.ciphers[0]
}

// Decryptor returns the TransportCipher to be used for transport decryption.
func (self *TransportCipherPair) Decryptor() *TransportCipher {
	return &self.ciphers[1]
}
