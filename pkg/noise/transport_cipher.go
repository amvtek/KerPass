package noise

type TransportCipher struct {
	CipherState
}

func (self *TransportCipher) EncryptWithAd(ad, plaintext []byte) ([]byte, error) {
	if !self.HasKey() {

		return nil, newError("missing cipher key")
	}
	return self.CipherState.EncryptWithAd(ad, plaintext)
}

func (self *TransportCipher) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	if !self.HasKey() {
		return nil, newError("missing cipher key")
	}
	return self.CipherState.DecryptWithAd(ad, ciphertext)
}

type TransportCipherPair struct {
	ciphers [2]TransportCipher
}

func (self *TransportCipherPair) Encryptor() *TransportCipher {
	return &self.ciphers[0]
}

func (self *TransportCipherPair) Decryptor() *TransportCipher {
	return &self.ciphers[1]
}
