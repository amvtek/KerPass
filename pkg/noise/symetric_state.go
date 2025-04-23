package noise

// SymetricState holds noise protocol handshake symetric state.
//
// SymetricState appears in noise protocol specs section 5.2.
type SymetricState struct {
	CipherState
	hash Hash
	hb   [hashMaxSize]byte
	ckb  [hashMaxSize]byte
	tkb  [hashMaxSize]byte
	thb  [hashMaxSize]byte
}

// Init set SymetricState initial state.
func (self *SymetricState) Init(protoname string, cipherfactory AEADFactory, hash Hash) error {
	self.hash = hash
	self.initCK(protoname)
	return wrapError(self.CipherState.Init(cipherfactory), "failed CipherState Init")
}

// InitializeSymetric set SymetricState initial state reading configuration information from protoname.
//
// InitializeSymetric is provided as it appears in noise protocol specs section 5.2.
// In most cases, it is preferrable to initialize SymetricState using Init as it is more efficient.
func (self *SymetricState) InitializeSymetric(protoname string) error {

	proto := NoiseProto{}
	err := ParseProtocol(protoname, &proto)
	if nil != err {
		return wrapError(err, "failed parsing protocol %s", protoname)
	}

	hash, err := GetHash(proto.HashAlgo)
	if nil != err {
		return wrapError(err, "failed loading Hash algorithm, %s", proto.HashAlgo)
	}
	self.hash = hash

	self.initCK(proto.Name)

	aeadFactory, err := GetAEADFactory(proto.CipherAlgo)
	if nil != err {
		return wrapError(err, "failed loading AEAD factory, %s", proto.CipherAlgo)
	}
	return wrapError(self.CipherState.Init(aeadFactory), "failed CipherState Init")
}

// MixKey mixes ikm into the SymetricState state.
//
// MixKey appears in noise protocol specs section 5.2.
func (self *SymetricState) MixKey(ikm []byte) error {
	hsz := self.hash.Size()
	ck := self.ckb[:hsz]
	tk := self.tkb[:hsz]
	err := self.hash.Kdf(ck, ikm, ck, tk)
	if nil != err {
		return wrapError(err, "failed HKDF")
	}
	return wrapError(self.InitializeKey(tk[:cipherKeySize]), "failed InitializeKey")
}

// MixHash mixes data into the SymetricState state.
//
// MixHash appears in noise protocol specs section 5.2.
func (self *SymetricState) MixHash(data []byte) {
	hsz := self.hash.Size()
	h := self.hb[:hsz]
	hd := self.hash.New()
	hd.Write(h)
	hd.Write(data)
	h = hd.Sum(self.hb[:0])
}

// MixKeyAndHash mixes ikm into the SymetricState state.
//
// MixKeyAndHash appears in noise protocol specs section 5.2.
func (self *SymetricState) MixKeyAndHash(ikm []byte) error {
	hsz := self.hash.Size()
	ck := self.ckb[:hsz]
	th := self.thb[:hsz]
	tk := self.tkb[:hsz]
	err := self.hash.Kdf(ck, ikm, ck, th, tk)
	if nil != err {
		return wrapError(err, "failed HKDF")
	}
	self.MixHash(th)
	return wrapError(self.InitializeKey(tk[:cipherKeySize]), "failed InitializeKey")
}

// GetHandshakeHash returns SymetricState h state.
//
// GetHandshakeHash is normally called at the end of the handshake.
//
// GetHandshakeHash appears in noise protocol specs section 5.2.
func (self *SymetricState) GetHandshakeHash() []byte {
	// TODO:
	// Spec section 5.2 says that this function shall be called after Split
	// Split() could take care of this ?
	hsz := self.hash.Size()
	rt := make([]byte, hsz)
	copy(rt, self.hb[:hsz])
	return rt
}

// EncryptAndHash returns ciphertext encrypted using inner CipherState. The ciphertext
// is mixed into the SymetricState before being returned.
//
// EncryptAndHash uses internal state to authenticate returned ciphertext.
// ciphertext recipient will be able to decrypt the returned ciphertext only if its
// state is exactly same as self.
//
// EncryptAndHash appears in noise protocol specs section 5.2.
func (self *SymetricState) EncryptAndHash(plaintext []byte) ([]byte, error) {
	hsz := self.hash.Size()
	h := self.hb[:hsz]
	ciphertext, err := self.EncryptWithAd(h, plaintext)
	if nil != err {
		return nil, wrapError(err, "failed EncryptWithAd")
	}
	self.MixHash(ciphertext)
	return ciphertext, nil
}

// DecryptAndHash returns plaintext decrypted using inner CipherState. After plaintext
// is decrypted the received ciphertext is mixed into the SymetricState.
//
// DecryptAndHash uses internal state to authenticate received ciphertext. ciphertext
// can be decrypted only if internal state is exactly same as sender before ciphertext
// encryption.
//
// DecryptAndHash appears in noise protocol specs section 5.2.
func (self *SymetricState) DecryptAndHash(ciphertext []byte) ([]byte, error) {
	hsz := self.hash.Size()
	h := self.hb[:hsz]
	plaintext, err := self.DecryptWithAd(h, ciphertext)
	if nil != err {
		return nil, wrapError(err, "failed DecryptWithAd")
	}
	self.MixHash(ciphertext)
	return plaintext, nil
}

// TODO: move Split to HandshakeState, this will simplify ensuring it is used at the right time.

func (self *SymetricState) initCK(protoname string) {
	psb := []byte(protoname)
	h := self.hb[:]
	ck := self.ckb[:]
	if len(psb) <= self.hash.Size() {
		zeros := make([]byte, hashMaxSize)
		copy(h, zeros)
		copy(h, psb)
	} else {
		hd := self.hash.New()
		hd.Write(psb)
		h = hd.Sum(self.hb[:0])
	}
	copy(ck, h)
}
