package noise

import (
	"crypto/rand"
	"io"

	"code.kerpass.org/golang/internal/algos"
)

// HandshakeState holds noise protocol handshake execution state.
//
// HandshakeState appears in section 5.3 of the noise protocol specs.
type HandshakeState struct {
	SymetricState
	verifiers *VerifierProvider
	initiator bool
	msgPtrns  []msgPtrn
	msgcursor int
	curve     algos.Curve
	s         *Keypair
	e         *Keypair
	rs        *PublicKey
	re        *PublicKey
	psks      [][]byte
	pskcursor int
}

// HandshakeParams holds HandshakeState.Initialize parameters.
type HandshakeParams struct {
	Cfg                Config
	Initiator          bool
	Prologue           []byte
	StaticKeypair      *Keypair
	EphemeralKeypair   *Keypair
	RemoteStaticKey    *PublicKey
	RemoteEphemeralKey *PublicKey
	Psks               [][]byte
}

// Initialize set handshake initial state. It errors if provided parameters are not compatible with provided cfg.
//
// Initialize appears in section 5.3 of the noise protocol specs.
func (self *HandshakeState) Initialize(params HandshakeParams) error {

	cfg := params.Cfg

	err := self.SymetricState.Init(cfg.ProtoName, cfg.CipherFactory, cfg.HashAlgo)
	if nil != err {
		return wrapError(err, "failed SymetricState initialization")
	}

	self.curve = cfg.CurveAlgo

	self.initiator = params.Initiator

	// reuse msgPtrns allocated memory if not empty
	mps := self.msgPtrns
	if nil != mps {
		mps = mps[:0]
	}
	self.msgPtrns = cfg.HandshakePattern.msgPtrns(mps)
	self.msgcursor = 0

	self.s = params.StaticKeypair
	self.e = params.EphemeralKeypair
	self.rs = params.RemoteStaticKey
	self.re = params.RemoteEphemeralKey

	self.MixHash(params.Prologue)

	var failIfUnusedPsks, usePsks bool
	for spec := range cfg.HandshakePattern.listInitSpecs(self.initiator) {
		switch spec.token {
		case "s":
			if nil == self.s {
				return newError("nil s not allowed with configured HandshakePattern")
			}
			if spec.hash {
				self.MixHash(self.s.PublicKey().Bytes())
			}
		case "e":
			if nil == self.e {
				return newError("nil e not allowed with configured HandshakePattern")
			}
			if spec.hash {
				self.MixHash(self.e.PublicKey().Bytes())
				if len(params.Psks) > 0 {
					err = self.MixKey(self.e.PublicKey().Bytes())
					if nil != err {
						return wrapError(err, "failed mixing e PublicKey")
					}
					failIfUnusedPsks = true
				}

			}
		case "rs":
			if nil == self.rs {
				return newError("nil rs not allowed with configured HandshakePattern")
			}
			if spec.hash {
				self.MixHash(self.rs.Bytes())
			}
		case "re":
			if nil == self.re {
				return newError("nil re not allowed with configured HandshakePattern")
			}
			if spec.hash {
				self.MixHash(self.re.Bytes())
				if len(params.Psks) > 0 {
					err = self.MixKey(self.re.Bytes())
					if nil != err {
						return wrapError(err, "failed mixing re")
					}
					failIfUnusedPsks = true
				}
			}
		case "psk":
			usePsks = true

			// pskcursor used by SetPsks to verify that psks is correctly sized.
			// SetPsks set pskcursor to 0 after loading the psks...
			self.pskcursor = spec.size

			err = self.SetPsks(params.Psks...)
			if nil != err {
				return wrapError(err, "failed loading psks")
			}
		default:
			continue
		}
	}
	if failIfUnusedPsks && !usePsks {
		return newError("configured HandshakePattern does not use psks")
	}
	return nil
}

// WriteMessage prepares a new handshake message taking into account inner state and payload parameter.
// The returned bool is true when the handshake is completed.
//
// WriteMessage appears in section 5.3 of the noise protocol specs.
func (self *HandshakeState) WriteMessage(payload []byte, message io.Writer) (bool, error) {

	initiator := self.initiator
	cursor := self.msgcursor

	var parity int
	if initiator {
		parity = 0
	} else {
		parity = 1
	}
	completed := false
	if cursor >= len(self.msgPtrns) || (cursor%2) != parity {
		return completed, newError("handshake error, state does not allow calling WriteMessage")
	}
	self.msgcursor += 1
	if self.msgcursor >= len(self.msgPtrns) {
		completed = true
	}

	var err error
	var ikm []byte
	var msglen int
	var keypair *Keypair
	var pubkey *PublicKey
	for tkn := range self.msgPtrns[cursor].Tokens() {
		switch tkn {
		case "e":
			if nil == self.e {
				keypair, err = self.curve.GenerateKey(rand.Reader)
				if nil != err {
					return completed, wrapError(err, "failed generating e Keypair")
				}
				self.e = keypair
			}
			ikm = self.e.PublicKey().Bytes()
			self.MixHash(ikm)
			if len(self.psks) > 0 {
				err = self.MixKey(ikm)
				if nil != err {
					return completed, wrapError(err, "failed mixing e PublicKey")
				}
			}
			_, err = message.Write(ikm)
			if nil != err {
				return completed, wrapError(err, "failed adding e PublicKey to the message buffer")
			}
			msglen += len(ikm)
		case "s":
			if nil == self.s {
				// initialization will detect this
				return completed, newError("missing s Keypair")
			}
			ikm, err = self.EncryptAndHash(self.s.PublicKey().Bytes())
			if nil != err {
				return completed, wrapError(err, "failed encrypting s PublicKey")
			}
			_, err = message.Write(ikm)
			if nil != err {
				return completed, wrapError(err, "failed adding s PublicKey to the message buffer")
			}
			msglen += len(ikm)
		case "ee":
			err = self.dhmix(self.e, self.re)
			if nil != err {
				return completed, wrapError(err, "failed ee DH mix")
			}
		case "es":
			if initiator {
				keypair = self.e
				pubkey = self.rs
			} else {
				keypair = self.s
				pubkey = self.re
			}
			err = self.dhmix(keypair, pubkey)
			if nil != err {
				return completed, wrapError(err, "failed es DH mix")
			}
		case "se":
			if initiator {
				keypair = self.s
				pubkey = self.re
			} else {
				keypair = self.e
				pubkey = self.rs
			}
			err = self.dhmix(keypair, pubkey)
			if nil != err {
				return completed, wrapError(err, "failed se DH mix")
			}
		case "ss":
			err = self.dhmix(self.s, self.rs)
			if nil != err {
				return completed, wrapError(err, "failed ss DH mix")
			}
		case "psk":
			// note that len(psks) has been validated in Initialize to match HandshakePattern requirements
			err = self.MixKeyAndHash(self.psks[self.pskcursor])
			if nil != err {
				return completed, wrapError(err, "failed mixing psk")
			}
			self.pskcursor += 1
		default:
			// unreachable, as long as the handshake was properly initialized
			return completed, newError("unsupported token %s", tkn)
		}
	}
	ikm, err = self.EncryptAndHash(payload)
	if nil != err {
		return completed, wrapError(err, "failed payload encryption")
	}
	_, err = message.Write(ikm)
	if nil != err {
		return completed, wrapError(err, "failed adding payload to the message buffer")
	}
	msglen += len(ikm)
	if msglen > msgMaxSize {
		return completed, wrapError(errSizeLimit, "generated message larger than %d bytes (noise protocol limit)", msgMaxSize)
	}
	return completed, nil

}

// ReadMessage processes incoming handshake message taking into account inner state.
// The returned bool is true when the handshake is completed.
//
// ReadMessage appears in section 5.3 of the noise protocol specs.
func (self *HandshakeState) ReadMessage(message []byte, payload io.Writer) (bool, error) {
	initiator := self.initiator
	cursor := self.msgcursor
	pubkeysize := self.curve.PublicKeyLen()
	msgsize := len(message)

	var parity int
	if initiator {
		parity = 1
	} else {
		parity = 0
	}
	completed := false
	if cursor >= len(self.msgPtrns) || (cursor%2) != parity {
		return completed, newError("handshake error, state does not allow calling ReadMessage")
	}
	if msgsize > msgMaxSize {
		return completed, wrapError(errSizeLimit, "received message larger than %d bytes (noise protocol limit)", msgMaxSize)
	}
	self.msgcursor += 1
	if self.msgcursor >= len(self.msgPtrns) {
		completed = true
	}

	var err error
	var ikm, ckm []byte
	var rb, want int
	var keypair *Keypair
	var pubkey *PublicKey
	for tkn := range self.msgPtrns[cursor].Tokens() {
		switch tkn {
		case "e":
			if (msgsize - rb) < pubkeysize {
				return completed, newError("message too small for e PublicKey")
			}
			ikm = message[rb : rb+pubkeysize]
			pubkey, err = self.curve.NewPublicKey(ikm)
			if nil != err {
				return completed, wrapError(err, "received invalid e PublicKey")
			}
			rb += pubkeysize
			self.re = pubkey
			self.MixHash(ikm)
			if len(self.psks) > 0 {
				err = self.MixKey(ikm)
				if nil != err {
					return completed, wrapError(err, "failed mixing e PublicKey")
				}
			}
		case "s":
			want = pubkeysize
			if self.HasKey() {
				want += cipherTagSize
			}
			if (msgsize - rb) < want {
				return completed, newError("message too small for s PublicKey credential")
			}
			ckm = message[rb : rb+want]
			ikm, err = self.DecryptAndHash(ckm)
			if nil != err {
				return completed, wrapError(err, "failed decrypting s PublicKey credential")
			}
			pubkey, err = self.curve.NewPublicKey(ikm)
			if nil != err {
				return completed, wrapError(err, "received s PublicKey appears invalid")
			}
			self.rs = pubkey
			rb += want
		case "ee":
			err = self.dhmix(self.e, self.re)
			if nil != err {
				return completed, wrapError(err, "failed ee DH mix")
			}
		case "es":
			if initiator {
				keypair = self.e
				pubkey = self.rs
			} else {
				keypair = self.s
				pubkey = self.re
			}
			err = self.dhmix(keypair, pubkey)
			if nil != err {
				return completed, wrapError(err, "failed es DH mix")
			}
		case "se":
			if initiator {
				keypair = self.s
				pubkey = self.re
			} else {
				keypair = self.e
				pubkey = self.rs
			}
			err = self.dhmix(keypair, pubkey)
			if nil != err {
				return completed, wrapError(err, "failed se DH mix")
			}
		case "ss":
			err = self.dhmix(self.s, self.rs)
			if nil != err {
				return completed, wrapError(err, "failed ss DH mix")
			}
		case "psk":
			// note that len(psks) has been validated in Initialize to match HandshakePattern requirements
			err = self.MixKeyAndHash(self.psks[self.pskcursor])
			if nil != err {
				return completed, wrapError(err, "failed mixing psk")
			}
			self.pskcursor += 1
		default:
			// unreachable, as long as the handshake was properly initialized
			return completed, newError("unsupported token %s", tkn)
		}
	}
	ikm, err = self.DecryptAndHash(message[rb:])
	if nil != err {
		return completed, wrapError(err, "failed message decryption")
	}
	_, err = payload.Write(ikm)
	if nil != err {
		return completed, wrapError(err, "failed transferring data to the payload buffer")
	}
	return completed, nil

}

// DHLen returns ECDH PublicKey byte size.
//
// This method is provided to comply with noise specs section 4.1 that mentions the DHLEN constant.
// noise specs are a bit ambiguous as it states that DHLEN is both the PublicKey size and ECDH shared
// secret size. This equality holds only for X25519 and X448.
func (self *HandshakeState) DHLen() int {
	return self.curve.PublicKeyLen()
}

// RemoteStaticKey returns the remote static PublicKey.
func (self *HandshakeState) RemoteStaticKey() *PublicKey {
	return self.rs
}

// StaticKeypair returns the local static Keypair.
func (self *HandshakeState) StaticKeypair() *Keypair {
	return self.s
}

func (self *HandshakeState) SetPsks(psks ...[]byte) error {
	for _, psk := range psks {
		if len(psk) != pskKeySize {
			return newError("Invalid psk size")
		}
	}
	// Initialize may have set pskcursor to non zero value to express psks size requirements
	if len(psks) < self.pskcursor {
		return newError("Not enough psks for ongoing handshake")
	}
	self.psks = psks
	self.pskcursor = 0
	return nil
}

// Split initializes a TransportCipherPair using internal state.
//
// Split should only be called at the end of the handshake.
//
// Split appears in noise protocol specs section 5.2.
func (self *HandshakeState) Split(dst *TransportCipherPair) error {
	if self.msgcursor < len(self.msgPtrns) {
		return newError("illegal Split call, handshake is not completed")
	}
	if nil == dst {
		return newError("invalid dst, can not be nil")
	}
	hsz := self.hash.Size()
	ck := self.ckb[:hsz]
	tk1 := self.thb[:hsz]
	tk2 := self.tkb[:hsz]
	err := self.hash.Kdf(ck, nil, tk1, tk2)
	if nil != err {
		return wrapError(err, "failed HKDF")
	}
	ecrypt := dst.Encryptor()
	ecrypt.factory = self.factory
	dcrypt := dst.Decryptor()
	dcrypt.factory = self.factory

	var ek, dk []byte
	if self.initiator {
		ek = tk1
		dk = tk2
	} else {
		ek = tk2
		dk = tk1
	}
	err = ecrypt.InitializeKey(ek[:cipherKeySize])
	if nil != err {
		return wrapError(err, "failed initializing encryption key")
	}
	err = dcrypt.InitializeKey(dk[:cipherKeySize])
	if nil != err {
		return wrapError(err, "failed initializing decryption key")
	}

	return nil
}

// dhmix executes Diffie-Hellmann key exchange in between keypair and pubkey.
// It mixes the resulting shared secret into the HandshakeState.
func (self *HandshakeState) dhmix(keypair *Keypair, pubkey *PublicKey) error {
	ikm, err := keypair.ECDH(pubkey)
	if nil != err {
		return wrapError(err, "failed ECDH")
	}
	return self.MixKey(ikm)
}
