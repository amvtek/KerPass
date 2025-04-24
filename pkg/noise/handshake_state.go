package noise

import (
	"io"
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
	dh        DH
	s         *Keypair
	e         *Keypair
	rs        *PublicKey
	re        *PublicKey
	psks      [][]byte
	pskcursor int
}

// Initialize set handshake initial state. It errors if provided parameters are not compatible with provided cfg.
//
// Initialize appears in section 5.3 of the noise protocol specs.
func (self *HandshakeState) Initialize(
	cfg Config,
	verifiers *VerifierProvider,
	initiator bool,
	prologue []byte,
	s *Keypair, e *Keypair, rs *PublicKey, re *PublicKey,
	psks [][]byte,
) error {

	err := self.SymetricState.Init(cfg.ProtoName, cfg.CipherFactory, cfg.HashAlgo)
	if nil != err {
		return wrapError(err, "failed SymetricState initialization")
	}

	self.dh = cfg.DhAlgo

	self.verifiers = verifiers
	verifiers.Reset()

	self.initiator = initiator

	// reuse msgPtrns allocated memory if not empty
	mps := self.msgPtrns
	if nil != mps {
		mps = mps[:0]
	}
	self.msgPtrns = cfg.HandshakePattern.msgPtrns(mps)
	self.msgcursor = 0

	self.s = s
	self.e = e
	self.rs = rs
	self.re = re

	self.MixHash(prologue)

	var failIfUnusedPsks, usePsks bool
	for spec := range cfg.HandshakePattern.listInitSpecs(initiator) {
		switch spec.token {
		case "s":
			if nil == self.s {
				return newError("nil s not allowed with configured HandshakePattern")
			}
			if spec.hash {
				self.MixHash(s.PublicKey().Bytes())
			}
		case "e":
			if nil == self.e {
				return newError("nil e not allowed with configured HandshakePattern")
			}
			if spec.hash {
				self.MixHash(e.PublicKey().Bytes())
				if len(psks) > 0 {
					err = self.MixKey(e.PublicKey().Bytes())
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
				self.MixHash(rs.Bytes())
			}
		case "re":
			if nil == self.re {
				return newError("nil re not allowed with configured HandshakePattern")
			}
			if spec.hash {
				self.MixHash(re.Bytes())
				if len(psks) > 0 {
					err = self.MixKey(re.Bytes())
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

			// psks maybe loaded later during the handshake by one of the CredentialVerifiers
			if !verifiers.ShouldLoad("psks") {
				err = self.SetPsks(psks...)
				if nil != err {
					return wrapError(err, "failed loading psks")
				}
			}
		case "verifiers":
			if nil == verifiers {
				return newError("configured HandshakePattern require non nil verifiers")
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
				keypair, err = self.dh.GenerateKeypair()
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
	dhlen := self.dh.DHLen()
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
	var rb, want, skip int
	var staticKeyVerifier CredentialVerifier
	var keypair *Keypair
	var pubkey *PublicKey
	for tkn := range self.msgPtrns[cursor].Tokens() {
		switch tkn {
		case "e":
			if (msgsize - rb) < dhlen {
				return completed, newError("message too small for e PublicKey")
			}
			ikm = message[rb : rb+dhlen]
			pubkey, err = self.dh.NewPublicKey(ikm)
			if nil != err {
				return completed, wrapError(err, "received invalid e PublicKey")
			}
			rb += dhlen
			self.re = pubkey
			self.MixHash(ikm)
			if len(self.psks) > 0 {
				err = self.MixKey(ikm)
				if nil != err {
					return completed, wrapError(err, "failed mixing e PublicKey")
				}
			}
		case "s":
			staticKeyVerifier = self.verifiers.Get("s")
			if nil == staticKeyVerifier {
				return completed, newError("can not load static key verifier")
			}
			want = staticKeyVerifier.ReadSize(self)
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
			// static key verification step 1
			skip, err = staticKeyVerifier.Verify(self, ikm)
			if nil != err {
				return completed, wrapError(err, "failed step 1 of s PublicKey credential verification")
			}
			pubkey, err = self.dh.NewPublicKey(ikm[skip:])
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
	skip = 0
	if nil != staticKeyVerifier {
		// perform static key verification step 2
		// the idea is that the payload of the message may contain additional verification information eg a certificate
		// TODO: see if multiple step validation is really useful ?
		skip, err = staticKeyVerifier.Verify(self, ikm)
		if nil != err {
			return completed, wrapError(err, "failed step 2 of s PublicKey credential verification")
		}
	}
	_, err = payload.Write(ikm[skip:])
	if nil != err {
		return completed, wrapError(err, "failed transferring data to the payload buffer")
	}
	return completed, nil

}

// DHLen returns inner DH PublicKey byte size.
func (self *HandshakeState) DHLen() int {
	return self.dh.DHLen()
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
	ikm, err := self.dh.DH(keypair, pubkey)
	if nil != err {
		return err
	}
	return self.MixKey(ikm)
}
