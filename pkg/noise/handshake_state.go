package noise

import (
	"io"
)

type HandshakeState struct {
	SymetricState
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

func (self *HandshakeState) Initialize(cfg Config, initiator bool, prologue []byte, s *Keypair, e *Keypair, rs *PublicKey, re *PublicKey, psks [][]byte) error {

	err := self.SymetricState.Init(cfg.ProtoName, cfg.CipherFactory, cfg.HashAlgo)
	if nil != err {
		return wrapError(err, "failed SymetricState initialization")
	}

	self.dh = cfg.DhAlgo

	self.initiator = initiator

	// reuse msgPtrns allocated memory if not empty
	mps := self.msgPtrns
	if nil != mps {
		mps = mps[:0]
	}
	self.msgPtrns = cfg.HandshakePattern.MsgPtrns(mps)
	self.msgcursor = 0

	self.s = s
	self.e = e
	self.rs = rs
	self.re = re

	self.MixHash(prologue)

	var failIfUnusedPsks, usePsks bool
	for spec := range cfg.HandshakePattern.ListInitSpecs(initiator) {
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
			if len(psks) != spec.size {
				return newError("psks length not compatible with configured HandshakePattern")
			}
			for _, psk := range psks {
				if len(psk) != pskKeySize {
					return newError("one of the provided psk is not correctly sized")
				}
			}
			usePsks = true
			self.psks = psks
			self.pskcursor = 0
		default:
			continue
		}
	}
	if failIfUnusedPsks && !usePsks {
		return newError("configured HandshakePattern does not use psks")
	}
	return nil
}

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
	var rb, want int
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
			want = dhlen
			if self.HasKey() {
				want += cipherTagSize
			}
			if (msgsize - rb) < want {
				return completed, newError("message too small for s PublicKey")
			}
			ckm = message[rb : rb+want]
			ikm, err = self.DecryptAndHash(ckm)
			if nil != err {
				return completed, wrapError(err, "failed decrypting s PublicKey")
			}
			pubkey, err = self.dh.NewPublicKey(ikm)
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

func (self *HandshakeState) dhmix(keypair *Keypair, pubkey *PublicKey) error {
	ikm, err := self.dh.DH(keypair, pubkey)
	if nil != err {
		return err
	}
	return self.MixKey(ikm)
}
