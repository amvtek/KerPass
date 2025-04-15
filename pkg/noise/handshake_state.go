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
		return err
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

	self.psks = psks
	self.pskcursor = 0

	self.MixHash(prologue)

	for spec := range cfg.HandshakePattern.ListInitSpecs(initiator) {
		switch spec.token {
		// TODO: ErrInvalidHandshakePattern not correct
		case "s":
			if nil == self.s {
				return ErrInvalidHandshakePattern
			}
			if spec.hash {
				self.MixHash(s.PublicKey().Bytes())
			}
		case "e":
			if nil == self.e {
				return ErrInvalidHandshakePattern
			}
			if spec.hash {
				self.MixHash(e.PublicKey().Bytes())
			}
		case "rs":
			if nil == self.rs {
				return ErrInvalidHandshakePattern
			}
			if spec.hash {
				self.MixHash(rs.Bytes())
			}
		case "re":
			if nil == self.re {
				return ErrInvalidHandshakePattern
			}
			if spec.hash {
				self.MixHash(re.Bytes())
			}
		case "psk":
			if len(self.psks) != spec.size {
				return ErrInvalidHandshakePattern
			}
			for _, psk := range self.psks {
				if len(psk) != pskKeySize {
					return ErrInvalidHandshakePattern
				}
			}
		default:
			continue
		}
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
		return completed, ErrOutOfSequence
	}
	self.msgcursor += 1
	if self.msgcursor >= len(self.msgPtrns) {
		completed = true
	}

	var err error
	var ikm []byte
	var keypair *Keypair
	var pubkey *PublicKey
	for tkn := range self.msgPtrns[cursor].Tokens() {
		switch tkn {
		case "e":
			if nil == self.e {
				keypair, err = self.dh.GenerateKeypair()
				if nil != err {
					return completed, err
				}
				self.e = keypair
			}
			ikm = self.e.PublicKey().Bytes()
			self.MixHash(ikm)
			_, err = message.Write(ikm)
			if nil != err {
				return completed, err
			}
		case "s":
			if nil == self.s {
				return completed, ErrMissingKey
			}
			ikm, err = self.EncryptAndHash(self.s.PublicKey().Bytes())
			if nil != err {
				return completed, err
			}
			_, err = message.Write(ikm)
			if nil != err {
				return completed, err
			}
		case "ee":
			err = self.dhmix(self.e, self.re)
			if nil != err {
				return completed, err
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
				return completed, err
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
				return completed, err
			}
		case "ss":
			err = self.dhmix(self.s, self.rs)
			if nil != err {
				return completed, err
			}
		default:
			return completed, ErrUnsupportedToken
		}
	}
	ikm, err = self.EncryptAndHash(payload)
	if nil != err {
		return completed, err
	}
	_, err = message.Write(ikm)
	if nil != err {
		return completed, err
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
		return completed, ErrOutOfSequence
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
				return completed, ErrInvalidMessage
			}
			ikm = message[rb : rb+dhlen]
			pubkey, err = self.dh.NewPublicKey(ikm)
			if nil != err {
				return completed, err
			}
			rb += dhlen
			self.re = pubkey
			self.MixHash(ikm)
		case "s":
			want = dhlen
			if self.HasKey() {
				want += cipherTagSize
			}
			if (msgsize - rb) < want {
				return completed, ErrInvalidMessage
			}
			ckm = message[rb : rb+want]
			ikm, err = self.DecryptAndHash(ckm)
			if nil != err {
				return completed, err
			}
			pubkey, err = self.dh.NewPublicKey(ikm)
			if nil != err {
				return completed, err
			}
			self.rs = pubkey
			rb += want
		case "ee":
			err = self.dhmix(self.e, self.re)
			if nil != err {
				return completed, err
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
				return completed, err
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
				return completed, err
			}
		case "ss":
			err = self.dhmix(self.s, self.rs)
			if nil != err {
				return completed, err
			}
		default:
			return completed, ErrUnsupportedToken
		}
	}
	ikm, err = self.DecryptAndHash(message[rb:])
	if nil != err {
		return completed, err
	}
	_, err = payload.Write(ikm)
	if nil != err {
		return completed, err
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
