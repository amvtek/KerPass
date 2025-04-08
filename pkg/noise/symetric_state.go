package noise

import (
	"crypto"
)

type SymetricState struct {
	hash   crypto.Hash
	cipher *CipherState
	hb     [64]byte
	ckb    [64]byte
	tkb    [64]byte
	thb    [64]byte
}

func (self *SymetricState) InitializeSymetric(protoname string) error {

	proto := NoiseProto{}
	ps, err := ParseProtocol(protoname, &proto)
	if nil != err {
		return err
	}

	hash, err := GetHash(proto.HashAlgo)
	if nil != err {
		return err
	}

	// ps is noise protocol name with whitespace stripped
	psb := []byte(ps)
	h := self.hb[:]
	ck := self.ckb[:]
	if len(psb) < hash.Size() {
		zeros := make([]byte, 64)
		copy(h, zeros)
		copy(h, psb)
	} else {
		hd := hash.New()
		hd.Write(psb)
		h = hd.Sum(self.hb[:0])
	}
	copy(ck, h)

	// The CipherState returned by NewCipherState conforms to noise spec 5.2 as it contains the "empty" key.
	// Hence there is no need to call cipher.InitializeKey(nil)
	cipher, err := NewCipherState(proto.CipherAlgo)
	if nil != err {
		return err
	}
	self.hash = hash
	self.cipher = cipher
	return nil

}

func (self *SymetricState) MixKey(ikm []byte) error {
	hsz := self.hash.Size()
	ck := self.ckb[:hsz]
	tk := self.tkb[:hsz]
	err := Hkdf(self.hash, ck, ikm, ck, tk)
	if nil != err {
		return err
	}
	return self.cipher.InitializeKey(tk[:32])
}

func (self *SymetricState) MixHash(data []byte) {
	hsz := self.hash.Size()
	h := self.hb[:hsz]
	hd := self.hash.New()
	hd.Write(h)
	hd.Write(data)
	hd.Sum(h)
}

func (self *SymetricState) MixKeyAndHash(ikm []byte) error {
	hsz := self.hash.Size()
	ck := self.ckb[:hsz]
	th := self.thb[:hsz]
	tk := self.tkb[:hsz]
	err := Hkdf(self.hash, ck, ikm, ck, th, tk)
	if nil != err {
		return err
	}
	self.MixHash(th)
	return self.cipher.InitializeKey(tk[:32])
}

func (self *SymetricState) GetHandshakeHash() []byte {
	// TODO:
	// Spec section 5.2 says that this function shall be called after Split
	// Split() could take care of this ?
	hsz := self.hash.Size()
	rt := make([]byte, hsz)
	copy(rt, self.hb[:hsz])
	return rt
}

func (self *SymetricState) EncryptAndHash(plaintext []byte) ([]byte, error) {
	hsz := self.hash.Size()
	h := self.hb[:hsz]
	ciphertext, err := self.cipher.EncryptWithAd(h, plaintext)
	if nil != err {
		return nil, err
	}
	self.MixHash(ciphertext)
	return ciphertext, nil
}

func (self *SymetricState) DecryptAndHash(ciphertext []byte) ([]byte, error) {
	hsz := self.hash.Size()
	h := self.hb[:hsz]
	plaintext, err := self.cipher.DecryptWithAd(h, ciphertext)
	if nil != err {
		return nil, err
	}
	self.MixHash(ciphertext)
	return plaintext, nil
}

func (self *SymetricState) Split() (*CipherState, *CipherState, error) {
	hsz := self.hash.Size()
	ck := self.ckb[:hsz]
	tk1 := self.thb[:hsz]
	tk2 := self.tkb[:hsz]
	err := Hkdf(self.hash, ck, nil, tk1, tk2)
	if nil != err {
		return nil, nil, err
	}
	cs1 := CipherState{factory: self.cipher.factory}
	err = cs1.InitializeKey(tk1[:32])
	if nil != err {
		return nil, nil, err
	}
	cs2 := CipherState{factory: self.cipher.factory}
	err = cs2.InitializeKey(tk2[:32])
	if nil != err {
		return nil, nil, err
	}
	return &cs1, &cs2, nil
}
