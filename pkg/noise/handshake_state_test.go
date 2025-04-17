package noise

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestHandshakeState01(t *testing.T) {
	vectors, err := LoadTestVectors("testdata/snow.txt")
	if nil != err {
		t.Fatalf("Unable to load vectors from snow.txt, got error %v", err)
	}
	// tn := 302
	for tn, vec := range vectors {
		t.Run(fmt.Sprintf("vectors[%d]%s", tn, vec.ProtocolName), func(t *testing.T) {
			testVector(t, vec)
		})
	}
}

func TestHandshakeState02(t *testing.T) {
	vectors, err := LoadTestVectors("testdata/cacophony.txt")
	if nil != err {
		t.Fatalf("Unable to load vectors from cacophony.txt, got error %v", err)
	}
	for tn, vec := range vectors {
		t.Run(fmt.Sprintf("vectors[%d]%s", tn, vec.ProtocolName), func(t *testing.T) {
			testVector(t, vec)
		})
	}
}

type cipherPair struct {
	ecs *CipherState
	dcs *CipherState
}

func (self cipherPair) EncryptWithAd(ad, plaintext []byte) ([]byte, error) {
	// make sure that selected CipherState has a key
	cs := self.ecs
	if nil == cs || !cs.HasKey() {
		return nil, ErrInvalidCipherState
	}
	return cs.EncryptWithAd(ad, plaintext)

}

func (self cipherPair) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	// make sure that selected CipherState has a key
	cs := self.dcs
	if nil == cs || !cs.HasKey() {
		return nil, ErrInvalidCipherState
	}
	return cs.DecryptWithAd(ad, ciphertext)
}

func testVector(t *testing.T, vec TestVector) {
	var err error
	var cfg Config
	var prologue []byte
	var s, e *Keypair
	var rs, re *PublicKey
	hss := [2]HandshakeState{}
	err = cfg.Load(vec.ProtocolName)
	if nil != err {
		t.Skipf("Skipping test for protocol %s, got config error %v", vec.ProtocolName, err)
	}
	if len(vec.InitiatorPrologue) > 0 {
		prologue = []byte(vec.InitiatorPrologue)
	} else {
		prologue = nil
	}
	if len(vec.InitiatorEphemeralKey) > 0 {
		e, err = cfg.DhAlgo.NewPrivateKey([]byte(vec.InitiatorEphemeralKey))
		if nil != err {
			t.Fatalf("Can not load initiator ephemeral Keypair, got error %v", err)
		}
	} else {
		e = nil
	}
	if len(vec.InitiatorStaticKey) > 0 {
		s, err = cfg.DhAlgo.NewPrivateKey([]byte(vec.InitiatorStaticKey))
		if nil != err {
			t.Fatalf("Can not load initiator static Keypair, got error %v", err)
		}
	} else {
		s = nil
	}
	if len(vec.InitiatorRemoteEphemeralKey) > 0 {
		re, err = cfg.DhAlgo.NewPublicKey([]byte(vec.InitiatorRemoteEphemeralKey))
		if nil != err {
			t.Fatalf("Can not load initiator remote ephemeral public key, got error %v", err)
		}
	} else {
		re = nil
	}
	if len(vec.InitiatorRemoteStaticKey) > 0 {
		rs, err = cfg.DhAlgo.NewPublicKey([]byte(vec.InitiatorRemoteStaticKey))
		if nil != err {
			t.Fatalf("Can not load initiator remote static public key, got error %v", err)
		}
	} else {
		rs = nil
	}
	err = hss[0].Initialize(cfg, true, prologue, s, e, rs, re, nil)
	if nil != err {
		t.Fatalf("Failed initiator handshake initialization, got error %v", err)
	}

	if len(vec.ResponderPrologue) > 0 {
		prologue = []byte(vec.ResponderPrologue)
	} else {
		prologue = nil
	}
	if len(vec.ResponderEphemeralKey) > 0 {
		e, err = cfg.DhAlgo.NewPrivateKey([]byte(vec.ResponderEphemeralKey))
		if nil != err {
			t.Fatalf("Can not load responder ephemeral Keypair, got error %v", err)
		}
	} else {
		e = nil
	}
	if len(vec.ResponderStaticKey) > 0 {
		s, err = cfg.DhAlgo.NewPrivateKey([]byte(vec.ResponderStaticKey))
		if nil != err {
			t.Fatalf("Can not load responder static Keypair, got error %v", err)
		}
	} else {
		s = nil
	}
	if len(vec.ResponderRemoteEphemeralKey) > 0 {
		re, err = cfg.DhAlgo.NewPublicKey([]byte(vec.ResponderRemoteEphemeralKey))
		if nil != err {
			t.Fatalf("Can not load responder remote ephemeral public key, got error %v", err)
		}
	} else {
		re = nil
	}
	if len(vec.ResponderRemoteStaticKey) > 0 {
		rs, err = cfg.DhAlgo.NewPublicKey([]byte(vec.ResponderRemoteStaticKey))
		if nil != err {
			t.Fatalf("Can not load responder remote static public key, got error %v", err)
		}
	} else {
		rs = nil
	}
	err = hss[1].Initialize(cfg, false, prologue, s, e, rs, re, nil)
	if nil != err {
		t.Fatalf("Failed responder handshake initialization, got error %v", err)
	}

	mbuf := new(bytes.Buffer)
	pbuf := new(bytes.Buffer)
	var payload, ciphertext []byte
	var writeCompleted, readCompleted bool
	var writeIdx, readIdx, untestedIdx int
	var errWrite, errRead error
	for pos, msg := range vec.Messages {
		writeIdx = pos % 2
		readIdx = (pos + 1) % 2

		mbuf.Reset()
		pbuf.Reset()
		payload = []byte(msg.Payload)
		ciphertext = []byte(msg.CipherText)
		writeCompleted, errWrite = hss[writeIdx].WriteMessage(payload, mbuf)
		if nil != errWrite {
			t.Fatalf("msg[%d] : Failed writemessage, got error %v", pos, errWrite)
		}
		readCompleted, errRead = hss[readIdx].ReadMessage(mbuf.Bytes(), pbuf)
		if nil != errRead {
			t.Fatalf("msg[%d] : Failed readmessage, got error %v", pos, errRead)
		}
		if !(writeCompleted == readCompleted) {
			t.Fatalf("msg[%d] : readCompleted %v != writeCompleted %v", pos, readCompleted, writeCompleted)
		}
		if !reflect.DeepEqual(mbuf.Bytes(), ciphertext) {
			t.Fatalf("msg[%d] : Failed ciphertext check", pos)
		}
		if !reflect.DeepEqual(payload, pbuf.Bytes()) {
			t.Fatalf("msg[%d] : Failed payload check", pos)
		}
		if writeCompleted && readCompleted {
			untestedIdx = pos + 1
			break
		}
	}
	t.Logf("=== %d processed messages", len(vec.Messages[0:untestedIdx]))
	t.Logf("=== %d unprocessed messages", len(vec.Messages[untestedIdx:]))
	cs00, cs01, err := hss[0].Split()
	if nil != err {
		t.Fatalf("Failed hss[0].Split()")
	}
	cs10, cs11, err := hss[1].Split()
	if nil != err {
		t.Fatalf("Failed hss[1].Split()")
	}

	if len(vec.HandshakeHash) > 0 {
		if !reflect.DeepEqual(hss[0].GetHandshakeHash(), []byte(vec.HandshakeHash)) {
			t.Fatalf("Failed hss[0] HandshakeHash control")
		}
		if !reflect.DeepEqual(hss[1].GetHandshakeHash(), []byte(vec.HandshakeHash)) {
			t.Fatalf("Failed hss[1] HandshakeHash control")
		}
	} else {
		if !reflect.DeepEqual(hss[0].GetHandshakeHash(), hss[1].GetHandshakeHash()) {
			t.Fatalf("Failed peer HandshakeHash control")
		}
	}

	peers := []cipherPair{{ecs: cs00, dcs: cs10}, {ecs: cs11, dcs: cs01}}
	if cfg.HandshakePattern.OneWay() {
		peers[1] = peers[0]
	}
	var cp cipherPair
	var plaintxt, ciphertxt []byte
	pmsg := len(vec.Messages[:untestedIdx])
	for pos, msg := range vec.Messages[untestedIdx:] {
		cp = peers[(pmsg+pos)%2]
		ciphertxt, err = cp.EncryptWithAd(nil, []byte(msg.Payload))
		if nil != err {
			t.Fatalf("transport msg[%d]: Failed payload encryption, got error %v", pos, err)
		}
		plaintxt, err = cp.DecryptWithAd(nil, ciphertxt)
		if nil != err {
			t.Fatalf("transport msg[%d]: Failed ciphertxt decryption, got error %v", pos, err)
		}
		if !reflect.DeepEqual(plaintxt, []byte(msg.Payload)) {
			t.Fatalf("transport msg[%d]: Failed plaintxt check\n% X\n!=\n% X", pos, plaintxt, msg.Payload)
		}
		if !reflect.DeepEqual(ciphertxt, []byte(msg.CipherText)) {
			t.Fatalf("transport msg[%d]: Failed ciphertxt check\n% X\n!=\n% X", pos, ciphertxt, msg.CipherText)
		}
	}

}
