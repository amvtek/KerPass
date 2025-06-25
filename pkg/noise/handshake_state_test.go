package noise

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestHandshakeState01(t *testing.T) {
	vectors, err := LoadTestVectors("testdata/snow.txt")
	if nil != err {
		t.Fatalf("Unable to load vectors from snow.txt, got error %v", err)
	}
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

func TestHandshakeStateSizeLimit(t *testing.T) {
	vectors, err := LoadTestVectors("testdata/snow.txt")
	if nil != err {
		t.Fatalf("Unable to load vectors from snow.txt, got error %v", err)
	}
	for tn, vec := range vectors[:16] {
		t.Run(fmt.Sprintf("vectors[%d]%s", tn, vec.ProtocolName), func(t *testing.T) {
			testSizeLimit(t, vec)
		})
	}
}

type cipherPair struct {
	ecs *TransportCipher
	dcs *TransportCipher
}

func (self cipherPair) EncryptWithAd(ad, plaintext []byte) ([]byte, error) {
	// make sure that selected TransportCipher has a key
	cs := self.ecs
	if nil == cs || !cs.HasKey() {
		return nil, newError("invalid TransportCipher")
	}
	return cs.EncryptWithAd(ad, plaintext)

}

func (self cipherPair) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	// make sure that selected TransportCipher has a key
	cs := self.dcs
	if nil == cs || !cs.HasKey() {
		return nil, newError("invalid TransportCipher")
	}
	return cs.DecryptWithAd(ad, ciphertext)
}

func testVector(t *testing.T, vec TestVector) {
	var err error
	var cfg Config
	var prologue []byte
	var s, e *Keypair
	var rs, re *PublicKey
	var psks, rpsks [][]byte
	hss := [2]HandshakeState{}
	err = cfg.Load(vec.ProtocolName)
	if nil != err {
		t.Fatalf("Failed loading configuration for protocol %s, got error %v", vec.ProtocolName, err)
	}
	if len(vec.InitiatorPrologue) > 0 {
		prologue = []byte(vec.InitiatorPrologue)
	} else {
		prologue = nil
	}
	if len(vec.InitiatorEphemeralKey) > 0 {
		e, err = cfg.CurveAlgo.NewPrivateKey([]byte(vec.InitiatorEphemeralKey))
		if nil != err {
			t.Fatalf("Can not load initiator ephemeral Keypair, got error %v", err)
		}
	} else {
		e = nil
	}
	if len(vec.InitiatorStaticKey) > 0 {
		s, err = cfg.CurveAlgo.NewPrivateKey([]byte(vec.InitiatorStaticKey))
		if nil != err {
			t.Fatalf("Can not load initiator static Keypair, got error %v", err)
		}
	} else {
		s = nil
	}
	if len(vec.InitiatorRemoteEphemeralKey) > 0 {
		re, err = cfg.CurveAlgo.NewPublicKey([]byte(vec.InitiatorRemoteEphemeralKey))
		if nil != err {
			t.Fatalf("Can not load initiator remote ephemeral public key, got error %v", err)
		}
	} else {
		re = nil
	}
	if len(vec.InitiatorRemoteStaticKey) > 0 {
		rs, err = cfg.CurveAlgo.NewPublicKey([]byte(vec.InitiatorRemoteStaticKey))
		if nil != err {
			t.Fatalf("Can not load initiator remote static public key, got error %v", err)
		}
	} else {
		rs = nil
	}
	if len(vec.InitiatorPsks) > 0 {
		psks = make([][]byte, 0, len(vec.InitiatorPsks))
		for _, psk := range vec.InitiatorPsks {
			psks = append(psks, []byte(psk))
		}
	} else {
		psks = nil
	}
	params := HandshakeParams{
		Cfg:                cfg,
		Verifiers:          newVerifiers(),
		Initiator:          true,
		Prologue:           prologue,
		StaticKeypair:      s,
		EphemeralKeypair:   e,
		RemoteStaticKey:    rs,
		RemoteEphemeralKey: re,
		Psks:               psks,
	}
	err = hss[0].Initialize(params)
	if nil != err {
		t.Fatalf("Failed initiator handshake initialization, got error %v", err)
	}

	if len(vec.ResponderPrologue) > 0 {
		prologue = []byte(vec.ResponderPrologue)
	} else {
		prologue = nil
	}
	if len(vec.ResponderEphemeralKey) > 0 {
		e, err = cfg.CurveAlgo.NewPrivateKey([]byte(vec.ResponderEphemeralKey))
		if nil != err {
			t.Fatalf("Can not load responder ephemeral Keypair, got error %v", err)
		}
	} else {
		e = nil
	}
	if len(vec.ResponderStaticKey) > 0 {
		s, err = cfg.CurveAlgo.NewPrivateKey([]byte(vec.ResponderStaticKey))
		if nil != err {
			t.Fatalf("Can not load responder static Keypair, got error %v", err)
		}
	} else {
		s = nil
	}
	if len(vec.ResponderRemoteEphemeralKey) > 0 {
		re, err = cfg.CurveAlgo.NewPublicKey([]byte(vec.ResponderRemoteEphemeralKey))
		if nil != err {
			t.Fatalf("Can not load responder remote ephemeral public key, got error %v", err)
		}
	} else {
		re = nil
	}
	if len(vec.ResponderRemoteStaticKey) > 0 {
		rs, err = cfg.CurveAlgo.NewPublicKey([]byte(vec.ResponderRemoteStaticKey))
		if nil != err {
			t.Fatalf("Can not load responder remote static public key, got error %v", err)
		}
	} else {
		rs = nil
	}
	if len(vec.ResponderPsks) > 0 {
		rpsks = make([][]byte, 0, len(vec.ResponderPsks))
		for _, psk := range vec.ResponderPsks {
			rpsks = append(rpsks, []byte(psk))
		}
	} else {
		rpsks = nil
	}
	params = HandshakeParams{
		Cfg:                cfg,
		Verifiers:          newVerifiers(),
		Initiator:          false,
		Prologue:           prologue,
		StaticKeypair:      s,
		EphemeralKeypair:   e,
		RemoteStaticKey:    rs,
		RemoteEphemeralKey: re,
		Psks:               rpsks,
	}
	err = hss[1].Initialize(params)
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
	tc0 := TransportCipherPair{}
	err = hss[0].Split(&tc0)
	if nil != err {
		t.Fatalf("Failed hss[0].Split, got error %v", err)
	}
	tc1 := TransportCipherPair{}
	err = hss[1].Split(&tc1)
	if nil != err {
		t.Fatalf("Failed hss[1].Split, got error %v", err)
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

	peers := []cipherPair{{ecs: tc0.Encryptor(), dcs: tc1.Decryptor()}, {ecs: tc1.Encryptor(), dcs: tc0.Decryptor()}}
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

func testSizeLimit(t *testing.T, vec TestVector) {
	// this test checks that first WriteMessage, ReadMessage
	//  * succeed when message size is msgMaxSize
	//  * fail when message size is msgMaxSize + 1
	// this test has been written duplicating testVector
	// it could probably be simpler ...

	var err error
	var cfg Config
	var prologue []byte
	var s, e *Keypair
	var rs, re *PublicKey
	var psks, rpsks [][]byte
	hsOks := [2]HandshakeState{}
	hsFails := [2]HandshakeState{}
	err = cfg.Load(vec.ProtocolName)
	if nil != err {
		t.Fatalf("Failed loading configuration for protocol %s, got error %v", vec.ProtocolName, err)
	}
	if len(vec.InitiatorPrologue) > 0 {
		prologue = []byte(vec.InitiatorPrologue)
	} else {
		prologue = nil
	}
	if len(vec.InitiatorEphemeralKey) > 0 {
		e, err = cfg.CurveAlgo.NewPrivateKey([]byte(vec.InitiatorEphemeralKey))
		if nil != err {
			t.Fatalf("Can not load initiator ephemeral Keypair, got error %v", err)
		}
	} else {
		e = nil
	}
	if len(vec.InitiatorStaticKey) > 0 {
		s, err = cfg.CurveAlgo.NewPrivateKey([]byte(vec.InitiatorStaticKey))
		if nil != err {
			t.Fatalf("Can not load initiator static Keypair, got error %v", err)
		}
	} else {
		s = nil
	}
	if len(vec.InitiatorRemoteEphemeralKey) > 0 {
		re, err = cfg.CurveAlgo.NewPublicKey([]byte(vec.InitiatorRemoteEphemeralKey))
		if nil != err {
			t.Fatalf("Can not load initiator remote ephemeral public key, got error %v", err)
		}
	} else {
		re = nil
	}
	if len(vec.InitiatorRemoteStaticKey) > 0 {
		rs, err = cfg.CurveAlgo.NewPublicKey([]byte(vec.InitiatorRemoteStaticKey))
		if nil != err {
			t.Fatalf("Can not load initiator remote static public key, got error %v", err)
		}
	} else {
		rs = nil
	}
	if len(vec.InitiatorPsks) > 0 {
		psks = make([][]byte, 0, len(vec.InitiatorPsks))
		for _, psk := range vec.InitiatorPsks {
			psks = append(psks, []byte(psk))
		}
	} else {
		psks = nil
	}

	params := HandshakeParams{
		Cfg:                cfg,
		Verifiers:          newVerifiers(),
		Initiator:          true,
		Prologue:           prologue,
		StaticKeypair:      s,
		EphemeralKeypair:   e,
		RemoteStaticKey:    rs,
		RemoteEphemeralKey: re,
		Psks:               psks,
	}
	err = hsOks[0].Initialize(params)
	if nil != err {
		t.Fatalf("hsOks[0]: Failed initiator handshake initialization, got error %v", err)
	}
	params.Verifiers = newVerifiers()
	err = hsFails[0].Initialize(params)
	if nil != err {
		t.Fatalf("hsFails[0]: Failed initiator handshake initialization, got error %v", err)
	}

	if len(vec.ResponderPrologue) > 0 {
		prologue = []byte(vec.ResponderPrologue)
	} else {
		prologue = nil
	}
	if len(vec.ResponderEphemeralKey) > 0 {
		e, err = cfg.CurveAlgo.NewPrivateKey([]byte(vec.ResponderEphemeralKey))
		if nil != err {
			t.Fatalf("Can not load responder ephemeral Keypair, got error %v", err)
		}
	} else {
		e = nil
	}
	if len(vec.ResponderStaticKey) > 0 {
		s, err = cfg.CurveAlgo.NewPrivateKey([]byte(vec.ResponderStaticKey))
		if nil != err {
			t.Fatalf("Can not load responder static Keypair, got error %v", err)
		}
	} else {
		s = nil
	}
	if len(vec.ResponderRemoteEphemeralKey) > 0 {
		re, err = cfg.CurveAlgo.NewPublicKey([]byte(vec.ResponderRemoteEphemeralKey))
		if nil != err {
			t.Fatalf("Can not load responder remote ephemeral public key, got error %v", err)
		}
	} else {
		re = nil
	}
	if len(vec.ResponderRemoteStaticKey) > 0 {
		rs, err = cfg.CurveAlgo.NewPublicKey([]byte(vec.ResponderRemoteStaticKey))
		if nil != err {
			t.Fatalf("Can not load responder remote static public key, got error %v", err)
		}
	} else {
		rs = nil
	}
	if len(vec.ResponderPsks) > 0 {
		rpsks = make([][]byte, 0, len(vec.ResponderPsks))
		for _, psk := range vec.ResponderPsks {
			rpsks = append(rpsks, []byte(psk))
		}
	} else {
		rpsks = nil
	}
	params = HandshakeParams{
		Cfg:                cfg,
		Verifiers:          newVerifiers(),
		Initiator:          false,
		Prologue:           prologue,
		StaticKeypair:      s,
		EphemeralKeypair:   e,
		RemoteStaticKey:    rs,
		RemoteEphemeralKey: re,
		Psks:               rpsks,
	}
	err = hsOks[1].Initialize(params)
	if nil != err {
		t.Fatalf("hsOks[1]: Failed responder handshake initialization, got error %v", err)
	}
	params.Verifiers = newVerifiers()
	err = hsFails[1].Initialize(params)
	if nil != err {
		t.Fatalf("hsFails[1]: Failed responder handshake initialization, got error %v", err)
	}

	mbuf := new(bytes.Buffer)
	pbuf := new(bytes.Buffer)
	var payload, ciphertext []byte
	var writeIdx, readIdx int
	var errWrite, errRead error
	for pos, msg := range vec.Messages[:1] {
		writeIdx = pos % 2
		readIdx = (pos + 1) % 2

		mbuf.Reset()
		pbuf.Reset()

		// we use a payload that results in ciphertext which length is msgMaxSize
		// when using such payload WriteMessage & ReadMessage shall succeed
		payload = []byte(msg.Payload)
		payload = append(payload, make([]byte, msgMaxSize-len(msg.CipherText))...)

		_, errWrite = hsOks[writeIdx].WriteMessage(payload, mbuf)
		if nil != errWrite {
			t.Fatalf("hsOks[%d] : Failed WriteMessage, got error %v", writeIdx, errWrite)
		}
		_, errRead = hsOks[readIdx].ReadMessage(mbuf.Bytes(), pbuf)
		if nil != errRead {
			t.Fatalf("hsOks[%d] : Failed ReadMessage, got error %v", readIdx, errRead)
		}
		ciphertext = mbuf.Bytes()

		// retest with payload & ciphertext containing 1 more byte...
		payload = append(payload, 0xFF)
		ciphertext = append(ciphertext, 0xFF)

		_, errWrite = hsFails[writeIdx].WriteMessage(payload, mbuf)
		if nil == errWrite || !errors.Is(errWrite, errSizeLimit) {
			t.Fatalf("hsFails[%d] : Failed WriteMessage did not error on payload size, got error %v", writeIdx, errWrite)
		}
		_, errRead = hsFails[readIdx].ReadMessage(ciphertext, pbuf)
		if nil == errRead || !errors.Is(errRead, errSizeLimit) {
			t.Fatalf("hsFails[%d] : Failed ReadMessage did not error on ciphertext size, got error %v", readIdx, errRead)
		}
	}
}

// newVerifiers returns a VerifierProvider that accept all static keys
func newVerifiers() *VerifierProvider {
	rv := &VerifierProvider{}
	cv := &AcceptOrRejectAnyKey{} // cv has nil Status hence it accept all keys...
	rv.SetVerifier("s", cv)
	return rv
}
