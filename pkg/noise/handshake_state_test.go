package noise

import (
	"bytes"
	"reflect"
	"testing"
)

func TestHandshakeState(t *testing.T) {
	vectors, err := LoadTestVectors("testdata/snow.txt")
	if nil != err {
		t.Fatalf("Unable to load vectors from snow.txt, got error %v", err)
	}
	for _, vec := range vectors {
		t.Run(vec.ProtocolName, func(t *testing.T) {
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
			var writeIdx, readIdx int
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
					t.Errorf("msg[%d] : Failed writemessage, got error %v", pos, errWrite)
				}
				if !reflect.DeepEqual(mbuf.Bytes(), ciphertext) {
					t.Errorf("msg[%d] : Failed ciphertext check", pos)
				}
				readCompleted, errRead = hss[readIdx].ReadMessage(mbuf.Bytes(), pbuf)
				if nil != errRead {
					t.Errorf("msg[%d] : Failed readmessage, got error %v", pos, errRead)
				}
				if !(writeCompleted == readCompleted) {
					t.Errorf("msg[%d] : readCompleted %v != writeCompleted %v", pos, readCompleted, writeCompleted)
				}
				if !reflect.DeepEqual(payload, pbuf.Bytes()) {
					t.Errorf("msg[%d] : Failed payload check", pos)
				}
				if (nil != errWrite) || (nil != errRead) {
					break
				}
				if writeCompleted && readCompleted {
					break
				}
			}

		})
	}
}
