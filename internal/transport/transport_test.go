package transport

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"

	"code.kerpass.org/golang/pkg/noise"
)

type Dummy struct {
	X       int    `cbor:"1,keyasint,omitzero"`
	Y       int    `cbor:"2,keyasint,omitzero"`
	Name    string `cbor:"3,keyasint,omitempty"`
	Payload []byte `cbor:"4,keyasint,omitempty"`
}

var ciphers = []string{"null", noise.CIPHER_AES256_GCM, noise.CIPHER_CHACHA20_POLY1305}

func TestTransportLoopbackJSON(t *testing.T) {
	for _, cipher := range ciphers {
		t.Run(fmt.Sprintf("json-%s", cipher), func(t *testing.T) {
			var err error
			msgfmt := "%s -> %s"
			buf := new(bytes.Buffer)
			transport := Transport{R: buf, W: buf, S: JSONSerializer{}}
			if "null" != cipher {
				err = setCipher(&transport, cipher)
				if nil != err {
					t.Fatalf("failed setting cipher, got error %v", err)
				}
				if nil == transport.C {
					t.Fatal("missing transport.C")
				}
				msgfmt = "%s -> % X"
			}

			msg1 := Dummy{X: 10, Y: 20, Name: "Hope", Payload: []byte{1, 2, 3, 4}}
			err = transport.WriteMessage(msg1)
			if nil != err {
				t.Fatalf("failed writing msg1, got error %v", err)
			}
			srzmsg := buf.Bytes()
			t.Logf("msg1 prefix -> % X", srzmsg[:2])
			t.Logf(msgfmt, "msg1", srzmsg[2:])
			t.Logf("len(msg1) -> %d", len(srzmsg))

			msg2 := Dummy{}
			err = transport.ReadMessage(&msg2)
			if nil != err {
				t.Fatalf("failed reading msg2, got error %v", err)
			}

			if !reflect.DeepEqual(msg1, msg2) {
				t.Fatalf("failed recovering msg1\n%+v\n!=\n%+v", msg1, msg2)
			}

			msg3 := RawMsg([]byte{1, 2, 3, 4, 5})
			err = transport.WriteMessage(msg3)
			if nil != err {
				t.Fatalf("failed writing msg3, got error %v", err)
			}
			srzmsg = buf.Bytes()
			t.Logf("msg3 prefix -> % X", srzmsg[:2])
			t.Logf("msg3 -> % X", srzmsg[2:])
			t.Logf("len(msg3) -> %d", len(srzmsg))

			msg4 := RawMsg{}
			err = transport.ReadMessage(&msg4)
			if nil != err {
				t.Fatalf("failed reading msg4, got error %v", err)
			}

			if !reflect.DeepEqual(msg3, msg4) {
				t.Fatalf("failed recovering msg3\n% X\n!=\n% X", msg3, msg4)
			}

		})
	}
}

func TestTransportLoopbackCBOR(t *testing.T) {
	for _, cipher := range ciphers {
		t.Run(fmt.Sprintf("cbor-%s", cipher), func(t *testing.T) {
			var err error
			buf := new(bytes.Buffer)
			transport := Transport{R: buf, W: buf, S: CBORSerializer{}}
			if "null" != cipher {
				err = setCipher(&transport, cipher)
				if nil != err {
					t.Fatalf("failed setting cipher, got error %v", err)
				}
				if nil == transport.C {
					t.Fatal("missing transport.C")
				}
			}

			msg1 := Dummy{X: 10, Y: 20, Name: "Hope", Payload: []byte{1, 2, 3, 4}}
			err = transport.WriteMessage(msg1)
			if nil != err {
				t.Fatalf("failed writing msg1, got error %v", err)
			}
			srzmsg := buf.Bytes()
			t.Logf("msg1 prefix -> % X", srzmsg[:2])
			t.Logf("msg1 -> % X", srzmsg[2:])
			t.Logf("len(msg1) -> %d", len(srzmsg))

			msg2 := Dummy{}
			err = transport.ReadMessage(&msg2)
			if nil != err {
				t.Fatalf("failed reading msg2, got error %v", err)
			}

			if !reflect.DeepEqual(msg1, msg2) {
				t.Fatalf("failed recovering msg1\n%+v\n!=\n%+v", msg1, msg2)
			}

			msg3 := RawMsg([]byte{1, 2, 3, 4, 5})
			err = transport.WriteMessage(msg3)
			if nil != err {
				t.Fatalf("failed writing msg3, got error %v", err)
			}
			srzmsg = buf.Bytes()
			t.Logf("msg3 prefix -> % X", srzmsg[:2])
			t.Logf("msg3 -> % X", srzmsg[2:])
			t.Logf("len(msg3) -> %d", len(srzmsg))

			msg4 := RawMsg{}
			err = transport.ReadMessage(&msg4)
			if nil != err {
				t.Fatalf("failed reading msg4, got error %v", err)
			}

			if !reflect.DeepEqual(msg3, msg4) {
				t.Fatalf("failed recovering msg3\n% X\n!=\n% X", msg3, msg4)
			}

		})
	}
}

func setCipher(transport *Transport, ciphername string) error {
	aeadfactory, err := noise.GetAEADFactory(ciphername)
	if nil != err {
		return wrapError(err, "failed loading AEAD factory")
	}

	cipherkey := make([]byte, 32)
	_, err = rand.Read(cipherkey)
	if nil != err {
		// unreachable according to package doc
		return wrapError(err, "failed rand.Read")
	}

	cipherpair := &noise.TransportCipherPair{}

	ciphers := []*noise.TransportCipher{cipherpair.Encryptor(), cipherpair.Decryptor()}
	for pos, cipher := range ciphers {
		err = cipher.Init(aeadfactory)
		if nil != err {
			return wrapError(err, "[%d] failed cipher.Init", pos)
		}
		err = cipher.InitializeKey(cipherkey)
		if nil != err {
			return wrapError(err, "[%d] failed cipher.InitializeKey", pos)
		}
	}

	transport.C = cipherpair

	return nil
}
