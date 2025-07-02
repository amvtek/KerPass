package transport

import (
	"bytes"
	"crypto/rand"
	"errors"
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

func (_ Dummy) Check() error {
	return nil
}

type InvalidDummy struct {
	*Dummy
}

func (_ InvalidDummy) Check() error {
	return newError("InvalidDummy is always Invalid")
}

var ciphers = []string{"null", noise.CIPHER_AES256_GCM, noise.CIPHER_CHACHA20_POLY1305}

func TestTransportLoopbackJSON(t *testing.T) {
	for _, cipher := range ciphers {
		t.Run(fmt.Sprintf("json-%s", cipher), func(t *testing.T) {
			var err error
			msgfmt := "%s -> %s"
			buf := new(bytes.Buffer)
			mt := MessageTransport{Transport: RWTransport{R: buf, W: buf}, S: JSONSerializer{}}
			if "null" != cipher {
				err = setCipher(&mt, cipher)
				if nil != err {
					t.Fatalf("failed setting cipher, got error %v", err)
				}
				if nil == mt.C {
					t.Fatal("missing mt.C")
				}
				msgfmt = "%s -> % X"
			}

			msg1 := Dummy{X: 10, Y: 20, Name: "Hope", Payload: []byte{1, 2, 3, 4}}
			err = mt.WriteMessage(msg1)
			if nil != err {
				t.Fatalf("failed writing msg1, got error %v", err)
			}
			srzmsg := buf.Bytes()
			t.Logf("msg1 prefix -> % X", srzmsg[:2])
			t.Logf(msgfmt, "msg1", srzmsg[2:])
			t.Logf("len(msg1) -> %d", len(srzmsg))

			msg2 := Dummy{}
			err = mt.ReadMessage(&msg2)
			if nil != err {
				t.Fatalf("failed reading msg2, got error %v", err)
			}

			if !reflect.DeepEqual(msg1, msg2) {
				t.Fatalf("failed recovering msg1\n%+v\n!=\n%+v", msg1, msg2)
			}

			msg3 := RawMsg([]byte{1, 2, 3, 4, 5})
			err = mt.WriteMessage(msg3)
			if nil != err {
				t.Fatalf("failed writing msg3, got error %v", err)
			}
			srzmsg = buf.Bytes()
			t.Logf("msg3 prefix -> % X", srzmsg[:2])
			t.Logf("msg3 -> % X", srzmsg[2:])
			t.Logf("len(msg3) -> %d", len(srzmsg))

			msg4 := RawMsg{}
			err = mt.ReadMessage(&msg4)
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
			mt := MessageTransport{Transport: RWTransport{R: buf, W: buf}, S: CBORSerializer{}}
			if "null" != cipher {
				err = setCipher(&mt, cipher)
				if nil != err {
					t.Fatalf("failed setting cipher, got error %v", err)
				}
				if nil == mt.C {
					t.Fatal("missing mt.C")
				}
			}

			msg1 := Dummy{X: 10, Y: 20, Name: "Hope", Payload: []byte{1, 2, 3, 4}}
			err = mt.WriteMessage(msg1)
			if nil != err {
				t.Fatalf("failed writing msg1, got error %v", err)
			}
			srzmsg := buf.Bytes()
			t.Logf("msg1 prefix -> % X", srzmsg[:2])
			t.Logf("msg1 -> % X", srzmsg[2:])
			t.Logf("len(msg1) -> %d", len(srzmsg))

			msg2 := Dummy{}
			err = mt.ReadMessage(&msg2)
			if nil != err {
				t.Fatalf("failed reading msg2, got error %v", err)
			}

			if !reflect.DeepEqual(msg1, msg2) {
				t.Fatalf("failed recovering msg1\n%+v\n!=\n%+v", msg1, msg2)
			}

			msg3 := RawMsg([]byte{1, 2, 3, 4, 5})
			err = mt.WriteMessage(msg3)
			if nil != err {
				t.Fatalf("failed writing msg3, got error %v", err)
			}
			srzmsg = buf.Bytes()
			t.Logf("msg3 prefix -> % X", srzmsg[:2])
			t.Logf("msg3 -> % X", srzmsg[2:])
			t.Logf("len(msg3) -> %d", len(srzmsg))

			msg4 := RawMsg{}
			err = mt.ReadMessage(&msg4)
			if nil != err {
				t.Fatalf("failed reading msg4, got error %v", err)
			}

			if !reflect.DeepEqual(msg3, msg4) {
				t.Fatalf("failed recovering msg3\n% X\n!=\n% X", msg3, msg4)
			}

		})
	}
}

func TestTransportFailReadMessageSerialization(t *testing.T) {
	buf := new(bytes.Buffer)

	// put invalid data in buf
	data := "12345"
	buf.Write([]byte{0, 5}) // length prefix
	buf.Write([]byte(data))

	mt := MessageTransport{Transport: RWTransport{R: buf, W: buf}, S: CBORSerializer{}}

	msg := Dummy{}
	err := mt.ReadMessage(&msg)
	if !errors.Is(err, SerializationError) {
		t.Errorf("failed not a SerializationError, err is %v", err)
	}
}

func TestTransportFailReadMessageValidation(t *testing.T) {
	buf := new(bytes.Buffer)
	mt := MessageTransport{Transport: RWTransport{R: buf, W: buf}, S: CBORSerializer{}}

	// step 1: WriteMessage
	msg := Dummy{X: 10, Y: 20, Name: "Hope", Payload: []byte{1, 2, 3, 4}}
	err := mt.WriteMessage(msg)
	if nil != err {
		t.Fatalf("failed WriteMessage, got error %v", err)
	}

	// step2: ReadMessage
	readmsg := InvalidDummy{} // same fields as Dummy{}
	err = mt.ReadMessage(&readmsg)
	if !errors.Is(err, ValidationError) {
		t.Errorf("failed not a ValidationError, err is %v", err)
	}
}

func TestTransportFailWriteMessageValidation(t *testing.T) {
	buf := new(bytes.Buffer)
	mt := MessageTransport{Transport: RWTransport{R: buf, W: buf}, S: CBORSerializer{}}

	msg := Dummy{X: 10, Y: 20, Name: "Hope", Payload: []byte{1, 2, 3, 4}}
	err := mt.WriteMessage(InvalidDummy{Dummy: &msg})
	if !errors.Is(err, ValidationError) {
		t.Errorf("failed not a ValidationError, err is %v", err)
	}
}

func TestTransportFailReadMessageEncryption(t *testing.T) {
	buf := new(bytes.Buffer)
	mt := MessageTransport{Transport: RWTransport{R: buf, W: buf}, S: JSONSerializer{}}
	setCipher(&mt, noise.CIPHER_AES256_GCM)

	// step 1: WriteMessage
	msg := Dummy{X: 10, Y: 20, Name: "Hope", Payload: []byte{1, 2, 3, 4}}
	err := mt.WriteMessage(msg)
	if nil != err {
		t.Fatalf("failed WriteMessage, got error %v", err)
	}

	// step2: ReadMessage
	readmsg := Dummy{}                      // same fields as Dummy{}
	setCipher(&mt, noise.CIPHER_AES256_GCM) // change the encryption key...
	err = mt.ReadMessage(&readmsg)
	if !errors.Is(err, EncryptionError) {
		t.Errorf("failed not an EncryptionError, err is %v", err)
	}
}

func setCipher(mt *MessageTransport, ciphername string) error {
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

	mt.C = cipherpair

	return nil
}
