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

func TestSafeSerializerJSON(t *testing.T) {
	for _, cipher := range ciphers {
		t.Run(fmt.Sprintf("json-%s", cipher), func(t *testing.T) {
			var err error
			msgfmt := "%s -> %s"
			sfs := WrapInSafeSerializer(JSONSerializer{})
			if "null" != cipher {
				err = setCipher(&sfs, cipher)
				if nil != err {
					t.Fatalf("failed setting cipher, got error %v", err)
				}
				if nil == sfs.CipherPair {
					t.Fatal("missing sf.CipherPair")
				}
				msgfmt = "%s -> % X"
			}

			msg1 := Dummy{X: 10, Y: 20, Name: "Hope", Payload: []byte{1, 2, 3, 4}}
			srzmsg, err := sfs.Marshal(msg1)
			if nil != err {
				t.Fatalf("failed marshaling msg1, got error %v", err)
			}
			t.Logf(msgfmt, "msg1", srzmsg)
			t.Logf("len(msg1) -> %d", len(srzmsg))

			msg2 := Dummy{}
			err = sfs.Unmarshal(srzmsg, &msg2)
			if nil != err {
				t.Fatalf("failed unmarshaling msg2, got error %v", err)
			}

			if !reflect.DeepEqual(msg1, msg2) {
				t.Fatalf("failed recovering msg1\n%+v\n!=\n%+v", msg1, msg2)
			}
		})
	}
}

func TestSafeSerializerCBOR(t *testing.T) {
	for _, cipher := range ciphers {
		t.Run(fmt.Sprintf("cbor-%s", cipher), func(t *testing.T) {
			var err error
			sfs := WrapInSafeSerializer(CBORSerializer{})
			if "null" != cipher {
				err = setCipher(&sfs, cipher)
				if nil != err {
					t.Fatalf("failed setting cipher, got error %v", err)
				}
				if nil == sfs.CipherPair {
					t.Fatal("missing sf.CipherPair")
				}
			}

			msg1 := Dummy{X: 10, Y: 20, Name: "Hope", Payload: []byte{1, 2, 3, 4}}
			srzmsg, err := sfs.Marshal(msg1)
			if nil != err {
				t.Fatalf("failed marshaling msg1, got error %v", err)
			}
			t.Logf("msg1 -> % X", srzmsg)
			t.Logf("len(msg1) -> %d", len(srzmsg))

			msg2 := Dummy{}
			err = sfs.Unmarshal(srzmsg, &msg2)
			if nil != err {
				t.Fatalf("failed unmarshaling msg2, got error %v", err)
			}

			if !reflect.DeepEqual(msg1, msg2) {
				t.Fatalf("failed recovering msg1\n%+v\n!=\n%+v", msg1, msg2)
			}
		})
	}
}

func TestSafeSerializerCBORFailsUnmarshalSerialization(t *testing.T) {
	buf := new(bytes.Buffer)

	// put invalid data in buf
	data := "12345"
	buf.Write([]byte{0, 0xFF}) // whatever
	buf.Write([]byte(data))

	sfs := WrapInSafeSerializer(CBORSerializer{})

	msg := Dummy{}
	err := sfs.Unmarshal(buf.Bytes(), &msg)
	if !errors.Is(err, SerializationError) {
		t.Errorf("failed not a SerializationError, err is %v", err)
	}
}

func TestSafeSerializerCBORFailUnmarshalValidation(t *testing.T) {
	sfs := WrapInSafeSerializer(CBORSerializer{})

	// step 1: Marshal
	msg := Dummy{X: 10, Y: 20, Name: "Hope", Payload: []byte{1, 2, 3, 4}}
	srzmsg, err := sfs.Marshal(msg)
	if nil != err {
		t.Fatalf("failed Marshal, got error %v", err)
	}

	// step2: Unmarshal
	readmsg := InvalidDummy{} // same fields as Dummy{}
	err = sfs.Unmarshal(srzmsg, &readmsg)
	if !errors.Is(err, ValidationError) {
		t.Errorf("failed not a ValidationError, err is %v", err)
	}
}

func TestSafeSerializerJSONFailMarshalValidation(t *testing.T) {
	sfs := WrapInSafeSerializer(JSONSerializer{})

	msg := Dummy{X: 10, Y: 20, Name: "Hope", Payload: []byte{1, 2, 3, 4}}
	_, err := sfs.Marshal(InvalidDummy{Dummy: &msg})
	if !errors.Is(err, ValidationError) {
		t.Errorf("failed not a ValidationError, err is %v", err)
	}
}

func TestSafeSerializerJSONFailUnmarshalEncryption(t *testing.T) {
	sfs := WrapInSafeSerializer(JSONSerializer{})
	setCipher(&sfs, noise.CIPHER_AES256_GCM)

	// step 1: Marshal
	msg := Dummy{X: 10, Y: 20, Name: "Hope", Payload: []byte{1, 2, 3, 4}}
	srzmsg, err := sfs.Marshal(msg)
	if nil != err {
		t.Fatalf("failed Marshal, got error %v", err)
	}

	// step2: Unmarshal
	readmsg := Dummy{}                       // same fields as Dummy{}
	setCipher(&sfs, noise.CIPHER_AES256_GCM) // change the encryption key...
	err = sfs.Unmarshal(srzmsg, &readmsg)
	if !errors.Is(err, EncryptionError) {
		t.Errorf("failed not an EncryptionError, err is %v", err)
	}
}

func setCipher(sf *SafeSerializer, ciphername string) error {
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

	sf.CipherPair = cipherpair

	return nil
}
