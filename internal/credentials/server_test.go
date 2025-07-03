package credentials

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestServerKeyJSON(t *testing.T) {
	sk := ServerKey{}

	// set RealmId
	realmId := make([]byte, 32)
	rand.Read(realmId)
	sk.RealmId = realmId

	// set Kh
	curve25519 := ecdh.X25519()
	keypair, err := curve25519.GenerateKey(rand.Reader)
	if nil != err {
		t.Fatalf("failed generating keypair, got error %v", err)
	}
	sk.Kh.PrivateKey = keypair

	// set Certificate
	sk.Certificate = []byte("not used for now")

	srzsk, err := json.Marshal(sk)
	if nil != err {
		t.Fatalf("failed json.Marshal, got error %v", err)
	}
	t.Logf("srzsk -> %s", srzsk)
	t.Logf("len(srzsk) -> %d", len(srzsk))

	dsk := ServerKey{}
	err = json.Unmarshal(srzsk, &dsk)
	if nil != err {
		t.Fatalf("failed json.Unmarshal, got error %v", err)
	}

	if !reflect.DeepEqual(dsk, sk) {
		t.Fatalf("failed unmarshal control\n%+v\n!=\n%+v", dsk, sk)
	}
}

func TestServerKeyCBOR(t *testing.T) {
	sk := ServerKey{}

	// set RealmId
	realmId := make([]byte, 32)
	rand.Read(realmId)
	sk.RealmId = realmId

	// set Kh
	curve25519 := ecdh.X25519()
	keypair, err := curve25519.GenerateKey(rand.Reader)
	if nil != err {
		t.Fatalf("failed generating keypair, got error %v", err)
	}
	sk.Kh.PrivateKey = keypair

	// set Certificate
	sk.Certificate = []byte("not used for now")

	srzsk, err := cbor.Marshal(sk)
	if nil != err {
		t.Fatalf("failed cbor.Marshal, got error %v", err)
	}
	t.Logf("srzsk -> % X", srzsk)
	t.Logf("len(srzsk) -> %d", len(srzsk))

	dsk := ServerKey{}
	err = cbor.Unmarshal(srzsk, &dsk)
	if nil != err {
		t.Fatalf("failed cbor.Unmarshal, got error %v", err)
	}

	if !reflect.DeepEqual(dsk, sk) {
		t.Fatalf("failed unmarshal control\n%+v\n!=\n%+v", dsk, sk)
	}
}

func TestServerCardJSON(t *testing.T) {
	sc := ServerCard{}

	// set RealmId
	realmId := make([]byte, 32)
	rand.Read(realmId)
	sc.RealmId = realmId

	// set CardId
	cardId := make([]byte, 32)
	rand.Read(cardId)
	sc.CardId = cardId

	// set Kh.PublicKey
	curve25519 := ecdh.X25519()
	keypair, err := curve25519.GenerateKey(rand.Reader)
	if nil != err {
		t.Fatalf("failed generating keypair, got error %v", err)
	}
	sc.Kh.PublicKey = keypair.PublicKey()

	// set Psk
	psk := make([]byte, 32)
	rand.Read(psk)
	sc.Psk = psk

	srzsc, err := json.Marshal(sc)
	if nil != err {
		t.Fatalf("failed json.Marshal, got error %v", err)
	}
	t.Logf("srzsc -> %s", srzsc)
	t.Logf("len(srzsc) -> %d", len(srzsc))

	dsc := ServerCard{}
	err = json.Unmarshal(srzsc, &dsc)
	if nil != err {
		t.Fatalf("failed json.Unmarshal, got error %v", err)
	}

	sc.CardId = nil // CardId was not marshaled, hence it shall not be set in dsc
	if !reflect.DeepEqual(dsc, sc) {
		t.Fatalf("failed unmarshal control\n%+v\n!=\n%+v", dsc, sc)
	}

}

func TestServerCardCBOR(t *testing.T) {
	sc := ServerCard{}

	// set RealmId
	realmId := make([]byte, 32)
	rand.Read(realmId)
	sc.RealmId = realmId

	// set CardId
	cardId := make([]byte, 32)
	rand.Read(cardId)
	sc.CardId = cardId

	// set Kh.PublicKey
	curve25519 := ecdh.X25519()
	keypair, err := curve25519.GenerateKey(rand.Reader)
	if nil != err {
		t.Fatalf("failed generating keypair, got error %v", err)
	}
	sc.Kh.PublicKey = keypair.PublicKey()

	// set Psk
	psk := make([]byte, 32)
	rand.Read(psk)
	sc.Psk = psk

	srzsc, err := cbor.Marshal(sc)
	if nil != err {
		t.Fatalf("failed json.Marshal, got error %v", err)
	}
	t.Logf("srzsc -> % X", srzsc)
	t.Logf("len(srzsc) -> %d", len(srzsc))

	dsc := ServerCard{}
	err = cbor.Unmarshal(srzsc, &dsc)
	if nil != err {
		t.Fatalf("failed json.Unmarshal, got error %v", err)
	}

	sc.CardId = nil // CardId was not marshaled, hence it shall not be set in dsc
	if !reflect.DeepEqual(dsc, sc) {
		t.Fatalf("failed unmarshal control\n%+v\n!=\n%+v", dsc, sc)
	}

}
