package ephemsec

import (
	"crypto/ecdh"
	"fmt"
	"reflect"
	"testing"

	"code.kerpass.org/golang/internal/utils"
)

func TestEphemSecVect01(t *testing.T) {
	vectors, err := LoadTestVectors("testdata/ephemsec-x25519-vectors.json")
	if nil != err {
		t.Fatalf("Failed loading ephemsec-x25519-vectors.json, got error %v", err)
	}
	for tn, vec := range vectors {
		t.Run(fmt.Sprintf("[%d]%s", tn, vec.SchemeName), func(t *testing.T) {
			testVector(t, vec)
		})
	}
}

func TestEphemSecVect02(t *testing.T) {
	vectors, err := LoadTestVectors("testdata/ephemsec-vectors.json")
	if nil != err {
		t.Fatalf("Failed loading ephemsec-vectors.json, got error %v", err)
	}
	for tn, vec := range vectors {
		t.Run(fmt.Sprintf("[%d]%s", tn, vec.SchemeName), func(t *testing.T) {
			testVector(t, vec)
		})
	}
}

func testVector(t *testing.T, vec TestVector) {
	scheme, err := NewScheme(vec.SchemeName)
	if nil != err {
		t.Fatalf("Failed scheme parsing, got error %v", err)
	}
	curve := scheme.Curve()
	P := scheme.P()

	// generate initiator secret
	istate := State{
		Context:         []byte(vec.Context),
		Nonce:           []byte(vec.InitiatorNonce),
		Time:            vec.InitiatorTime,
		SynchroHint:     vec.ResponderSynchroHint,
		EphemKey:        mustLoadPrivKey(t, curve, vec.InitiatorEphemKey, "initiator ephem key"),
		StaticKey:       mustLoadPrivKey(t, curve, vec.InitiatorStaticKey, "initiator static key"),
		RemoteEphemKey:  mustLoadPubKey(t, curve, vec.InitiatorRemoteEphemKey, "initiator remote ephem key"),
		RemoteStaticKey: mustLoadPubKey(t, curve, vec.InitiatorRemoteStaticKey, "initiator remote static key"),
		Psk:             []byte(vec.Psk),
	}
	isec, err := istate.EPHEMSEC(scheme, Initiator, nil)
	if nil != err {
		t.Fatalf("Failed Initiator EPHEMSEC, got error %v", err)
	}
	if len(isec) != P {
		t.Errorf("Failed isec size control, %d != %d", len(isec), P)
	}

	// generate responder secret
	rstate := State{
		Context:         []byte(vec.Context),
		Nonce:           []byte(vec.InitiatorNonce),
		Time:            vec.ResponderTime,
		EphemKey:        mustLoadPrivKey(t, curve, vec.ResponderEphemKey, "responder ephem key"),
		StaticKey:       mustLoadPrivKey(t, curve, vec.ResponderStaticKey, "responder static key"),
		RemoteEphemKey:  mustLoadPubKey(t, curve, vec.ResponderRemoteEphemKey, "responder remote ephem key"),
		RemoteStaticKey: mustLoadPubKey(t, curve, vec.ResponderRemoteStaticKey, "responder remote static key"),
		Psk:             []byte(vec.Psk),
	}
	rsec, err := rstate.EPHEMSEC(scheme, Responder, nil)
	if nil != err {
		t.Fatalf("Failed Responder EPHEMSEC, got error %v", err)
	}
	if len(rsec) != P {
		t.Errorf("Failed rsec size control, %d != %d", len(rsec), P)
	}
	if istate.ptime != rstate.ptime {
		t.Logf("---\n[resp] TIME: %d\n[init] TIME: %d\n[init] SYNC: %d", rstate.Time, istate.Time, istate.SynchroHint)
		t.Fatalf("Failed synchronization\n[resp] PTIME: %d\n!=\n[init] PTIME: %d", rstate.ptime, istate.ptime)
	}

	if !reflect.DeepEqual(isec, rsec) {
		t.Fatalf("Failed initiator/responder secret match\nisec: % X\n!=\nrsec: % X", isec, rsec)
	}

	vsec := []byte(vec.SharedSecret)
	if !reflect.DeepEqual(vsec, isec) {
		t.Errorf("Failed vect/local shared secret match\nvsec: % X\n!=\nlsec: % X", vsec, isec)
	}

	vhsec := []byte(vec.HkdfSecret)
	lhsec := istate.ikm[:istate.ikmcursor]
	if !reflect.DeepEqual(vhsec, lhsec) {
		t.Errorf("Failed vect/local HKDF secret match\nvsec: % X\n!=\nlsec: % X", vhsec, lhsec)
	}

	vhsalt := []byte(vec.HkdfSalt)
	lhsalt := istate.context[:istate.contextcursor]
	if !reflect.DeepEqual(vhsalt, lhsalt) {
		t.Errorf("Failed vect/local HKDF salt match\nvsalt: % X\n!=\nlsalt: % X", vhsalt, lhsalt)
	}

	vhinfo := []byte(vec.HkdfInfo)
	lhinfo := istate.info[:istate.infocursor]
	if !reflect.DeepEqual(vhinfo, lhinfo) {
		t.Errorf("Failed vect/local HKDF info match\nvinfo: % X\n!=\nlinfo: % X", vhinfo, lhinfo)
	}
}

func mustLoadPrivKey(t *testing.T, curve ecdh.Curve, srzkey utils.HexBinary, name string) *ecdh.PrivateKey {
	if 0 == len(srzkey) {
		return nil
	}
	privkey, err := curve.NewPrivateKey([]byte(srzkey))
	if nil != err {
		t.Fatalf("Failed loading PrivateKey %s, got error %v", name, err)
	}
	return privkey
}

func mustLoadPubKey(t *testing.T, curve ecdh.Curve, srzkey utils.HexBinary, name string) *ecdh.PublicKey {
	if 0 == len(srzkey) {
		return nil
	}
	pubkey, err := curve.NewPublicKey([]byte(srzkey))
	if nil != err {
		t.Fatalf("Failed loading PublicKey %s, got error %v", name, err)
	}
	return pubkey
}
