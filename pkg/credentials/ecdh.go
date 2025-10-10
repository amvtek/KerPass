package credentials

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
)

// PublicKeyHandle "extends" ecdh.PublicKey to support CBOR/JSON marshal/unmarshal.
type PublicKeyHandle struct {
	*ecdh.PublicKey
}

func (self PublicKeyHandle) MarshalBinary() ([]byte, error) {
	if nil == self.PublicKey {
		return nil, nil
	}
	var buf bytes.Buffer
	curveId, err := getCurveId(self.Curve())
	if nil != err {
		return nil, wrapError(err, "failed determining curveId")
	}
	buf.WriteByte(curveId)
	buf.Write(self.Bytes())
	return buf.Bytes(), nil
}

func (self PublicKeyHandle) MarshalJSON() ([]byte, error) {
	pkb, err := self.MarshalBinary()
	if nil != err {
		return nil, err
	}
	return json.Marshal(pkb)
}

func (self *PublicKeyHandle) UnmarshalBinary(data []byte) error {
	if len(data) == 0 {
		return newError("no data")
	}
	curve, err := getCurve(data[0])
	if nil != err {
		return wrapError(err, "can not determine Curve")
	}

	pubkey, err := curve.NewPublicKey(data[1:])
	if nil != err {
		return wrapError(err, "failed deserializing PublicKey")
	}
	self.PublicKey = pubkey

	return nil
}

func (self *PublicKeyHandle) UnmarshalJSON(data []byte) error {
	pkb := []byte{}
	err := json.Unmarshal(data, &pkb)
	if nil != err {
		return err
	}
	return self.UnmarshalBinary(pkb)
}

// PrivateKeyHandle "extends" ecdh.PrivateKey to support CBOR/JSON marshal/unmarshal.
type PrivateKeyHandle struct {
	*ecdh.PrivateKey
}

func (self PrivateKeyHandle) MarshalBinary() ([]byte, error) {
	if nil == self.PrivateKey {
		return nil, nil
	}
	var buf bytes.Buffer
	curveId, err := getCurveId(self.Curve())
	if nil != err {
		return nil, wrapError(err, "failed determining curveId")
	}
	buf.WriteByte(curveId)
	buf.Write(self.Bytes())
	return buf.Bytes(), nil
}

func (self PrivateKeyHandle) MarshalJSON() ([]byte, error) {
	pkb, err := self.MarshalBinary()
	if nil != err {
		return nil, err
	}
	return json.Marshal(pkb)
}

func (self *PrivateKeyHandle) UnmarshalBinary(data []byte) error {
	if len(data) == 0 {
		return newError("no data")
	}
	curve, err := getCurve(data[0])
	if nil != err {
		return wrapError(err, "can not determine Curve")
	}

	pubkey, err := curve.NewPrivateKey(data[1:])
	if nil != err {
		return wrapError(err, "failed deserializing PrivateKey")
	}
	self.PrivateKey = pubkey

	return nil
}

func (self *PrivateKeyHandle) UnmarshalJSON(data []byte) error {
	pkb := []byte{}
	err := json.Unmarshal(data, &pkb)
	if nil != err {
		return err
	}
	return self.UnmarshalBinary(pkb)
}

// getCurveId returns a 1 byte identifier that corresponds to an ecdh.Curve.
func getCurveId(curve ecdh.Curve) (byte, error) {
	switch curve {
	case ecdh.X25519():
		return 1, nil
	case ecdh.P256():
		return 2, nil
	case ecdh.P384():
		return 3, nil
	case ecdh.P521():
		return 4, nil
	default:
		return 0, newError("Unknown Curve")
	}
}

// getCurve returns the Curve that corresponds to curveId.
func getCurve(curveId byte) (ecdh.Curve, error) {
	switch curveId {
	case 1:
		return ecdh.X25519(), nil
	case 2:
		return ecdh.P256(), nil
	case 3:
		return ecdh.P384(), nil
	case 4:
		return ecdh.P521(), nil
	default:
		return nil, newError("Unknown curveId: %d", curveId)
	}
}
