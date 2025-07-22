package transport

import (
	"encoding/json"

	"github.com/fxamacker/cbor/v2"

	"code.kerpass.org/golang/pkg/noise"
)

// Serializer is an interface that provides methods to Marshal/Unmarshal messages.
type Serializer interface {
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
}

// JSONSerializer provides a Serializer that uses json Marshal/Unmarshal
type JSONSerializer struct{}

// Marshal wraps json.Marshal
func (self JSONSerializer) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

// Unmarshal wraps json.Unmarshal
func (self JSONSerializer) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

var _ Serializer = JSONSerializer{}

// CBORSerializer provides a Serializer that uses default cbor Marshal/Unmarshal
type CBORSerializer struct{}

// Marshal wraps cbor.Marshal
func (self CBORSerializer) Marshal(v any) ([]byte, error) {
	return cbor.Marshal(v)
}

// Unmarshal wraps cbor.Unmarshal
func (self CBORSerializer) Unmarshal(data []byte, v any) error {
	return cbor.Unmarshal(data, v)
}

var _ Serializer = CBORSerializer{}

// A SafeSerializer wraps a Serializer ensuring that marshaled/unmarshaled messages are optionally
// validated and encrypted.
type SafeSerializer struct {
	Serializer
	CipherPair *noise.TransportCipherPair
}

// WrapInSafeSerializer returns a SafeSerializer wrapping s.
func WrapInSafeSerializer(s Serializer) SafeSerializer {
	if c, isSafeSerializer := s.(SafeSerializer); isSafeSerializer {
		return c
	}

	return SafeSerializer{Serializer: s}

}

// Marshal performs 3 operations to deliver a serialized v.
// 1. It v has a Check method, Marshal call it and errors in case it returns a non empty error
// 2. It marshals v using the wrapped Serializer and errors in case it case it fails.
// 3. If a CipherPair is set, it uses it to encrypt the marshalled v.
func (self SafeSerializer) Marshal(v any) (srzmsg []byte, err error) {

	// optionally validate v
	if c, validate := v.(Checker); validate {
		err = c.Check()
		if nil != err {
			return nil, wrapError(ValidationError, "invalid, Check returned %v", err)
		}
	}

	// performs actual serialization
	srzmsg, err = self.Serializer.Marshal(v)
	if nil != err {
		return nil, wrapError(SerializationError, "failed marshalling msg, got error %v", err)
	}

	// optionally apply encryption
	if nil != self.CipherPair {
		// we need to apply encryption
		enc := self.CipherPair.Encryptor()
		srzmsg, err = enc.EncryptWithAd(nil, srzmsg)
		if nil != err {
			return nil, wrapError(EncryptionError, "failed encrypting msg, got error %v", err)
		}
	}

	return srzmsg, nil
}

// Unmarshal performs 3 operations to deliver v.
// 1. If a CipherPair is set, it uses it to decrypt data.
// 2. It unmarshals data in v using the wrapped Serializer and errors in case it case it fails.
// 1. It v has a Check method, it calls it and errors in case it returns a non empty error
func (self SafeSerializer) Unmarshal(data []byte, v any) error {
	var err error

	// optionally decrypt data
	if nil != self.CipherPair {
		dec := self.CipherPair.Decryptor()
		data, err = dec.DecryptWithAd(nil, data)
		if nil != err {
			return wrapError(EncryptionError, "failed decrypting message, got error %v", err)
		}
	}

	// performs actual deserialization
	err = self.Serializer.Unmarshal(data, v)
	if nil != err {
		return wrapError(SerializationError, "failed unmarshaling message, got error %v", err)
	}

	// optionally validate v
	if c, checkable := v.(Checker); checkable {
		err = c.Check()
		if nil != err {
			return wrapError(ValidationError, "invalid, Check returned %v", err)
		}
	}

	return nil
}

var _ Serializer = SafeSerializer{}

// Checker is an interface that provides a method Check to validate messages.
type Checker interface {
	Check() error
}
