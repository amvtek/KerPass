package transport

import (
	"encoding/json"

	"github.com/fxamacker/cbor/v2"
)

// Serializer defines the interface for message serialization and deserialization.
type Serializer interface {
	// Marshal encodes v into a byte slice.
	Marshal(v any) ([]byte, error)

	// Unmarshal decodes data into v.
	Unmarshal(data []byte, v any) error
}

// JSONSerializer implements Serializer using standard JSON encoding.
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

// CBORSerializer implements Serializer using CBOR encoding with configurable modes.
type CBORSerializer struct {
	cbor.EncMode
	cbor.DecMode
}

var _ Serializer = CBORSerializer{}

// NewCBORSerializer creates a CBORSerializer with default encoding options.
func NewCBORSerializer() Serializer {
	return CBORSerializer{
		EncMode: cborDefaultEncMode,
		DecMode: cborDefaultDecMode,
	}
}

// NewCTAP2Serializer creates a CBORSerializer with CTAP2-compliant encoding options.
func NewCTAP2Serializer() Serializer {
	return CBORSerializer{
		EncMode: cborCTAP2EncMode,
		DecMode: cborDefaultDecMode,
	}
}

// A SafeSerializer wraps a Serializer ensuring that marshaled/unmarshaled messages are validated.
type SafeSerializer struct {
	Serializer
}

// WrapInSafeSerializer wraps s in a SafeSerializer. If s is already a SafeSerializer, it returns it unchanged.
func WrapInSafeSerializer(s Serializer) SafeSerializer {
	if c, isSafeSerializer := s.(SafeSerializer); isSafeSerializer {
		return c
	}

	return SafeSerializer{Serializer: s}

}

// Marshal validates v if it implements Checker, then serializes it using the wrapped Serializer.
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

	return srzmsg, nil
}

// Unmarshal deserializes data into v using the wrapped Serializer, then validates v if it implements Checker.
func (self SafeSerializer) Unmarshal(data []byte, v any) error {
	var err error

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

// Checker defines the validation interface for messages.
type Checker interface {
	// Check validates the message and returns an error if invalid.
	Check() error
}

var cborDefaultEncMode cbor.EncMode
var cborCTAP2EncMode cbor.EncMode
var cborDefaultDecMode cbor.DecMode

func init() {
	var err error
	cborDefaultEncMode, err = cbor.EncOptions{}.EncMode()
	if nil != err {
		panic(wrapError(err, "failed cbor default EncOptions validation"))
	}

	cborCTAP2EncMode, err = cbor.CTAP2EncOptions().EncMode()
	if nil != err {
		panic(wrapError(err, "failed cbor CTAP2 EncOptions validation"))
	}

	cborDefaultDecMode, err = cbor.DecOptions{}.DecMode()
	if nil != err {
		panic(wrapError(err, "failed cbor default DecOptions validation"))
	}
}
