package transport

import (
	"github.com/fxamacker/cbor/v2"
)

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
