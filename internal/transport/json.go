package transport

import (
	"encoding/json"
)

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
