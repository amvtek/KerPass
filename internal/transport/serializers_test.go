package transport

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// Test structs with JSON and CBOR tags
type SimpleStruct struct {
	Name  string `json:"name" cbor:"1,keyasint"`
	Value int    `json:"value" cbor:"2,keyasint"`
}

type ComplexStruct struct {
	ID      string         `json:"id" cbor:"1,keyasint"`
	Numbers []int          `json:"numbers" cbor:"2,keyasint"`
	Mapping map[string]int `json:"mapping" cbor:"3,keyasint"`
	Nested  *SimpleStruct  `json:"nested" cbor:"4,keyasint"`
}

// Validatable test structs
type ValidatableStruct struct {
	Required string `json:"required" cbor:"1,keyasint"`
	Count    int    `json:"count" cbor:"2,keyasint"`
}

func (v ValidatableStruct) Check() error {
	if v.Required == "" {
		return errors.New("required field is empty")
	}
	if v.Count < 0 {
		return errors.New("count must be non-negative")
	}
	return nil
}

type AlwaysValidStruct struct {
	Data string `json:"data" cbor:"1,keyasint"`
}

func (a AlwaysValidStruct) Check() error {
	return nil // Always valid
}

type AlwaysInvalidStruct struct {
	Data string `json:"data" cbor:"1,keyasint"`
}

func (a AlwaysInvalidStruct) Check() error {
	return errors.New("always invalid")
}

// TestSerializer_JSONSerializer_Marshal tests JSON marshaling
func TestSerializer_JSONSerializer_Marshal(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name: "simple struct",
			input: SimpleStruct{
				Name:  "test",
				Value: 42,
			},
			wantErr: false,
		},
		{
			name: "complex struct",
			input: ComplexStruct{
				ID:      "abc123",
				Numbers: []int{1, 2, 3},
				Mapping: map[string]int{"a": 1, "b": 2},
				Nested: &SimpleStruct{
					Name:  "nested",
					Value: 99,
				},
			},
			wantErr: false,
		},
		{
			name:    "nil value",
			input:   nil,
			wantErr: false,
		},
		{
			name:    "primitive type",
			input:   123,
			wantErr: false,
		},
		{
			name:    "slice",
			input:   []string{"a", "b", "c"},
			wantErr: false,
		},
		{
			name:    "map",
			input:   map[string]interface{}{"key": "value"},
			wantErr: false,
		},
	}

	serializer := JSONSerializer{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := serializer.Marshal(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("JSONSerializer.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(got) == 0 {
				t.Error("JSONSerializer.Marshal() returned empty data")
			}
		})
	}
}

// TestSerializer_JSONSerializer_Unmarshal tests JSON unmarshaling
func TestSerializer_JSONSerializer_Unmarshal(t *testing.T) {
	jsonData := []byte(`{"name":"test","value":42}`)

	var result SimpleStruct
	serializer := JSONSerializer{}

	err := serializer.Unmarshal(jsonData, &result)
	if err != nil {
		t.Errorf("JSONSerializer.Unmarshal() error = %v", err)
		return
	}

	if result.Name != "test" || result.Value != 42 {
		t.Errorf("JSONSerializer.Unmarshal() got = %+v, want Name=test, Value=42", result)
	}
}

// TestSerializer_JSONSerializer_RoundTrip tests JSON round-trip serialization
func TestSerializer_JSONSerializer_RoundTrip(t *testing.T) {
	original := ComplexStruct{
		ID:      "test123",
		Numbers: []int{1, 2, 3, 4, 5},
		Mapping: map[string]int{
			"x": 10,
			"y": 20,
			"z": 30,
		},
		Nested: &SimpleStruct{
			Name:  "nested",
			Value: 100,
		},
	}

	serializer := JSONSerializer{}

	// Marshal
	data, err := serializer.Marshal(original)
	if err != nil {
		t.Fatalf("JSONSerializer.Marshal() error = %v", err)
	}

	// Unmarshal
	var restored ComplexStruct
	err = serializer.Unmarshal(data, &restored)
	if err != nil {
		t.Fatalf("JSONSerializer.Unmarshal() error = %v", err)
	}

	// Compare - using JSON comparison since pointers might be different
	data2, _ := serializer.Marshal(restored)
	if !bytes.Equal(data, data2) {
		t.Error("JSONSerializer round-trip failed: data mismatch")
	}
}

// TestSerializer_CBORSerializer_Default tests default CBOR serializer
func TestSerializer_CBORSerializer_Default(t *testing.T) {
	serializer := NewCBORSerializer()

	original := SimpleStruct{
		Name:  "cbor test",
		Value: 255,
	}

	// Marshal
	data, err := serializer.Marshal(original)
	if err != nil {
		t.Fatalf("CBORSerializer.Marshal() error = %v", err)
	}

	// Verify it's valid CBOR (starts with CBOR header)
	if len(data) == 0 {
		t.Fatal("CBORSerializer.Marshal() returned empty data")
	}

	// Unmarshal
	var restored SimpleStruct
	err = serializer.Unmarshal(data, &restored)
	if err != nil {
		t.Fatalf("CBORSerializer.Unmarshal() error = %v", err)
	}

	if restored.Name != original.Name || restored.Value != original.Value {
		t.Errorf("CBORSerializer round-trip failed: got %+v, want %+v", restored, original)
	}
}

// TestSerializer_CBORSerializer_CTAP2 tests CTAP2 CBOR serializer
func TestSerializer_CBORSerializer_CTAP2(t *testing.T) {
	serializer := NewCTAP2Serializer()

	original := ComplexStruct{
		ID:      "ctap2",
		Numbers: []int{1, 2},
		Mapping: map[string]int{"test": 1},
		Nested: &SimpleStruct{
			Name:  "child",
			Value: 50,
		},
	}

	// Marshal
	data, err := serializer.Marshal(original)
	if err != nil {
		t.Fatalf("CTAP2Serializer.Marshal() error = %v", err)
	}

	// Unmarshal
	var restored ComplexStruct
	err = serializer.Unmarshal(data, &restored)
	if err != nil {
		t.Fatalf("CTAP2Serializer.Unmarshal() error = %v", err)
	}

	// Verify by re-marshaling
	data2, _ := serializer.Marshal(restored)
	if !bytes.Equal(data, data2) {
		t.Error("CTAP2Serializer round-trip failed")
	}
}

// TestSerializer_CBORSerializer_InvalidData tests CBOR with invalid data
func TestSerializer_CBORSerializer_InvalidData(t *testing.T) {
	serializer := NewCBORSerializer()

	// Invalid CBOR data
	invalidData := []byte{0xFF, 0xFF, 0xFF} // Not valid CBOR

	var result SimpleStruct
	err := serializer.Unmarshal(invalidData, &result)
	if err == nil {
		t.Error("CBORSerializer.Unmarshal() should fail with invalid CBOR data")
	}
}

// TestSerializer_SafeSerializer_Marshal_Valid tests SafeSerializer with valid data for all serializers
func TestSerializer_SafeSerializer_Marshal_Valid(t *testing.T) {
	serializers := []struct {
		name       string
		serializer Serializer
	}{
		{"JSON", JSONSerializer{}},
		{"CBOR_Default", NewCBORSerializer()},
		{"CBOR_CTAP2", NewCTAP2Serializer()},
	}

	for _, s := range serializers {
		t.Run(s.name, func(t *testing.T) {
			safeSerializer := WrapInSafeSerializer(s.serializer)

			validData := ValidatableStruct{
				Required: "present",
				Count:    10,
			}

			data, err := safeSerializer.Marshal(validData)
			if err != nil {
				t.Errorf("%s SafeSerializer.Marshal() with valid data error = %v", s.name, err)
				return
			}

			if len(data) == 0 {
				t.Errorf("%s SafeSerializer.Marshal() returned empty data", s.name)
			}
		})
	}
}

// TestSerializer_SafeSerializer_Marshal_Invalid tests SafeSerializer with invalid data for all serializers
func TestSerializer_SafeSerializer_Marshal_Invalid(t *testing.T) {
	serializers := []struct {
		name       string
		serializer Serializer
	}{
		{"JSON", JSONSerializer{}},
		{"CBOR_Default", NewCBORSerializer()},
		{"CBOR_CTAP2", NewCTAP2Serializer()},
	}

	for _, s := range serializers {
		t.Run(s.name, func(t *testing.T) {
			safeSerializer := WrapInSafeSerializer(s.serializer)

			invalidData := ValidatableStruct{
				Required: "", // Empty - should fail validation
				Count:    10,
			}

			_, err := safeSerializer.Marshal(invalidData)
			if err == nil {
				t.Errorf("%s SafeSerializer.Marshal() should fail with invalid data", s.name)
				return
			}

			// Check for ValidationError sentinel
			if !errors.Is(err, ValidationError) {
				t.Errorf("%s SafeSerializer.Marshal() error = %v, want ValidationError", s.name, err)
			}
		})
	}
}

// TestSerializer_SafeSerializer_Unmarshal_Valid tests SafeSerializer unmarshal with valid data for all serializers
func TestSerializer_SafeSerializer_Unmarshal_Valid(t *testing.T) {
	testCases := []struct {
		name       string
		serializer Serializer
		data       []byte
	}{
		{
			name:       "JSON",
			serializer: JSONSerializer{},
			data:       []byte(`{"required":"test","count":5}`),
		},
		{
			name:       "CBOR_Default",
			serializer: NewCBORSerializer(),
			data:       []byte{0xa2, 0x01, 0x64, 0x74, 0x65, 0x73, 0x74, 0x02, 0x05}, // {"required":"test","count":5}
		},
		{
			name:       "CBOR_CTAP2",
			serializer: NewCTAP2Serializer(),
			data:       []byte{0xa2, 0x01, 0x64, 0x74, 0x65, 0x73, 0x74, 0x02, 0x05}, // {"required":"test","count":5}
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			safeSerializer := WrapInSafeSerializer(tc.serializer)

			var result ValidatableStruct
			err := safeSerializer.Unmarshal(tc.data, &result)
			if err != nil {
				t.Errorf("%s SafeSerializer.Unmarshal() with valid data error = %v", tc.name, err)
				return
			}

			if result.Required != "test" || result.Count != 5 {
				t.Errorf("%s SafeSerializer.Unmarshal() got = %+v", tc.name, result)
			}
		})
	}
}

// TestSerializer_SafeSerializer_Unmarshal_Invalid tests SafeSerializer unmarshal with invalid data for all serializers
func TestSerializer_SafeSerializer_Unmarshal_Invalid(t *testing.T) {
	testCases := []struct {
		name       string
		serializer Serializer
		data       []byte
	}{
		{
			name:       "JSON",
			serializer: JSONSerializer{},
			data:       []byte(`{"required":"","count":-1}`),
		},
		{
			name:       "CBOR_Default",
			serializer: NewCBORSerializer(),
			data:       []byte{0xa2, 0x01, 0x60, 0x02, 0x20}, // {"required":"","count":-1}
		},
		{
			name:       "CBOR_CTAP2",
			serializer: NewCTAP2Serializer(),
			data:       []byte{0xa2, 0x01, 0x60, 0x02, 0x20}, // {"required":"","count":-1}
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			safeSerializer := WrapInSafeSerializer(tc.serializer)

			var result ValidatableStruct
			err := safeSerializer.Unmarshal(tc.data, &result)
			if err == nil {
				t.Errorf("%s SafeSerializer.Unmarshal() should fail with invalid data", tc.name)
				return
			}

			// Check for ValidationError sentinel
			if !errors.Is(err, ValidationError) {
				t.Errorf("%s SafeSerializer.Unmarshal() error = %v, want ValidationError", tc.name, err)
			}
		})
	}
}

// TestSerializer_SafeSerializer_Unmarshal_InvalidData tests SafeSerializer with malformed serialized data
func TestSerializer_SafeSerializer_Unmarshal_InvalidData(t *testing.T) {
	testCases := []struct {
		name       string
		serializer Serializer
		data       []byte
	}{
		{
			name:       "JSON_Invalid",
			serializer: JSONSerializer{},
			data:       []byte(`{"invalid": json`), // Invalid JSON
		},
		{
			name:       "CBOR_Default_Invalid",
			serializer: NewCBORSerializer(),
			data:       []byte{0xFF, 0xFF, 0xFF}, // Invalid CBOR
		},
		{
			name:       "CBOR_CTAP2_Invalid",
			serializer: NewCTAP2Serializer(),
			data:       []byte{0xFF, 0xFF, 0xFF}, // Invalid CBOR
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			safeSerializer := WrapInSafeSerializer(tc.serializer)

			var result SimpleStruct
			err := safeSerializer.Unmarshal(tc.data, &result)
			if err == nil {
				t.Errorf("%s SafeSerializer.Unmarshal() should fail with invalid data", tc.name)
				return
			}

			// Check for SerializationError sentinel
			if !errors.Is(err, SerializationError) {
				t.Errorf("%s SafeSerializer.Unmarshal() error = %v, want SerializationError", tc.name, err)
			}
		})
	}
}

// TestSerializer_SafeSerializer_AlwaysInvalid tests SafeSerializer with AlwaysInvalidStruct for all serializers
func TestSerializer_SafeSerializer_AlwaysInvalid(t *testing.T) {
	serializers := []struct {
		name       string
		serializer Serializer
	}{
		{"JSON", JSONSerializer{}},
		{"CBOR_Default", NewCBORSerializer()},
		{"CBOR_CTAP2", NewCTAP2Serializer()},
	}

	for _, s := range serializers {
		t.Run(s.name, func(t *testing.T) {
			safeSerializer := WrapInSafeSerializer(s.serializer)

			invalid := AlwaysInvalidStruct{Data: "test"}

			// Marshal should fail with ValidationError
			_, err := safeSerializer.Marshal(invalid)
			if err == nil {
				t.Errorf("%s SafeSerializer.Marshal() should fail with AlwaysInvalidStruct", s.name)
				return
			}

			if !errors.Is(err, ValidationError) {
				t.Errorf("%s SafeSerializer.Marshal() error = %v, want ValidationError", s.name, err)
			}

			// For unmarshal, we need to serialize first
			var tempData []byte
			rawSerializer := s.serializer
			if ss, ok := rawSerializer.(SafeSerializer); ok {
				rawSerializer = ss.Serializer
			}

			tempData, _ = rawSerializer.Marshal(invalid)

			var result AlwaysInvalidStruct
			err = safeSerializer.Unmarshal(tempData, &result)
			if err == nil {
				t.Errorf("%s SafeSerializer.Unmarshal() should fail with AlwaysInvalidStruct", s.name)
				return
			}

			if !errors.Is(err, ValidationError) {
				t.Errorf("%s SafeSerializer.Unmarshal() error = %v, want ValidationError", s.name, err)
			}
		})
	}
}

// TestSerializer_SafeSerializer_AlwaysValid tests SafeSerializer with AlwaysValidStruct for all serializers
func TestSerializer_SafeSerializer_AlwaysValid(t *testing.T) {
	serializers := []struct {
		name       string
		serializer Serializer
	}{
		{"JSON", JSONSerializer{}},
		{"CBOR_Default", NewCBORSerializer()},
		{"CBOR_CTAP2", NewCTAP2Serializer()},
	}

	for _, s := range serializers {
		t.Run(s.name, func(t *testing.T) {
			safeSerializer := WrapInSafeSerializer(s.serializer)

			valid := AlwaysValidStruct{Data: "always valid"}

			// Marshal should succeed
			data, err := safeSerializer.Marshal(valid)
			if err != nil {
				t.Errorf("%s SafeSerializer.Marshal() with AlwaysValidStruct error = %v", s.name, err)
				return
			}

			if len(data) == 0 {
				t.Errorf("%s SafeSerializer.Marshal() returned empty data", s.name)
			}

			// Unmarshal should succeed
			var result AlwaysValidStruct
			err = safeSerializer.Unmarshal(data, &result)
			if err != nil {
				t.Errorf("%s SafeSerializer.Unmarshal() with AlwaysValidStruct error = %v", s.name, err)
				return
			}

			if result.Data != valid.Data {
				t.Errorf("%s SafeSerializer.Unmarshal() got = %+v, want %+v", s.name, result, valid)
			}
		})
	}
}

// TestSerializer_SafeSerializer_WithoutChecker tests SafeSerializer with non-validatable types for all serializers
func TestSerializer_SafeSerializer_WithoutChecker(t *testing.T) {
	serializers := []struct {
		name       string
		serializer Serializer
	}{
		{"JSON", JSONSerializer{}},
		{"CBOR_Default", NewCBORSerializer()},
		{"CBOR_CTAP2", NewCTAP2Serializer()},
	}

	for _, s := range serializers {
		t.Run(s.name, func(t *testing.T) {
			safeSerializer := WrapInSafeSerializer(s.serializer)

			simpleData := SimpleStruct{
				Name:  "test",
				Value: 100,
			}

			// Should work without Checker interface
			data, err := safeSerializer.Marshal(simpleData)
			if err != nil {
				t.Errorf("%s SafeSerializer.Marshal() without Checker error = %v", s.name, err)
				return
			}

			var restored SimpleStruct
			err = safeSerializer.Unmarshal(data, &restored)
			if err != nil {
				t.Errorf("%s SafeSerializer.Unmarshal() without Checker error = %v", s.name, err)
				return
			}

			if restored.Name != simpleData.Name || restored.Value != simpleData.Value {
				t.Errorf("%s SafeSerializer round-trip failed: got %+v, want %+v", s.name, restored, simpleData)
			}
		})
	}
}

// TestSerializer_SafeSerializer_WrappingChain tests multiple levels of wrapping
func TestSerializer_SafeSerializer_WrappingChain(t *testing.T) {
	serializers := []struct {
		name       string
		serializer Serializer
	}{
		{"JSON", JSONSerializer{}},
		{"CBOR_Default", NewCBORSerializer()},
		{"CBOR_CTAP2", NewCTAP2Serializer()},
	}

	for _, s := range serializers {
		t.Run(s.name, func(t *testing.T) {
			// Wrap once
			wrapped1 := WrapInSafeSerializer(s.serializer)

			// Wrap again (should return same instance)
			wrapped2 := WrapInSafeSerializer(wrapped1)

			if wrapped2 != wrapped1 {
				t.Errorf("%s WrapInSafeSerializer should return same instance when wrapping SafeSerializer", s.name)
			}

			// Verify it still works
			data := SimpleStruct{Name: "test", Value: 42}
			marshaled, err := wrapped2.Marshal(data)
			if err != nil {
				t.Errorf("%s Double-wrapped SafeSerializer.Marshal() error = %v", s.name, err)
				return
			}

			var result SimpleStruct
			err = wrapped2.Unmarshal(marshaled, &result)
			if err != nil {
				t.Errorf("%s Double-wrapped SafeSerializer.Unmarshal() error = %v", s.name, err)
				return
			}
		})
	}
}

// TestSerializer_WrapInSafeSerializer tests the WrapInSafeSerializer function
func TestSerializer_WrapInSafeSerializer(t *testing.T) {
	jsonSerializer := JSONSerializer{}

	// Wrap regular serializer
	wrapped1 := WrapInSafeSerializer(jsonSerializer)
	if wrapped1.Serializer == nil {
		t.Error("WrapInSafeSerializer() should wrap non-SafeSerializer")
	}

	// Wrap already wrapped serializer
	wrapped2 := WrapInSafeSerializer(wrapped1)
	if wrapped2 != wrapped1 {
		t.Error("WrapInSafeSerializer() should return same SafeSerializer when wrapping SafeSerializer")
	}

	// Wrap CBOR serializer
	cborSerializer := NewCBORSerializer()
	wrapped3 := WrapInSafeSerializer(cborSerializer)
	if wrapped3.Serializer == nil {
		t.Error("WrapInSafeSerializer() should wrap CBORSerializer")
	}
}

// TestSerializer_InterfaceCompliance tests interface compliance
func TestSerializer_InterfaceCompliance(t *testing.T) {
	// These assignments should compile if interfaces are implemented
	var _ Serializer = JSONSerializer{}
	var _ Serializer = CBORSerializer{}
	var _ Serializer = SafeSerializer{}

	// Test Checker interface
	var _ Checker = ValidatableStruct{}
	var _ Checker = AlwaysValidStruct{}
	var _ Checker = AlwaysInvalidStruct{}
}

// TestSerializer_ErrorTypes tests error type wrapping
func TestSerializer_ErrorTypes(t *testing.T) {
	serializers := []struct {
		name       string
		serializer Serializer
	}{
		{"JSON", JSONSerializer{}},
		{"CBOR_Default", NewCBORSerializer()},
		{"CBOR_CTAP2", NewCTAP2Serializer()},
	}

	for _, s := range serializers {
		t.Run(s.name, func(t *testing.T) {
			safeSerializer := WrapInSafeSerializer(s.serializer)

			// Test with always invalid struct
			invalid := AlwaysInvalidStruct{Data: "test"}

			_, err := safeSerializer.Marshal(invalid)
			if err == nil {
				t.Errorf("%s SafeSerializer.Marshal() should fail with AlwaysInvalidStruct", s.name)
				return
			}

			// Check for ValidationError sentinel
			if !errors.Is(err, ValidationError) {
				t.Errorf("%s SafeSerializer.Marshal() error = %v, want ValidationError", s.name, err)
			}
		})
	}
}

// TestSerializer_NilAndEmpty tests nil and empty values
func TestSerializer_NilAndEmpty(t *testing.T) {
	jsonSerializer := JSONSerializer{}

	tests := []struct {
		name  string
		value any
	}{
		{"nil", nil},
		{"empty string", ""},
		{"zero int", 0},
		{"empty slice", []string{}},
		{"empty map", map[string]int{}},
		{"nil pointer", (*SimpleStruct)(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := jsonSerializer.Marshal(tt.value)
			if err != nil {
				t.Errorf("JSONSerializer.Marshal() with %s error = %v", tt.name, err)
				return
			}

			// Should produce valid JSON
			if len(data) == 0 && tt.value != nil {
				t.Errorf("JSONSerializer.Marshal() returned empty data for %s", tt.name)
			}
		})
	}
}

// TestSerializer_CBOR_TagHandling tests CBOR tag handling with keyasint
func TestSerializer_CBOR_TagHandling(t *testing.T) {
	serializer := NewCBORSerializer()

	data := SimpleStruct{
		Name:  "tag test",
		Value: 777,
	}

	cborData, err := serializer.Marshal(data)
	if err != nil {
		t.Fatalf("CBORSerializer.Marshal() error = %v", err)
	}

	// For debugging: print hex representation
	t.Logf("CBOR hex: %s", hex.EncodeToString(cborData))

	var restored SimpleStruct
	err = serializer.Unmarshal(cborData, &restored)
	if err != nil {
		t.Fatalf("CBORSerializer.Unmarshal() error = %v", err)
	}

	if restored.Name != data.Name || restored.Value != data.Value {
		t.Errorf("CBOR tag handling failed: got %+v, want %+v", restored, data)
	}
}

// TestSerializer_MixedSerializers tests using different serializers
func TestSerializer_MixedSerializers(t *testing.T) {
	// Create test data
	data := SimpleStruct{
		Name:  "mixed",
		Value: 999,
	}

	// Test JSON
	jsonSerializer := JSONSerializer{}
	jsonData, err := jsonSerializer.Marshal(data)
	if err != nil {
		t.Fatalf("JSONSerializer.Marshal() error = %v", err)
	}

	// Test CBOR
	cborSerializer := NewCBORSerializer()
	cborData, err := cborSerializer.Marshal(data)
	if err != nil {
		t.Fatalf("CBORSerializer.Marshal() error = %v", err)
	}

	// They should be different (different formats)
	if bytes.Equal(jsonData, cborData) {
		t.Error("JSON and CBOR data should be different")
	}

	// Both should unmarshal correctly
	var fromJSON SimpleStruct
	err = jsonSerializer.Unmarshal(jsonData, &fromJSON)
	if err != nil {
		t.Errorf("JSONSerializer.Unmarshal() error = %v", err)
	}

	var fromCBOR SimpleStruct
	err = cborSerializer.Unmarshal(cborData, &fromCBOR)
	if err != nil {
		t.Errorf("CBORSerializer.Unmarshal() error = %v", err)
	}

	if fromJSON != fromCBOR {
		t.Errorf("Data mismatch: JSON=%+v, CBOR=%+v", fromJSON, fromCBOR)
	}
}
