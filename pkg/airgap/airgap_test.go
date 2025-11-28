package airgap

import (
	"crypto/ecdh"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"code.kerpass.org/golang/pkg/credentials"
	"code.kerpass.org/golang/pkg/ephemsec"
)

// Test AgentCardCreate validation
func TestAgentCardCreate_Valid(t *testing.T) {
	tests := []struct {
		name string
		msg  *AgentCardCreate
	}{
		{"minimum_valid", validAgentCardCreate()},
		{"http_scheme", &AgentCardCreate{
			RealmId:         make([]byte, 32),
			AuthorizationId: make([]byte, 32),
			AuthServerUrl:   "http://auth.example.com",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.msg.Check(); err != nil {
				t.Errorf("Check() failed for valid message: %v", err)
			}
		})
	}
}

func TestAgentCardCreate_Invalid(t *testing.T) {
	tests := []struct {
		name string
		msg  *AgentCardCreate
		want string
	}{
		{"realm_too_short", &AgentCardCreate{
			RealmId:         make([]byte, 31),
			AuthorizationId: make([]byte, 32),
			AuthServerUrl:   "https://auth.example.com",
		}, "RealmId"},
		{"auth_id_too_short", &AgentCardCreate{
			RealmId:         make([]byte, 32),
			AuthorizationId: make([]byte, 31),
			AuthServerUrl:   "https://auth.example.com",
		}, "AuthorizationId"},
		{"invalid_url", &AgentCardCreate{
			RealmId:         make([]byte, 32),
			AuthorizationId: make([]byte, 32),
			AuthServerUrl:   "not a url",
		}, "invalid AuthServerUrl"},
		{"unsupported_scheme", &AgentCardCreate{
			RealmId:         make([]byte, 32),
			AuthorizationId: make([]byte, 32),
			AuthServerUrl:   "ftp://auth.example.com",
		}, "scheme"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.Check()
			if err == nil {
				t.Errorf("Check() succeeded for invalid message, wanted error containing %q", tt.want)
			} else if !errorContains(err, tt.want) {
				t.Errorf("Check() error = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

// Test AgentCardChallenge validation
func TestAgentCardChallenge_Valid(t *testing.T) {
	tests := []struct {
		name       string
		schemeCode uint16
	}{
		{"E1S1_pattern", ephemsec.SHA512_X25519_E1S1_T600B10P8},
		{"E1S2_pattern", ephemsec.SHA512_X25519_E1S2_T600B10P8},
		{"E2S2_pattern", ephemsec.SHA512_X25519_E2S2_T600B10P8},
		{"base32_pad", ephemsec.SHA512_X25519_E1S1_T600B32P9},
		{"base256_pad", ephemsec.SHA512_X25519_E1S1_T1024B256P33},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := validAgentCardChallenge(t, tt.schemeCode)
			if err := msg.Check(); err != nil {
				t.Errorf("Check() failed: %v", err)
			}
		})
	}
}

func TestAgentCardChallenge_Invalid(t *testing.T) {
	schemeCode := ephemsec.SHA512_X25519_E1S2_T600B10P8

	tests := []struct {
		name   string
		modify func(*AgentCardChallenge)
		want   string
	}{
		{"realm_too_short", func(m *AgentCardChallenge) {
			m.RealmId = make([]byte, 31)
		}, "RealmId"},
		{"invalid_scheme", func(m *AgentCardChallenge) {
			m.Scheme = 0xFFFF
		}, "Scheme lookup"},
		{"pad_wrong_size", func(m *AgentCardChallenge) {
			m.OtpPad = make([]byte, 9) // scheme.P() is 8
		}, "pad size"},
		{"pad_digit_out_of_range", func(m *AgentCardChallenge) {
			m.OtpPad = make([]byte, 8)
			m.OtpPad[0] = 10 // base is 10, so 10 is out of range
		}, "digit not in [0..base)"},
		{"missing_E_key", func(m *AgentCardChallenge) {
			m.E = zeroPublicKey()
		}, "missing E"},
		{"missing_S_key_E1S2", func(m *AgentCardChallenge) {
			m.S = zeroPublicKey()
		}, "missing S"},
		{"nonce_too_short", func(m *AgentCardChallenge) {
			m.INonce = make([]byte, 15)
		}, "INonce"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := validAgentCardChallenge(t, schemeCode)
			tt.modify(msg)

			err := msg.Check()
			if err == nil {
				t.Errorf("Check() succeeded, wanted error containing %q", tt.want)
			} else if !errorContains(err, tt.want) {
				t.Errorf("Check() error = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

// Test AppOTK validation
func TestAppOTK_Valid(t *testing.T) {
	msg := validAppOTK(t)
	if err := msg.Check(); err != nil {
		t.Errorf("Check() failed for valid AppOTK: %v", err)
	}
}

func TestAppOTK_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*AppOTK)
		want   string
	}{
		{"card_id_too_short", func(m *AppOTK) {
			m.CardId = make([]byte, 31)
		}, "CardId"},
		{"otk_too_short", func(m *AppOTK) {
			m.OTK = make([]byte, 3)
		}, "OTK"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := validAppOTK(t)
			tt.modify(msg)

			err := msg.Check()
			if err == nil {
				t.Errorf("Check() succeeded, wanted error containing %q", tt.want)
			} else if !errorContains(err, tt.want) {
				t.Errorf("Check() error = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

// Test Marshal/Unmarshal round trips
func TestAgentMsg_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		msg  AgentMsg
	}{
		{"AgentCardCreate", validAgentCardCreate()},
		{"AgentCardChallenge_E1S1", validAgentCardChallenge(t, ephemsec.SHA512_X25519_E1S1_T600B10P8)},
		{"AgentCardChallenge_E1S2", validAgentCardChallenge(t, ephemsec.SHA512_X25519_E1S2_T600B10P8)},
		{"AgentCardChallenge_E2S2", validAgentCardChallenge(t, ephemsec.SHA512_X25519_E2S2_T600B10P8)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := MarshalAgentMsg(tt.msg)
			if err != nil {
				t.Fatalf("MarshalAgentMsg() failed: %v", err)
			}

			// Unmarshal
			decoded, err := UnmarshalAgentMsg(data)
			if err != nil {
				t.Fatalf("UnmarshalAgentMsg() failed: %v", err)
			}

			// Verify tag
			if decoded.AgentTag() != tt.msg.AgentTag() {
				t.Errorf("Tag mismatch: got %d, want %d", decoded.AgentTag(), tt.msg.AgentTag())
			}

			// Verify Check() passes
			if checkable, ok := decoded.(checker); ok {
				if err := checkable.Check(); err != nil {
					t.Errorf("Unmarshaled message failed Check(): %v", err)
				}
			}
		})
	}
}

func TestAppMsg_RoundTrip(t *testing.T) {
	msg := validAppOTK(t)
	data, err := MarshalAppMsg(msg)
	if err != nil {
		t.Fatalf("MarshalAppMsg() failed: %v", err)
	}

	decoded, err := UnmarshalAppMsg(data)
	if err != nil {
		t.Fatalf("UnmarshalAppMsg() failed: %v", err)
	}

	if decoded.AppTag() != TagAppOTK {
		t.Errorf("Tag mismatch: got %d, want %d", decoded.AppTag(), TagAppOTK)
	}
}

// Test Unmarshal with invalid/corrupted data
func TestUnmarshalAgentMsg_InvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty_data", []byte{}, "failed reading msg tag"},
		{"invalid_cbor", []byte{0xFF, 0xFF}, "failed reading msg tag"},
		{"unknown_tag", func() []byte {
			data, _ := cbor.Marshal(cbor.Tag{Number: 99, Content: map[int]string{1: "test"}})
			return data
		}(), "invalid AgentMsg tag"},
		{"valid_tag_invalid_content", func() []byte {
			data, _ := cbor.Marshal(cbor.Tag{Number: TagAgentCardCreate, Content: map[int]string{}})
			return data
		}(), "loaded an invalid msg"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalAgentMsg(tt.data)
			if err == nil {
				t.Errorf("UnmarshalAgentMsg() succeeded, wanted error containing %q", tt.want)
			} else if !errorContains(err, tt.want) {
				t.Errorf("Error = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

// Test pad validation with real schemes
func TestCheckPad_WithRealSchemes(t *testing.T) {
	tests := []struct {
		code       uint16
		validPad   []byte
		invalidPad []byte
	}{
		{ephemsec.SHA512_X25519_E1S1_T600B10P8, make([]byte, 8), []byte{10}},
		{ephemsec.SHA512_X25519_E1S1_T600B32P9, make([]byte, 9), []byte{32}},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.code)), func(t *testing.T) {
			scheme, err := ephemsec.GetScheme(tt.code)
			if err != nil {
				t.Fatalf("Failed to get scheme: %v", err)
			}

			// Valid pad should pass
			if err := checkPad(tt.validPad, scheme.B(), scheme.P()); err != nil {
				t.Errorf("checkPad() failed on valid pad: %v", err)
			}

			// Invalid pad should fail
			if err := checkPad(tt.invalidPad, scheme.B(), scheme.P()); err == nil {
				t.Errorf("checkPad() succeeded on invalid pad")
			}
		})
	}
}

// errorContains is a helper to check if an error contains a specific substring.
func errorContains(err error, substr string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), substr)
}

// Helper: Generate valid X25519 public key handle
func generatePublicKey(t *testing.T) credentials.PublicKeyHandle {
	t.Helper()
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	return credentials.PublicKeyHandle{PublicKey: priv.PublicKey()}
}

// Helper: Generate zero-value public key handle for negative tests
func zeroPublicKey() credentials.PublicKeyHandle {
	return credentials.PublicKeyHandle{PublicKey: nil}
}

// Helper: Creates valid AgentCardCreate
func validAgentCardCreate() *AgentCardCreate {
	return &AgentCardCreate{
		RealmId:         make([]byte, 32),
		AuthorizationId: make([]byte, 32),
		AuthServerUrl:   "https://auth.example.com",
	}
}

// Helper: Creates valid AgentCardChallenge based on scheme
func validAgentCardChallenge(t *testing.T, schemeCode uint16) *AgentCardChallenge {
	t.Helper()
	scheme, err := ephemsec.GetScheme(schemeCode)
	if err != nil {
		t.Fatalf("Failed to get scheme %x: %v", schemeCode, err)
	}

	// Determine if S key is required based on key exchange pattern
	pattern := scheme.KeyExchangePattern()
	needSKey := (pattern == "E1S2" || pattern == "E2S2")

	msg := &AgentCardChallenge{
		RealmId: make([]byte, 32),
		Context: make([]byte, 32),
		Scheme:  schemeCode,
		OtpPad:  make([]byte, scheme.P()),
		E:       generatePublicKey(t),
		INonce:  make([]byte, 16),
	}

	if needSKey {
		msg.S = generatePublicKey(t)
	}

	return msg
}

// Helper: Creates valid AppOTK
func validAppOTK(t *testing.T) *AppOTK {
	t.Helper()
	return &AppOTK{
		CardId: make([]byte, 32),
		OTK:    make([]byte, 32), // Must be >= 4 per spec
	}
}
