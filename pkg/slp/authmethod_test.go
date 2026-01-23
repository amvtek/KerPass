package slp

import (
	"testing"

	"code.kerpass.org/golang/pkg/ephemsec"
)

// Scheme categories for testing
var (
	// OTP schemes (B=10) - compatible with SlpDirect, SlpCpace
	otpSchemesB10 = []uint16{
		ephemsec.SHA512_X25519_E1S1_T600B10P8,
		ephemsec.SHA512_256_X25519_E1S1_T600B10P8,
		ephemsec.BLAKE2S_X25519_E1S1_T600B10P8,
		ephemsec.BLAKE2B_X25519_E1S1_T600B10P8,
	}

	// OTP schemes (B=32) - compatible with SlpDirect, SlpCpace
	otpSchemesB32 = []uint16{
		ephemsec.SHA512_X25519_E1S1_T600B32P9,
		ephemsec.SHA512_256_X25519_E1S1_T600B32P9,
		ephemsec.BLAKE2S_X25519_E1S1_T600B32P9,
		ephemsec.BLAKE2B_X25519_E1S1_T600B32P9,
	}

	// OTK schemes (B=256, P=33) - compatible with SlpDirect, SlpNXpsk2
	otkSchemes = []uint16{
		ephemsec.SHA512_X25519_E1S1_T1024B256P33,
		ephemsec.SHA512_256_X25519_E1S1_T1024B256P33,
		ephemsec.BLAKE2S_X25519_E1S1_T1024B256P33,
		ephemsec.BLAKE2B_X25519_E1S1_T1024B256P33,
	}
)

func TestAuthMethod_RoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		protocol uint16
		scheme   uint16
	}{
		{"SlpDirect_OTP_B10", SlpDirect, ephemsec.SHA512_X25519_E1S1_T600B10P8},
		{"SlpDirect_OTP_B32", SlpDirect, ephemsec.BLAKE2S_X25519_E1S1_T600B32P9},
		{"SlpDirect_OTK", SlpDirect, ephemsec.SHA512_X25519_E1S1_T1024B256P33},
		{"SlpCpace_OTP_B10", SlpCpace, ephemsec.SHA512_256_X25519_E1S1_T600B10P8},
		{"SlpCpace_OTP_B32", SlpCpace, ephemsec.BLAKE2B_X25519_E1S1_T600B32P9},
		{"SlpNXpsk2_OTK", SlpNXpsk2, ephemsec.BLAKE2B_X25519_E1S1_T1024B256P33},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			original := AuthMethod{Protocol: tc.protocol, Scheme: tc.scheme}

			encoded := original.EncodeToInt()

			var decoded AuthMethod
			err := decoded.ReadInt(encoded)
			if err != nil {
				t.Fatalf("ReadInt failed: %v", err)
			}

			if decoded.Protocol != original.Protocol {
				t.Errorf("Protocol mismatch: got %d, want %d", decoded.Protocol, original.Protocol)
			}
			if decoded.Scheme != original.Scheme {
				t.Errorf("Scheme mismatch: got %d, want %d", decoded.Scheme, original.Scheme)
			}
		})
	}
}

func TestAuthMethod_EncodeToInt_BitLayout(t *testing.T) {
	tests := []struct {
		name     string
		protocol uint16
		scheme   uint16
		want     int
	}{
		{"SlpDirect_0x1111", SlpDirect, 0x1111, 0x01111},
		{"SlpCpace_0x2121", SlpCpace, 0x2121, 0x12121},
		{"SlpNXpsk2_0x3141", SlpNXpsk2, 0x3141, 0x23141},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mtd := AuthMethod{Protocol: tc.protocol, Scheme: tc.scheme}
			got := mtd.EncodeToInt()

			if got != tc.want {
				t.Errorf("EncodeToInt() = 0x%X, want 0x%X", got, tc.want)
			}
		})
	}
}

func TestAuthMethod_ReadInt_IgnoresHighBits(t *testing.T) {
	mtd := AuthMethod{Protocol: SlpDirect, Scheme: ephemsec.SHA512_X25519_E1S1_T600B10P8}
	base := mtd.EncodeToInt()

	// Set bits beyond the lowest 18 that should be masked off
	highBitVariants := []int{
		base | 0x00040000, // bit 18
		base | 0x00080000, // bit 19
		base | 0x7FF00000, // bits 20-30
		base | 0x7FFC0000, // all high bits
	}

	for _, input := range highBitVariants {
		var decoded AuthMethod
		err := decoded.ReadInt(input)
		if err != nil {
			t.Errorf("ReadInt(0x%X) failed: %v", input, err)
			continue
		}

		if decoded.Protocol != mtd.Protocol || decoded.Scheme != mtd.Scheme {
			t.Errorf("ReadInt(0x%X) = {%d, 0x%X}, want {%d, 0x%X}",
				input, decoded.Protocol, decoded.Scheme, mtd.Protocol, mtd.Scheme)
		}
	}
}

func TestAuthMethod_ReadInt_InvalidProtocol(t *testing.T) {
	validScheme := ephemsec.SHA512_X25519_E1S1_T600B10P8

	invalidProtocols := []uint16{3, 4, 5, 0xFFFF}
	for _, proto := range invalidProtocols {
		input := (int(proto&0x3) << 16) | int(validScheme)
		// Only test protocol=3 as others get masked to valid values
		if proto == 3 {
			var mtd AuthMethod
			err := mtd.ReadInt(input)
			if err == nil {
				t.Errorf("ReadInt with protocol=%d should fail", proto)
			}
		}
	}
}

func TestAuthMethod_ReadInt_InvalidScheme(t *testing.T) {
	invalidSchemes := []uint16{0x0000, 0x0001, 0x9999, 0xFFFF}

	for _, scheme := range invalidSchemes {
		input := (int(SlpDirect) << 16) | int(scheme)
		var mtd AuthMethod
		err := mtd.ReadInt(input)
		if err == nil {
			t.Errorf("ReadInt with invalid scheme=0x%X should fail", scheme)
		}
	}
}

func TestAuthMethod_ReadInt_ProtocolSchemeConstraints(t *testing.T) {
	tests := []struct {
		name     string
		protocol uint16
		scheme   uint16
		wantErr  bool
	}{
		// SlpDirect accepts any valid scheme
		{"SlpDirect_OTP_B10_OK", SlpDirect, ephemsec.SHA512_X25519_E1S1_T600B10P8, false},
		{"SlpDirect_OTP_B32_OK", SlpDirect, ephemsec.SHA512_X25519_E1S1_T600B32P9, false},
		{"SlpDirect_OTK_OK", SlpDirect, ephemsec.SHA512_X25519_E1S1_T1024B256P33, false},

		// SlpCpace accepts OTP only (B != 256)
		{"SlpCpace_OTP_B10_OK", SlpCpace, ephemsec.BLAKE2S_X25519_E1S1_T600B10P8, false},
		{"SlpCpace_OTP_B32_OK", SlpCpace, ephemsec.BLAKE2S_X25519_E1S1_T600B32P9, false},
		{"SlpCpace_OTK_Fail", SlpCpace, ephemsec.SHA512_X25519_E1S1_T1024B256P33, true},

		// SlpNXpsk2 accepts OTK only (B=256, P>=33)
		{"SlpNXpsk2_OTK_OK", SlpNXpsk2, ephemsec.BLAKE2B_X25519_E1S1_T1024B256P33, false},
		{"SlpNXpsk2_OTP_B10_Fail", SlpNXpsk2, ephemsec.SHA512_X25519_E1S1_T600B10P8, true},
		{"SlpNXpsk2_OTP_B32_Fail", SlpNXpsk2, ephemsec.SHA512_X25519_E1S1_T600B32P9, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := (int(tc.protocol) << 16) | int(tc.scheme)
			var mtd AuthMethod
			err := mtd.ReadInt(input)

			if tc.wantErr && err == nil {
				t.Errorf("ReadInt should fail for protocol=%d, scheme=0x%X", tc.protocol, tc.scheme)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ReadInt failed unexpectedly: %v", err)
			}
		})
	}
}

func TestAuthMethod_ReadInt_AllValidCombinations(t *testing.T) {
	// SlpDirect with all scheme types
	for _, scheme := range append(append(otpSchemesB10, otpSchemesB32...), otkSchemes...) {
		input := (int(SlpDirect) << 16) | int(scheme)
		var mtd AuthMethod
		if err := mtd.ReadInt(input); err != nil {
			t.Errorf("SlpDirect + scheme 0x%X should be valid: %v", scheme, err)
		}
	}

	// SlpCpace with OTP schemes only
	for _, scheme := range append(otpSchemesB10, otpSchemesB32...) {
		input := (int(SlpCpace) << 16) | int(scheme)
		var mtd AuthMethod
		if err := mtd.ReadInt(input); err != nil {
			t.Errorf("SlpCpace + OTP scheme 0x%X should be valid: %v", scheme, err)
		}
	}

	// SlpNXpsk2 with OTK schemes only
	for _, scheme := range otkSchemes {
		input := (int(SlpNXpsk2) << 16) | int(scheme)
		var mtd AuthMethod
		if err := mtd.ReadInt(input); err != nil {
			t.Errorf("SlpNXpsk2 + OTK scheme 0x%X should be valid: %v", scheme, err)
		}
	}
}

func TestAuthMethod_EncodeToInt_ZeroValues(t *testing.T) {
	// Zero protocol with valid scheme
	mtd := AuthMethod{Protocol: 0, Scheme: ephemsec.SHA512_X25519_E1S1_T600B10P8}
	got := mtd.EncodeToInt()
	want := int(ephemsec.SHA512_X25519_E1S1_T600B10P8)

	if got != want {
		t.Errorf("EncodeToInt() with zero protocol = 0x%X, want 0x%X", got, want)
	}
}
