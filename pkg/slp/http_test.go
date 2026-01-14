package slp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"code.kerpass.org/golang/internal/session"
	"code.kerpass.org/golang/internal/transport"
	"code.kerpass.org/golang/pkg/credentials"
	"code.kerpass.org/golang/pkg/ephemsec"
)

// TestHttp_NewCardChallengeEndpoint tests the constructor
func TestHttp_NewCardChallengeEndpoint(t *testing.T) {
	t.Run("ValidFactory", func(t *testing.T) {
		factory := &mockChallengeFactory{}
		endpoint, err := NewCardChallengeEndpoint(factory)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if endpoint == nil {
			t.Fatal("Expected non-nil endpoint")
		}
	})

	t.Run("NilFactory", func(t *testing.T) {
		endpoint, err := NewCardChallengeEndpoint(nil)
		if err == nil {
			t.Fatal("Expected error for nil factory")
		}
		if endpoint != nil {
			t.Fatal("Expected nil endpoint for nil factory")
		}
	})

	t.Run("FactoryWithCheckPasses", func(t *testing.T) {
		factory := &validatableMockFactory{shouldFailCheck: false}
		endpoint, err := NewCardChallengeEndpoint(factory)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if endpoint == nil {
			t.Fatal("Expected non-nil endpoint")
		}
	})

	t.Run("FactoryWithCheckFails", func(t *testing.T) {
		factory := &validatableMockFactory{shouldFailCheck: true}
		endpoint, err := NewCardChallengeEndpoint(factory)
		if err == nil {
			t.Fatal("Expected error for factory that fails Check()")
		}
		if endpoint != nil {
			t.Fatal("Expected nil endpoint for invalid factory")
		}
	})
}

// TestHttp_MethodValidation tests HTTP method validation
func TestHttp_MethodValidation(t *testing.T) {
	factory := &mockChallengeFactory{}
	endpoint, _ := NewCardChallengeEndpoint(factory)

	testCases := []struct {
		method     string
		wantStatus int
	}{
		{"GET", http.StatusMethodNotAllowed},
		{"PUT", http.StatusMethodNotAllowed},
		{"DELETE", http.StatusMethodNotAllowed},
		{"PATCH", http.StatusMethodNotAllowed},
		{"HEAD", http.StatusMethodNotAllowed},
		{"OPTIONS", http.StatusMethodNotAllowed},
	}

	for _, tc := range testCases {
		t.Run(tc.method, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/", nil)
			w := httptest.NewRecorder()

			endpoint.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("Method %s: got status %d, want %d", tc.method, w.Code, tc.wantStatus)
			}
		})
	}
}

// TestHttp_RequestBodyValidation tests request body handling
func TestHttp_RequestBodyValidation(t *testing.T) {
	factory := &mockChallengeFactory{}
	endpoint, _ := NewCardChallengeEndpoint(factory)

	t.Run("EmptyBody", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte{}))
		w := httptest.NewRecorder()

		endpoint.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Empty body: got status %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("InvalidCBOR", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte{0x01, 0x02, 0x03}))
		w := httptest.NewRecorder()

		endpoint.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Invalid CBOR: got status %d, want %d", w.Code, http.StatusBadRequest)
		}
		// Check it's not CBOR response
		ct := w.Header().Get("Content-Type")
		if ct == "application/cbor" {
			t.Error("Error response should not be CBOR")
		}
	})

	t.Run("ValidCBORInvalidRequest", func(t *testing.T) {
		// Create an invalid request that will fail Check()
		// We need to create a request with invalid data
		// Let's create one with a missing RealmId
		invalidReq := CardChallengeRequest{
			SelectedMethod: AuthMethod{Protocol: SlpDirect, Scheme: ephemsec.SHA512_X25519_E1S1_T600B32P9},
			AppContextUrl:  "https://example.com",
			// Missing RealmId - will fail Check()
		}

		// Use raw serializer to bypass Check()
		rawSrz := transport.NewCTAP2Serializer()
		data, err := rawSrz.Marshal(&invalidReq)
		if err != nil {
			t.Fatalf("Failed to marshal invalid request: %v", err)
		}

		req := httptest.NewRequest("POST", "/", bytes.NewReader(data))
		w := httptest.NewRecorder()

		endpoint.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Invalid request: got status %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}

// TestHttp_FactoryErrorHandling tests factory error propagation
func TestHttp_FactoryErrorHandling(t *testing.T) {
	t.Run("FactoryReturnsError", func(t *testing.T) {
		factory := &mockChallengeFactory{shouldFail: true}
		endpoint, _ := NewCardChallengeEndpoint(factory)

		// Create a valid request
		validReq := CardChallengeRequest{
			RealmId:        make([]byte, 32),
			SelectedMethod: AuthMethod{Protocol: SlpDirect, Scheme: ephemsec.SHA512_X25519_E1S1_T600B32P9},
			AppContextUrl:  "https://example.com",
		}
		copy(validReq.RealmId, "test-realm-id-12345678901234567890")

		data, err := ctapSrz.Marshal(&validReq)
		if err != nil {
			t.Fatalf("Failed to marshal valid request: %v", err)
		}

		req := httptest.NewRequest("POST", "/", bytes.NewReader(data))
		w := httptest.NewRecorder()

		endpoint.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Factory error: got status %d, want %d", w.Code, http.StatusInternalServerError)
		}
	})

	t.Run("FactorySuccess", func(t *testing.T) {
		// Create a factory that returns a valid challenge
		factory := &mockChallengeFactory{
			challenge: &CardChallenge{
				SessionId:          []byte("test-session-id"),
				E:                  credentials.PublicKeyHandle{PublicKey: testPublicKey(t)},
				INonce:             make([]byte, 32),
				AuthServerLoginUrl: "https://auth.example.com/login",
				AppStartUrl:        "https://app.example.com/start",
			},
		}

		endpoint, _ := NewCardChallengeEndpoint(factory)

		// Create a valid request
		validReq := CardChallengeRequest{
			RealmId:        make([]byte, 32),
			SelectedMethod: AuthMethod{Protocol: SlpDirect, Scheme: ephemsec.SHA512_X25519_E1S1_T600B32P9},
			AppContextUrl:  "https://example.com",
		}
		copy(validReq.RealmId, "test-realm-id-12345678901234567890")

		data, err := ctapSrz.Marshal(&validReq)
		if err != nil {
			t.Fatalf("Failed to marshal valid request: %v", err)
		}

		req := httptest.NewRequest("POST", "/", bytes.NewReader(data))
		w := httptest.NewRecorder()

		endpoint.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Success case: got status %d, want %d", w.Code, http.StatusOK)
		}

		// Check Content-Type
		ct := w.Header().Get("Content-Type")
		if ct != "application/cbor" {
			t.Errorf("Success case: got Content-Type %s, want application/cbor", ct)
		}

		// Verify response can be unmarshaled
		var resp CardChallenge
		if err := ctapSrz.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
		}

		// Verify response passes Check
		if err := resp.Check(); err != nil {
			t.Errorf("Response fails Check: %v", err)
		}
	})
}

// TestHttp_CompleteValidFlow tests a complete valid request-response flow
func TestHttp_CompleteValidFlow(t *testing.T) {
	// Use a real factory for integration test
	factory := createTestFactory(t)
	endpoint, err := NewCardChallengeEndpoint(factory)
	if err != nil {
		t.Fatalf("Failed to create endpoint: %v", err)
	}

	// Create a valid request
	validReq := CardChallengeRequest{
		RealmId:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		SelectedMethod: AuthMethod{Protocol: SlpDirect, Scheme: ephemsec.SHA512_X25519_E1S1_T600B32P9},
		AppContextUrl:  "https://app1.example.com/context",
	}

	data, err := ctapSrz.Marshal(&validReq)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest("POST", "/", bytes.NewReader(data))
	w := httptest.NewRecorder()

	endpoint.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Got status %d, want %d. Body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	// Verify response
	var resp CardChallenge
	if err := ctapSrz.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if err := resp.Check(); err != nil {
		t.Fatalf("Response validation failed: %v", err)
	}

	if len(resp.SessionId) == 0 {
		t.Error("SessionId should not be empty")
	}

	if resp.E.IsZero() {
		t.Error("Ephemeral key should be set")
	}

	if len(resp.INonce) != 32 {
		t.Errorf("Nonce length: got %d, want 32", len(resp.INonce))
	}
}

// TestHttp_DifferentProtocols tests different authentication protocols
func TestHttp_DifferentProtocols(t *testing.T) {
	factory := createTestFactory(t)
	endpoint, _ := NewCardChallengeEndpoint(factory)

	testCases := []struct {
		name     string
		protocol uint16
		scheme   uint16
	}{
		{"SlpDirect", SlpDirect, ephemsec.SHA512_X25519_E1S1_T600B32P9},
		{"SlpCpace", SlpCpace, ephemsec.BLAKE2S_X25519_E1S2_T600B32P9},
		{"SlpNXpsk2", SlpNXpsk2, ephemsec.BLAKE2B_X25519_E2S2_T1024B256P33},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validReq := CardChallengeRequest{
				RealmId:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
				SelectedMethod: AuthMethod{Protocol: tc.protocol, Scheme: tc.scheme},
				AppContextUrl:  "https://app1.example.com/context",
			}

			// For E2S2 scheme, use realm 2
			if tc.scheme == ephemsec.BLAKE2B_X25519_E2S2_T1024B256P33 {
				validReq.RealmId[0] = 2
				validReq.AppContextUrl = "https://app2.example.com/context"
			}

			data, err := ctapSrz.Marshal(&validReq)
			if err != nil {
				t.Fatalf("Failed to marshal request: %v", err)
			}

			req := httptest.NewRequest("POST", "/", bytes.NewReader(data))
			w := httptest.NewRecorder()

			endpoint.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("%s: got status %d, want %d", tc.name, w.Code, http.StatusOK)
			}

			var resp CardChallenge
			if err := ctapSrz.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("%s: failed to unmarshal response: %v", tc.name, err)
			}

			if err := resp.Check(); err != nil {
				t.Fatalf("%s: response validation failed: %v", tc.name, err)
			}
		})
	}
}

// TestHttp_ErrorResponseFormat tests error response formatting
func TestHttp_ErrorResponseFormat(t *testing.T) {
	factory := &mockChallengeFactory{shouldFail: true}
	endpoint, _ := NewCardChallengeEndpoint(factory)

	// Create a valid request
	validReq := CardChallengeRequest{
		RealmId:        make([]byte, 32),
		SelectedMethod: AuthMethod{Protocol: SlpDirect, Scheme: ephemsec.SHA512_X25519_E1S1_T600B32P9},
		AppContextUrl:  "https://example.com",
	}
	copy(validReq.RealmId, "test-realm-id-12345678901234567890")

	data, err := ctapSrz.Marshal(&validReq)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest("POST", "/", bytes.NewReader(data))
	w := httptest.NewRecorder()

	endpoint.ServeHTTP(w, req)

	// Verify error response is plain text, not CBOR
	ct := w.Header().Get("Content-Type")
	if ct == "application/cbor" {
		t.Error("Error response should not be CBOR")
	}

	// Body should contain error message
	body := w.Body.String()
	if len(body) == 0 {
		t.Error("Error response should have non-empty body")
	}
}

// TestHttp_MalformedRequestEdgeCases tests edge cases for malformed requests
func TestHttp_MalformedRequestEdgeCases(t *testing.T) {
	factory := &mockChallengeFactory{}
	endpoint, _ := NewCardChallengeEndpoint(factory)

	t.Run("VeryLargeBody", func(t *testing.T) {
		// Create a very large body (1MB)
		largeBody := make([]byte, 1024*1024)
		for i := range largeBody {
			largeBody[i] = byte(i % 256)
		}

		req := httptest.NewRequest("POST", "/", bytes.NewReader(largeBody))
		w := httptest.NewRecorder()

		endpoint.ServeHTTP(w, req)

		// Should return Bad Request, not crash
		if w.Code != http.StatusBadRequest && w.Code != http.StatusInternalServerError {
			t.Errorf("Large body: got status %d, expected 400 or 500", w.Code)
		}
	})

	t.Run("BodyReadError", func(t *testing.T) {
		// Create a reader that returns an error on Read
		errorReader := &errorReader{err: io.ErrUnexpectedEOF}
		req := httptest.NewRequest("POST", "/", errorReader)
		w := httptest.NewRecorder()

		endpoint.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Read error: got status %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}

// Helper functions and mock implementations

type mockChallengeFactory struct {
	shouldFail bool
	challenge  *CardChallenge
}

func (m *mockChallengeFactory) GetCardChallenge(req *CardChallengeRequest, dst *CardChallenge) error {
	if m.shouldFail {
		return newError("mock factory error")
	}
	if m.challenge != nil {
		*dst = *m.challenge
	}
	return nil
}

func (m *mockChallengeFactory) GetAgentAuthContext(sid []byte, dst *AgentAuthContext) error {
	return nil
}

type validatableMockFactory struct {
	mockChallengeFactory
	shouldFailCheck bool
}

func (v *validatableMockFactory) Check() error {
	if v.shouldFailCheck {
		return newError("factory check failed")
	}
	return nil
}

type errorReader struct {
	err error
}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, e.err
}

func testPublicKey(t *testing.T) *ecdh.PublicKey {
	t.Helper()
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	return priv.PublicKey()
}

func createTestFactory(t *testing.T) *ChallengeFactoryImpl {
	t.Helper()

	// Create session key factory
	skf, err := session.NewSidFactory(5 * time.Minute)
	if err != nil {
		t.Fatalf("Failed to create session key factory: %v", err)
	}

	// Create key store
	kst := credentials.NewMemKeyStore()

	// Create challenge setter
	cst, err := NewHkdfChalSetter(crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to create challenge setter: %v", err)
	}

	// Preload server keys
	ctx := context.Background()

	// For BLAKE2S_X25519_E1S2_T600B32P9
	sch1, err := ephemsec.GetScheme(ephemsec.BLAKE2S_X25519_E1S2_T600B32P9)
	if err != nil {
		t.Fatalf("Failed to get scheme: %v", err)
	}
	key1, _ := sch1.Curve().GenerateKey(rand.Reader)
	serverKey1 := credentials.ServerKey{
		RealmId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Kh: credentials.PrivateKeyHandle{
			PrivateKey: key1,
		},
		Certificate: []byte("cert1"),
	}
	kst.SaveServerKey(ctx, sch1.Name(), serverKey1)

	// For BLAKE2B_X25519_E2S2_T1024B256P33
	sch2, err := ephemsec.GetScheme(ephemsec.BLAKE2B_X25519_E2S2_T1024B256P33)
	if err != nil {
		t.Fatalf("Failed to get scheme: %v", err)
	}
	key2, _ := sch2.Curve().GenerateKey(rand.Reader)
	serverKey2 := credentials.ServerKey{
		RealmId: []byte{2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Kh: credentials.PrivateKeyHandle{
			PrivateKey: key2,
		},
		Certificate: []byte("cert2"),
	}
	kst.SaveServerKey(ctx, sch2.Name(), serverKey2)

	// Create configurations
	cfg := []AuthContext{
		{
			RealmId:              [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			AuthMethod:           AuthMethod{Protocol: SlpDirect, Scheme: ephemsec.SHA512_X25519_E1S1_T600B32P9},
			AppContextUrl:        "https://app1.example.com/context",
			AuthServerGetChalUrl: "https://auth1.example.com/get-challenge",
			AuthServerLoginUrl:   "https://auth1.example.com/login",
			AppStartUrl:          "https://app1.example.com/start",
		},
		{
			RealmId:              [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			AuthMethod:           AuthMethod{Protocol: SlpCpace, Scheme: ephemsec.BLAKE2S_X25519_E1S2_T600B32P9},
			AppContextUrl:        "https://app1.example.com/context",
			AuthServerGetChalUrl: "https://auth1.example.com/get-challenge",
			AuthServerLoginUrl:   "https://auth1.example.com/login",
			AppStartUrl:          "https://app1.example.com/start",
		},
		{
			RealmId:              [32]byte{2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			AuthMethod:           AuthMethod{Protocol: SlpNXpsk2, Scheme: ephemsec.BLAKE2B_X25519_E2S2_T1024B256P33},
			AppContextUrl:        "https://app2.example.com/context",
			AuthServerGetChalUrl: "https://auth2.example.com/get-challenge",
			AuthServerLoginUrl:   "https://auth2.example.com/login",
			AppStartUrl:          "https://app2.example.com/start",
		},
	}

	return &ChallengeFactoryImpl{
		skf: skf,
		kst: kst,
		cst: cst,
		cfg: cfg,
	}
}
