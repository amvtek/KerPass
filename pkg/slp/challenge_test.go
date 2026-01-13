package slp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"

	"code.kerpass.org/golang/internal/session"
	"code.kerpass.org/golang/pkg/credentials"
	"code.kerpass.org/golang/pkg/ephemsec"
)

// TestChallenge_NewHkdfChalSetter tests creation of HkdfChalSetter
func TestChallenge_NewHkdfChalSetter(t *testing.T) {
	t.Run("ValidHash", func(t *testing.T) {
		setter, err := NewHkdfChalSetter(crypto.SHA256)
		if err != nil {
			t.Fatalf("NewHkdfChalSetter failed: %v", err)
		}

		// Verify the setter can be checked
		if err := setter.Check(); err != nil {
			t.Fatalf("Check failed: %v", err)
		}

		// Verify it implements ChalSetter
		var _ ChalSetter = setter
	})

	t.Run("InvalidHash", func(t *testing.T) {
		// Create an invalid hash ID (max uint + 1 would be 0)
		invalidHash := crypto.Hash(0)

		setter, err := NewHkdfChalSetter(invalidHash)
		if err == nil {
			t.Error("Expected error for invalid hash, got nil")
		}
		if setter != nil {
			t.Error("Expected nil setter for invalid hash")
		}
	})
}

// TestChallenge_HkdfChalSetter_Check tests validation of HkdfChalSetter
func TestChallenge_HkdfChalSetter_Check(t *testing.T) {
	t.Run("ValidSetter", func(t *testing.T) {
		setter, err := NewHkdfChalSetter(crypto.SHA256)
		if err != nil {
			t.Fatalf("Setup failed: %v", err)
		}

		if err := setter.Check(); err != nil {
			t.Fatalf("Check failed on valid setter: %v", err)
		}
	})

	t.Run("TamperedPRK", func(t *testing.T) {
		setter, err := NewHkdfChalSetter(crypto.SHA256)
		if err != nil {
			t.Fatalf("Setup failed: %v", err)
		}

		// Tamper with the PRK (make it wrong size for SHA256)
		setter.prk = []byte("too-short")

		if err := setter.Check(); err == nil {
			t.Error("Expected error for tampered PRK, got nil")
		}
	})
}

// TestChallenge_HkdfChalSetter_SetChal tests challenge generation
func TestChallenge_HkdfChalSetter_SetChal(t *testing.T) {
	setter, err := NewHkdfChalSetter(crypto.SHA256)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Get curve from one of our test schemes
	sch, err := ephemsec.GetScheme(ephemsec.SHA512_X25519_E1S1_T600B32P9)
	if err != nil {
		t.Fatalf("Failed to get scheme: %v", err)
	}
	curve := sch.Curve()

	t.Run("ValidInput", func(t *testing.T) {
		sid := make([]byte, 32)
		rand.Read(sid)

		var chal SessionChal
		err := setter.SetChal(curve, sid, &chal)
		if err != nil {
			t.Fatalf("SetChal failed: %v", err)
		}

		// Verify generated challenge
		if chal.e.PrivateKey == nil {
			t.Error("Ephemeral key not generated")
		}

		if len(chal.n) != 32 {
			t.Errorf("Nonce incorrect length: got %d, want 32", len(chal.n))
		}

		// Verify public key can be derived
		pubKey := chal.e.PrivateKey.PublicKey()
		if pubKey == nil {
			t.Error("Failed to derive public key")
		}
	})

	t.Run("DifferentSIDDifferentOutput", func(t *testing.T) {
		sid1 := make([]byte, 32)
		sid2 := make([]byte, 32)
		rand.Read(sid1)
		rand.Read(sid2)

		// Ensure they're different
		sid2[0] ^= 0xFF

		var chal1, chal2 SessionChal

		err1 := setter.SetChal(curve, sid1, &chal1)
		if err1 != nil {
			t.Fatalf("First SetChal failed: %v", err1)
		}

		err2 := setter.SetChal(curve, sid2, &chal2)
		if err2 != nil {
			t.Fatalf("Second SetChal failed: %v", err2)
		}

		// Keys should be different
		key1Bytes := chal1.e.PrivateKey.Bytes()
		key2Bytes := chal2.e.PrivateKey.Bytes()

		if bytes.Equal(key1Bytes, key2Bytes) {
			t.Error("Different SIDs produced same ephemeral key")
		}

		if bytes.Equal(chal1.n, chal2.n) {
			t.Error("Different SIDs produced same nonce")
		}
	})

	t.Run("NilDestination", func(t *testing.T) {
		sid := make([]byte, 32)
		rand.Read(sid)

		// This should panic or error
		defer func() {
			if r := recover(); r == nil {
				t.Log("SetChal with nil destination handled gracefully")
			}
		}()

		err := setter.SetChal(curve, sid, nil)
		if err != nil {
			// If it returns an error instead of panicking, that's okay
			t.Logf("SetChal returned error (expected): %v", err)
		}
	})
}

// TestChallenge_AuthContext_Check tests validation of AuthContext
func TestChallenge_AuthContext_Check(t *testing.T) {
	t.Run("ValidContext", func(t *testing.T) {
		ctx := AuthContext{
			RealmId:              [32]byte{1},
			AuthMethod:           AuthMethod{Protocol: SlpCpace, Scheme: ephemsec.BLAKE2S_X25519_E1S2_T600B32P9},
			AppContextUrl:        "https://app.example.com/context",
			AuthServerGetChalUrl: "https://auth.example.com/get-challenge",
			AuthServerLoginUrl:   "https://auth.example.com/login",
			AppStartUrl:          "https://app.example.com/start",
		}

		if err := ctx.Check(); err != nil {
			t.Fatalf("Check failed on valid context: %v", err)
		}
	})

	t.Run("InvalidAuthMethod", func(t *testing.T) {
		ctx := AuthContext{
			AuthMethod: AuthMethod{Protocol: 999, Scheme: 999}, // Invalid values
		}

		if err := ctx.Check(); err == nil {
			t.Error("Expected error for invalid auth method, got nil")
		}
	})

	t.Run("InvalidURL", func(t *testing.T) {
		ctx := AuthContext{
			AuthMethod:    AuthMethod{Protocol: SlpCpace, Scheme: ephemsec.BLAKE2S_X25519_E1S2_T600B32P9},
			AppContextUrl: "://invalid-url",
		}

		if err := ctx.Check(); err == nil {
			t.Error("Expected error for invalid URL, got nil")
		}
	})

	t.Run("MissingRequiredFields", func(t *testing.T) {
		ctx := AuthContext{
			AuthMethod: AuthMethod{Protocol: SlpCpace, Scheme: ephemsec.BLAKE2S_X25519_E1S2_T600B32P9},
			// Missing all URLs
		}

		// Should fail on first missing URL check
		if err := ctx.Check(); err == nil {
			t.Error("Expected error for missing URLs, got nil")
		}
	})
}

func realmId(b0 byte) []byte {
	rv := make([]byte, 32)
	rv[0] = b0
	return rv
}

// testFactorySetup creates a test ChallengeFactoryImpl
func testFactorySetup(t *testing.T) *ChallengeFactoryImpl {
	t.Helper()

	// Create session key factory
	skf, err := session.NewSidFactory(5 * time.Minute)
	if err != nil {
		t.Fatalf("Failed to session key factory: %v", err)
	}

	// Create key store
	kst := credentials.NewMemKeyStore()

	// Create challenge setter
	cst, err := NewHkdfChalSetter(crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to create challenge setter: %v", err)
	}

	// Preload server keys for schemes that need them
	ctx := context.Background()

	// For BLAKE2S_X25519_E1S2_T600B32P9
	key1, _ := ecdh.X25519().GenerateKey(rand.Reader)
	cert1 := []byte("cert-for-blake2s-x25519-e1s2")
	serverKey1 := credentials.ServerKey{
		RealmId: realmId(1),
		Kh: credentials.PrivateKeyHandle{
			PrivateKey: key1,
		},
		Certificate: cert1,
	}
	sch, err := ephemsec.GetScheme(ephemsec.BLAKE2S_X25519_E1S2_T600B32P9)
	if nil != err {
		t.Fatalf("failed loading scheme BLAKE2S_X25519_E1S2_T600B32P9, got error %v", err)
	}
	kst.SaveServerKey(ctx, sch.Name(), serverKey1)

	// For BLAKE2B_X25519_E2S2_T1024B256P33
	key2, _ := ecdh.X25519().GenerateKey(rand.Reader)
	cert2 := []byte("cert-for-blake2b-x25519-e2s2")
	serverKey2 := credentials.ServerKey{
		RealmId: realmId(2),
		Kh: credentials.PrivateKeyHandle{
			PrivateKey: key2,
		},
		Certificate: cert2,
	}
	sch, err = ephemsec.GetScheme(ephemsec.BLAKE2B_X25519_E2S2_T1024B256P33)
	if nil != err {
		t.Fatalf("failed loading scheme BLAKE2B_X25519_E2S2_T1024B256P33, got error %v", err)
	}
	kst.SaveServerKey(ctx, sch.Name(), serverKey2)

	// Create configurations
	cfg := []AuthContext{
		{
			RealmId:              [32]byte{1},
			AuthMethod:           AuthMethod{Protocol: SlpDirect, Scheme: ephemsec.SHA512_X25519_E1S1_T600B32P9},
			AppContextUrl:        "https://app1.example.com/context",
			AuthServerGetChalUrl: "https://auth1.example.com/get-challenge",
			AuthServerLoginUrl:   "https://auth1.example.com/login",
			AppStartUrl:          "https://app1.example.com/start",
		},
		{
			RealmId:              [32]byte{1}, // Same realm, different method
			AuthMethod:           AuthMethod{Protocol: SlpCpace, Scheme: ephemsec.BLAKE2S_X25519_E1S2_T600B32P9},
			AppContextUrl:        "https://app1.example.com/context",
			AuthServerGetChalUrl: "https://auth1.example.com/get-challenge",
			AuthServerLoginUrl:   "https://auth1.example.com/login",
			AppStartUrl:          "https://app1.example.com/start",
		},
		{
			RealmId:              [32]byte{2},
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

// TestChallenge_FactoryImpl_GetCardChallenge tests card challenge generation
func TestChallenge_FactoryImpl_GetCardChallenge(t *testing.T) {
	factory := testFactorySetup(t)

	t.Run("E1S1_Scheme_NoStaticKey", func(t *testing.T) {
		req := &CardChallengeRequest{
			RealmId:        realmId(1),
			SelectedMethod: AuthMethod{Protocol: SlpDirect, Scheme: ephemsec.SHA512_X25519_E1S1_T600B32P9},
			AppContextUrl:  "https://app1.example.com/context",
		}

		var dst CardChallenge
		err := factory.GetCardChallenge(req, &dst)
		if err != nil {
			t.Fatalf("GetCardChallenge failed: %v", err)
		}

		// Validate response
		if err := dst.Check(); err != nil {
			t.Fatalf("Generated CardChallenge invalid: %v", err)
		}

		// E1S1 should not have static key
		if !dst.S.IsZero() {
			t.Error("E1S1 scheme should not have static key")
		}

		if len(dst.StaticKeyCert) > 0 {
			t.Error("E1S1 scheme should not have static key certificate")
		}

		if len(dst.SessionId) == 0 {
			t.Error("SessionId should not be empty")
		}

		if dst.E.IsZero() {
			t.Error("Ephemeral key should be set")
		}

		if len(dst.INonce) != 32 {
			t.Errorf("Nonce incorrect length: got %d, want 32", len(dst.INonce))
		}
	})

	t.Run("E1S2_Scheme_WithStaticKey", func(t *testing.T) {
		req := &CardChallengeRequest{
			RealmId:        realmId(1),
			SelectedMethod: AuthMethod{Protocol: SlpCpace, Scheme: ephemsec.BLAKE2S_X25519_E1S2_T600B32P9},
			AppContextUrl:  "https://app1.example.com/context",
		}

		var dst CardChallenge
		err := factory.GetCardChallenge(req, &dst)
		if err != nil {
			t.Fatalf("GetCardChallenge failed: %v", err)
		}

		// Validate response
		if err := dst.Check(); err != nil {
			t.Fatalf("Generated CardChallenge invalid: %v", err)
		}

		// E1S2 should have static key
		if dst.S.IsZero() {
			t.Error("E1S2 scheme should have static key")
		}

		if len(dst.StaticKeyCert) == 0 {
			t.Error("E1S2 scheme should have static key certificate")
		}

		// Verify key compatibility
		if dst.E.Curve() != dst.S.Curve() {
			t.Error("E and S should use the same curve")
		}
	})

	t.Run("E2S2_Scheme_WithStaticKey", func(t *testing.T) {
		req := &CardChallengeRequest{
			RealmId:        realmId(2),
			SelectedMethod: AuthMethod{Protocol: SlpNXpsk2, Scheme: ephemsec.BLAKE2B_X25519_E2S2_T1024B256P33},
			AppContextUrl:  "https://app2.example.com/context",
		}

		var dst CardChallenge
		err := factory.GetCardChallenge(req, &dst)
		if err != nil {
			t.Fatalf("GetCardChallenge failed: %v", err)
		}

		// Validate response
		if err := dst.Check(); err != nil {
			t.Fatalf("Generated CardChallenge invalid: %v", err)
		}

		// E2S2 should have static key
		if dst.S.IsZero() {
			t.Error("E2S2 scheme should have static key")
		}

		if len(dst.StaticKeyCert) == 0 {
			t.Error("E2S2 scheme should have static key certificate")
		}
	})

	t.Run("InvalidRequest_NoMatchingConfig", func(t *testing.T) {
		req := &CardChallengeRequest{
			RealmId:        realmId(255), // Non-existent realm
			SelectedMethod: AuthMethod{Protocol: SlpDirect, Scheme: ephemsec.SHA512_X25519_E1S1_T600B32P9},
			AppContextUrl:  "https://app1.example.com/context",
		}

		var dst CardChallenge
		err := factory.GetCardChallenge(req, &dst)
		if err == nil {
			t.Error("Expected error for non-existent realm, got nil")
		}
	})

	t.Run("InvalidRequest_WrongURL", func(t *testing.T) {
		req := &CardChallengeRequest{
			RealmId:        realmId(1),
			SelectedMethod: AuthMethod{Protocol: SlpDirect, Scheme: ephemsec.SHA512_X25519_E1S1_T600B32P9},
			AppContextUrl:  "https://wrong.example.com/context", // Wrong URL
		}

		var dst CardChallenge
		err := factory.GetCardChallenge(req, &dst)
		if err == nil {
			t.Error("Expected error for wrong AppContextUrl, got nil")
		}
	})

	t.Run("MissingStaticKey", func(t *testing.T) {
		// Create a new config without preloading the key
		skf, err := session.NewSidFactory(3 * time.Minute)
		if nil != err {
			t.Fatalf("failed creating session key factory, got error %v", err)
		}
		kst := credentials.NewMemKeyStore()
		cst, _ := NewHkdfChalSetter(crypto.SHA256)

		cfg := []AuthContext{
			{
				RealmId:              [32]byte{3},
				AuthMethod:           AuthMethod{Protocol: SlpCpace, Scheme: ephemsec.BLAKE2S_X25519_E1S2_T600B32P9},
				AppContextUrl:        "https://app3.example.com/context",
				AuthServerGetChalUrl: "https://auth3.example.com/get-challenge",
				AuthServerLoginUrl:   "https://auth3.example.com/login",
				AppStartUrl:          "https://app3.example.com/start",
			},
		}

		factory := &ChallengeFactoryImpl{
			skf: skf,
			kst: kst,
			cst: cst,
			cfg: cfg,
		}

		req := &CardChallengeRequest{
			RealmId:        realmId(3),
			SelectedMethod: AuthMethod{Protocol: SlpCpace, Scheme: ephemsec.BLAKE2S_X25519_E1S2_T600B32P9},
			AppContextUrl:  "https://app3.example.com/context",
		}

		var dst CardChallenge
		err = factory.GetCardChallenge(req, &dst)
		if err == nil {
			t.Error("Expected error for missing static key, got nil")
		}
	})

	t.Run("NilDestination", func(t *testing.T) {
		req := &CardChallengeRequest{
			RealmId:        realmId(1),
			SelectedMethod: AuthMethod{Protocol: SlpDirect, Scheme: ephemsec.SHA512_X25519_E1S1_T600B32P9},
			AppContextUrl:  "https://app1.example.com/context",
		}

		// This should panic or error
		defer func() {
			if r := recover(); r == nil {
				t.Log("GetCardChallenge with nil destination handled gracefully")
			}
		}()

		err := factory.GetCardChallenge(req, nil)
		if err != nil {
			// If it returns an error instead of panicking, that's okay
			t.Logf("GetCardChallenge returned error (expected): %v", err)
		}
	})
}

// TestChallenge_FactoryImpl_GetAgentAuthContext tests agent auth context retrieval
func TestChallenge_FactoryImpl_GetAgentAuthContext(t *testing.T) {
	factory := testFactorySetup(t)

	// First create a valid session by getting a card challenge
	req := &CardChallengeRequest{
		RealmId:        realmId(1),
		SelectedMethod: AuthMethod{Protocol: SlpCpace, Scheme: ephemsec.BLAKE2S_X25519_E1S2_T600B32P9},
		AppContextUrl:  "https://app1.example.com/context",
	}

	var cardChallenge CardChallenge
	err := factory.GetCardChallenge(req, &cardChallenge)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	t.Run("ValidSessionID", func(t *testing.T) {
		var dst AgentAuthContext
		err := factory.GetAgentAuthContext(cardChallenge.SessionId, &dst)
		if err != nil {
			t.Fatalf("GetAgentAuthContext failed: %v", err)
		}

		// Validate returned context
		if dst.SelectedProtocol != SlpCpace {
			t.Errorf("Incorrect protocol: got %d, want %d", dst.SelectedProtocol, SlpCpace)
		}

		if !bytes.Equal(dst.SessionId, cardChallenge.SessionId) {
			t.Error("Session ID mismatch")
		}

		if dst.AppContextUrl != "https://app1.example.com/context" {
			t.Errorf("Incorrect AppContextUrl: got %s", dst.AppContextUrl)
		}

		if dst.AuthServerGetChalUrl != "https://auth1.example.com/get-challenge" {
			t.Errorf("Incorrect AuthServerGetChalUrl: got %s", dst.AuthServerGetChalUrl)
		}

		if dst.AuthServerLoginUrl != "https://auth1.example.com/login" {
			t.Errorf("Incorrect AuthServerLoginUrl: got %s", dst.AuthServerLoginUrl)
		}

		if dst.AppStartUrl != "https://app1.example.com/start" {
			t.Errorf("Incorrect AppStartUrl: got %s", dst.AppStartUrl)
		}

		// E1S2 should have static key certificate
		if len(dst.StaticKeyCert) == 0 {
			t.Error("E1S2 scheme should have static key certificate in auth context")
		}
	})

	t.Run("DifferentSessionTypes", func(t *testing.T) {
		// Test with E1S1 scheme (no static key)
		reqE1S1 := &CardChallengeRequest{
			RealmId:        realmId(1),
			SelectedMethod: AuthMethod{Protocol: SlpDirect, Scheme: ephemsec.SHA512_X25519_E1S1_T600B32P9},
			AppContextUrl:  "https://app1.example.com/context",
		}

		var challengeE1S1 CardChallenge
		err := factory.GetCardChallenge(reqE1S1, &challengeE1S1)
		if err != nil {
			t.Fatalf("Setup E1S1 failed: %v", err)
		}

		var ctxE1S1 AgentAuthContext
		err = factory.GetAgentAuthContext(challengeE1S1.SessionId, &ctxE1S1)
		if err != nil {
			t.Fatalf("GetAgentAuthContext for E1S1 failed: %v", err)
		}

		// E1S1 should not have static key certificate
		if len(ctxE1S1.StaticKeyCert) > 0 {
			t.Error("E1S1 scheme should not have static key certificate")
		}

		if ctxE1S1.SelectedProtocol != SlpDirect {
			t.Errorf("E1S1 protocol mismatch: got %d, want %d", ctxE1S1.SelectedProtocol, SlpDirect)
		}
	})

	t.Run("InvalidSessionID_Length", func(t *testing.T) {
		var dst AgentAuthContext
		invalidSid := []byte("too-short")

		err := factory.GetAgentAuthContext(invalidSid, &dst)
		if err == nil {
			t.Error("Expected error for invalid session ID length, got nil")
		}
	})

	t.Run("InvalidSessionID_Format", func(t *testing.T) {
		var dst AgentAuthContext

		// Create a session ID with invalid format (wrong size for session.Sid)
		invalidSid := make([]byte, 64) // Wrong size
		rand.Read(invalidSid)

		err := factory.GetAgentAuthContext(invalidSid, &dst)
		if err == nil {
			t.Error("Expected error for invalid session ID format, got nil")
		}
	})

	t.Run("InvalidSessionID_UnknownIndex", func(t *testing.T) {
		// Create a session ID with an out-of-bounds config index
		skf, err := session.NewSidFactory(3 * time.Minute)
		if nil != err {
			t.Fatalf("failed creating session factory, got error %v", err)
		}

		// Create a SID with a large AD (config index)
		// This depends on the SidFactory implementation
		// We'll try to create a SID with AD=999
		sid := skf.New(999)

		var dst AgentAuthContext
		err = factory.GetAgentAuthContext(sid[:], &dst)
		if err == nil {
			t.Error("Expected error for out-of-bounds config index, got nil")
		}
	})

	t.Run("NilDestination", func(t *testing.T) {
		// This should panic or error
		defer func() {
			if r := recover(); r == nil {
				t.Log("GetAgentAuthContext with nil destination handled gracefully")
			}
		}()

		err := factory.GetAgentAuthContext(cardChallenge.SessionId, nil)
		if err != nil {
			// If it returns an error instead of panicking, that's okay
			t.Logf("GetAgentAuthContext returned error (expected): %v", err)
		}
	})
}

// TestChallenge_FactoryImpl_InterfaceCompliance verifies interface implementation
func TestChallenge_FactoryImpl_InterfaceCompliance(t *testing.T) {
	factory := testFactorySetup(t)

	// Verify the factory implements the ChallengeFactory interface
	var _ ChallengeFactory = factory

	// Test interface methods
	req := &CardChallengeRequest{
		RealmId:        realmId(1),
		SelectedMethod: AuthMethod{Protocol: SlpDirect, Scheme: ephemsec.SHA512_X25519_E1S1_T600B32P9},
		AppContextUrl:  "https://app1.example.com/context",
	}

	var challenge CardChallenge
	err := factory.GetCardChallenge(req, &challenge)
	if err != nil {
		t.Fatalf("Interface method GetCardChallenge failed: %v", err)
	}

	var authCtx AgentAuthContext
	err = factory.GetAgentAuthContext(challenge.SessionId, &authCtx)
	if err != nil {
		t.Fatalf("Interface method GetAgentAuthContext failed: %v", err)
	}
}

// TestChallenge_Integration_CompleteFlow tests complete authentication flow
func TestChallenge_Integration_CompleteFlow(t *testing.T) {
	factory := testFactorySetup(t)

	testCases := []struct {
		name     string
		realm    []byte
		protocol uint16
		scheme   uint16
		ctxUrl   string
	}{
		{
			name:     "E1S1_SlpDirect",
			realm:    realmId(1),
			protocol: SlpDirect,
			scheme:   ephemsec.SHA512_X25519_E1S1_T600B32P9,
			ctxUrl:   "https://app1.example.com/context",
		},
		{
			name:     "E1S2_SlpCpace",
			realm:    realmId(1),
			protocol: SlpCpace,
			scheme:   ephemsec.BLAKE2S_X25519_E1S2_T600B32P9,
			ctxUrl:   "https://app1.example.com/context",
		},
		{
			name:     "E2S2_SlpNXpsk2",
			realm:    realmId(2),
			protocol: SlpNXpsk2,
			scheme:   ephemsec.BLAKE2B_X25519_E2S2_T1024B256P33,
			ctxUrl:   "https://app2.example.com/context",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Step 1: Get card challenge
			req := &CardChallengeRequest{
				RealmId:        tc.realm,
				SelectedMethod: AuthMethod{Protocol: tc.protocol, Scheme: tc.scheme},
				AppContextUrl:  tc.ctxUrl,
			}

			var challenge CardChallenge
			err := factory.GetCardChallenge(req, &challenge)
			if err != nil {
				t.Fatalf("[%s] GetCardChallenge failed: %v", tc.name, err)
			}

			// Validate challenge
			if err := challenge.Check(); err != nil {
				t.Fatalf("[%s] Challenge validation failed: %v", tc.name, err)
			}

			// Step 2: Get agent auth context
			var authCtx AgentAuthContext
			err = factory.GetAgentAuthContext(challenge.SessionId, &authCtx)
			if err != nil {
				t.Fatalf("[%s] GetAgentAuthContext failed: %v", tc.name, err)
			}

			// Verify consistency
			if authCtx.SelectedProtocol != tc.protocol {
				t.Errorf("[%s] Protocol mismatch: got %d, want %d",
					tc.name, authCtx.SelectedProtocol, tc.protocol)
			}

			if !bytes.Equal(authCtx.SessionId, challenge.SessionId) {
				t.Errorf("[%s] Session ID mismatch", tc.name)
			}

			// Verify URLs are consistent
			if challenge.AuthServerLoginUrl != authCtx.AuthServerLoginUrl {
				t.Errorf("[%s] AuthServerLoginUrl mismatch", tc.name)
			}

			if challenge.AppStartUrl != authCtx.AppStartUrl {
				t.Errorf("[%s] AppStartUrl mismatch", tc.name)
			}

			// Step 3: Test Sum method on AgentAuthContext
			hash1, err := authCtx.Sum(nil)
			if err != nil {
				t.Fatalf("[%s] AgentAuthContext.Sum failed: %v", tc.name, err)
			}

			if len(hash1) != 32 { // SHA256 size
				t.Errorf("[%s] Hash incorrect length: got %d, want 32", tc.name, len(hash1))
			}

			// Step 4: Test EphemSecContextHash
			realmId := make([]byte, 32)
			copy(realmId, tc.realm)

			agentCtxHash, _ := authCtx.Sum(nil)
			finalHash, err := EphemSecContextHash(realmId, agentCtxHash, nil)
			if err != nil {
				t.Fatalf("[%s] EphemSecContextHash failed: %v", tc.name, err)
			}

			if len(finalHash) != 32 {
				t.Errorf("[%s] Final hash incorrect length: got %d, want 32", tc.name, len(finalHash))
			}
		})
	}
}
