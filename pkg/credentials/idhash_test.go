package credentials

import (
	"encoding/json"
	"strings"
	"testing"
)

// NewIdHasher ---------------------------------------------------------------

// TestIdHash_NewIdHasher_EmptySeedUsesDefault verifies that passing an empty
// seed does not error and silently falls back to the built-in default seed.
func TestIdHash_NewIdHasher_EmptySeedUsesDefault(t *testing.T) {
	idh, err := NewIdHasher(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idh == nil {
		t.Fatal("expected non-nil IdHasher")
	}
}

// TestIdHash_NewIdHasher_DifferentSeedsProduceDifferentSalts confirms that two
// IdHashers built from distinct seeds are not equivalent (different internal salts).
func TestIdHash_NewIdHasher_DifferentSeedsProduceDifferentSalts(t *testing.T) {
	idh1 := newTestHasher(t, "seed-alpha")
	idh2 := newTestHasher(t, "seed-beta")

	// A visible difference manifests as different IdToken outputs for the same input.
	realm := makeRealm(0x01)
	tok1, err := idh1.IdTokenOfUserId(realm, "alice", nil)
	if err != nil {
		t.Fatalf("IdTokenOfUserId: %v", err)
	}
	tok2, err := idh2.IdTokenOfUserId(realm, "alice", nil)
	if err != nil {
		t.Fatalf("IdTokenOfUserId: %v", err)
	}
	if string(tok1) == string(tok2) {
		t.Error("expected different tokens for different seeds")
	}
}

// TestIdHash_NewIdHasher_SameSeedIsDeterministic verifies that two IdHashers
// built from the same seed produce identical derivations.
func TestIdHash_NewIdHasher_SameSeedIsDeterministic(t *testing.T) {
	idh1 := newTestHasher(t, "stable-seed")
	idh2 := newTestHasher(t, "stable-seed")

	tok1, _ := idh1.IdTokenOfUserId(makeRealm(0x02), "bob", nil)
	tok2, _ := idh2.IdTokenOfUserId(makeRealm(0x02), "bob", nil)
	if string(tok1) != string(tok2) {
		t.Error("expected identical tokens across IdHashers sharing the same seed")
	}
}

// IdTokenOfUserId ---------------------------------------------------------------

// TestIdHash_IdTokenOfUserId_InvalidRealmLength checks that realm IDs that are
// not exactly 32 bytes are rejected.
func TestIdHash_IdTokenOfUserId_InvalidRealmLength(t *testing.T) {
	idh := newTestHasher(t, "seed")
	for _, badLen := range []int{0, 16, 31, 33, 64} {
		realm := make([]byte, badLen)
		_, err := idh.IdTokenOfUserId(realm, "alice", nil)
		if err == nil {
			t.Errorf("expected error for realm len=%d", badLen)
		}
	}
}

// TestIdHash_IdTokenOfUserId_EmptyUserIdRejected verifies the empty-string guard.
func TestIdHash_IdTokenOfUserId_EmptyUserIdRejected(t *testing.T) {
	idh := newTestHasher(t, "seed")
	_, err := idh.IdTokenOfUserId(makeRealm(0x01), "", nil)
	if err == nil {
		t.Error("expected error for empty userId")
	}
}

// TestIdHash_IdTokenOfUserId_TooLongUserIdRejected verifies the 255-byte length guard.
func TestIdHash_IdTokenOfUserId_TooLongUserIdRejected(t *testing.T) {
	idh := newTestHasher(t, "seed")
	longId := strings.Repeat("x", 256)
	_, err := idh.IdTokenOfUserId(makeRealm(0x01), longId, nil)
	if err == nil {
		t.Error("expected error for userId len=256")
	}
}

// TestIdHash_IdTokenOfUserId_Deterministic checks that the same (realm, userId)
// always produces the same 32-byte token.
func TestIdHash_IdTokenOfUserId_Deterministic(t *testing.T) {
	idh := newTestHasher(t, "seed")
	realm := makeRealm(0xAB)

	tok1, err := idh.IdTokenOfUserId(realm, "carol", nil)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	tok2, err := idh.IdTokenOfUserId(realm, "carol", nil)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(tok1) != string(tok2) {
		t.Error("expected identical tokens across calls")
	}
	if len(tok1) != 32 {
		t.Errorf("expected 32-byte token, got %d", len(tok1))
	}
}

// TestIdHash_IdTokenOfUserId_DifferentUserIdsDifferentTokens confirms domain
// separation between distinct user IDs within the same realm.
func TestIdHash_IdTokenOfUserId_DifferentUserIdsDifferentTokens(t *testing.T) {
	idh := newTestHasher(t, "seed")
	realm := makeRealm(0x01)

	tok1, _ := idh.IdTokenOfUserId(realm, "dave", nil)
	tok2, _ := idh.IdTokenOfUserId(realm, "eve", nil)
	if string(tok1) == string(tok2) {
		t.Error("different userIds must produce different tokens")
	}
}

// TestIdHash_IdTokenOfUserId_DifferentRealmsDifferentTokens confirms that the
// realm is bound into the derivation — same userId, different realm → different token.
func TestIdHash_IdTokenOfUserId_DifferentRealmsDifferentTokens(t *testing.T) {
	idh := newTestHasher(t, "seed")

	tok1, _ := idh.IdTokenOfUserId(makeRealm(0x01), "frank", nil)
	tok2, _ := idh.IdTokenOfUserId(makeRealm(0x02), "frank", nil)
	if string(tok1) == string(tok2) {
		t.Error("different realms must produce different tokens")
	}
}

// DeriveFromCardAccess — ServerCardAccess variant: IdToken ----------------------
//
// IdToken is a 32-byte client-held credential presented directly by the client.
// The server derives both a lookup key (IdKey) and a StorageKey from it.

// TestIdHash_DeriveFromCardAccess_IdToken_Deterministic verifies that presenting
// the same IdToken twice yields identical AccessKeys.
func TestIdHash_DeriveFromCardAccess_IdToken_Deterministic(t *testing.T) {
	idh := newTestHasher(t, "seed")
	tok := IdToken(makeToken(0x11))

	var aks1, aks2 AccessKeys
	if err := idh.DeriveFromCardAccess(tok, &aks1); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := aks1.Check(); err != nil {
		t.Fatalf("aks1.Check: %v", err)
	}
	if err := idh.DeriveFromCardAccess(tok, &aks2); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if err := aks2.Check(); err != nil {
		t.Fatalf("aks2.Check: %v", err)
	}
	if aks1 != aks2 {
		t.Error("expected identical AccessKeys for same IdToken")
	}
}

// TestIdHash_DeriveFromCardAccess_IdToken_IdKeyDiffersFromStorageKey confirms
// that the two HKDF expand labels ("IdToken/IdKey" vs "IdToken/StorageKey")
// produce distinct, non-zero outputs — they must never collide.
func TestIdHash_DeriveFromCardAccess_IdToken_IdKeyDiffersFromStorageKey(t *testing.T) {
	idh := newTestHasher(t, "seed")

	var aks AccessKeys
	if err := idh.DeriveFromCardAccess(IdToken(makeToken(0x22)), &aks); err != nil {
		t.Fatalf("DeriveFromCardAccess: %v", err)
	}
	if err := aks.Check(); err != nil {
		t.Fatalf("aks.Check: %v", err)
	}
	if aks.IdKey == aks.StorageKey {
		t.Error("IdKey and StorageKey must be distinct")
	}
}

// TestIdHash_DeriveFromCardAccess_IdToken_DifferentTokensDifferentKeys ensures
// that two different IdTokens produce unrelated AccessKeys.
func TestIdHash_DeriveFromCardAccess_IdToken_DifferentTokensDifferentKeys(t *testing.T) {
	idh := newTestHasher(t, "seed")

	var aks1, aks2 AccessKeys
	idh.DeriveFromCardAccess(IdToken(makeToken(0x33)), &aks1)
	idh.DeriveFromCardAccess(IdToken(makeToken(0x44)), &aks2)
	if aks1.IdKey == aks2.IdKey {
		t.Error("different IdTokens must produce different IdKey")
	}
}

// TestIdHash_DeriveFromCardAccess_IdToken_InvalidLengthRejected verifies that
// an IdToken that is not exactly 32 bytes is rejected by Check() before derivation.
func TestIdHash_DeriveFromCardAccess_IdToken_InvalidLengthRejected(t *testing.T) {
	idh := newTestHasher(t, "seed")

	var aks AccessKeys
	err := idh.DeriveFromCardAccess(IdToken(make([]byte, 16)), &aks)
	if err == nil {
		t.Error("expected error for IdToken with len != 32")
	}
}

// DeriveFromCardAccess — ServerCardAccess variant: OtpId -----------------------
//
// OtpId carries a (realm, username) pair. The server resolves it by internally
// deriving an IdToken via IdTokenOfUserId, then proceeding identically to the
// IdToken path. Both variants must therefore produce the same AccessKeys for
// equivalent inputs — that equivalence is the key invariant tested here.

// TestIdHash_DeriveFromCardAccess_OtpId_Deterministic verifies that the same
// (realm, username) pair always yields the same AccessKeys.
func TestIdHash_DeriveFromCardAccess_OtpId_Deterministic(t *testing.T) {
	idh := newTestHasher(t, "seed")
	otp := OtpId{Realm: makeRealm(0x01), Username: "grace"}

	var aks1, aks2 AccessKeys
	if err := idh.DeriveFromCardAccess(otp, &aks1); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := aks1.Check(); err != nil {
		t.Fatalf("aks1.Check: %v", err)
	}
	if err := idh.DeriveFromCardAccess(otp, &aks2); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if err := aks2.Check(); err != nil {
		t.Fatalf("aks2.Check: %v", err)
	}
	if aks1 != aks2 {
		t.Error("expected identical AccessKeys for same OtpId")
	}
}

// TestIdHash_DeriveFromCardAccess_OtpId_MatchesDerivedIdToken is the key
// cross-variant invariant: OtpId{realm, username} must produce the same
// AccessKeys as manually calling IdTokenOfUserId(realm, username) and then
// passing the result as an IdToken.
func TestIdHash_DeriveFromCardAccess_OtpId_MatchesDerivedIdToken(t *testing.T) {
	idh := newTestHasher(t, "seed")
	realm := makeRealm(0x01)

	// Path A: OtpId variant.
	var aksOtp AccessKeys
	if err := idh.DeriveFromCardAccess(OtpId{Realm: realm, Username: "grace"}, &aksOtp); err != nil {
		t.Fatalf("DeriveFromCardAccess(OtpId): %v", err)
	}
	if err := aksOtp.Check(); err != nil {
		t.Fatalf("aksOtp.Check: %v", err)
	}

	// Path B: manual IdToken variant.
	rawTok, err := idh.IdTokenOfUserId(realm, "grace", nil)
	if err != nil {
		t.Fatalf("IdTokenOfUserId: %v", err)
	}
	var aksIdToken AccessKeys
	if err := idh.DeriveFromCardAccess(IdToken(rawTok), &aksIdToken); err != nil {
		t.Fatalf("DeriveFromCardAccess(IdToken): %v", err)
	}
	if err := aksIdToken.Check(); err != nil {
		t.Fatalf("aksIdToken.Check: %v", err)
	}

	if aksOtp != aksIdToken {
		t.Error("OtpId and equivalent IdToken must produce identical AccessKeys")
	}
}

// TestIdHash_DeriveFromCardAccess_OtpId_DifferentUsernamesDifferentKeys confirms
// that distinct usernames within the same realm resolve to different AccessKeys.
func TestIdHash_DeriveFromCardAccess_OtpId_DifferentUsernamesDifferentKeys(t *testing.T) {
	idh := newTestHasher(t, "seed")
	realm := makeRealm(0x01)

	var aks1, aks2 AccessKeys
	idh.DeriveFromCardAccess(OtpId{Realm: realm, Username: "henry"}, &aks1)
	idh.DeriveFromCardAccess(OtpId{Realm: realm, Username: "iris"}, &aks2)
	if aks1.IdKey == aks2.IdKey {
		t.Error("different usernames must produce different IdKey")
	}
}

// TestIdHash_DeriveFromCardAccess_OtpId_DifferentRealmsDifferentKeys confirms
// that the same username in different realms resolves to different AccessKeys.
func TestIdHash_DeriveFromCardAccess_OtpId_DifferentRealmsDifferentKeys(t *testing.T) {
	idh := newTestHasher(t, "seed")

	var aks1, aks2 AccessKeys
	idh.DeriveFromCardAccess(OtpId{Realm: makeRealm(0x01), Username: "jack"}, &aks1)
	idh.DeriveFromCardAccess(OtpId{Realm: makeRealm(0x02), Username: "jack"}, &aks2)
	if aks1.IdKey == aks2.IdKey {
		t.Error("different realms must produce different IdKey")
	}
}

// DeriveFromEnrollAccess ---------------------------------------------------------------

// TestIdHash_DeriveFromEnrollAccess_Deterministic verifies that the same
// EnrollToken always yields the same AccessKeys.
func TestIdHash_DeriveFromEnrollAccess_Deterministic(t *testing.T) {
	idh := newTestHasher(t, "seed")
	et := EnrollToken(makeToken(0x55))

	var aks1, aks2 AccessKeys
	if err := idh.DeriveFromEnrollAccess(et, &aks1); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := aks1.Check(); err != nil {
		t.Fatalf("aks1.Check: %v", err)
	}
	if err := idh.DeriveFromEnrollAccess(et, &aks2); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if err := aks2.Check(); err != nil {
		t.Fatalf("aks2.Check: %v", err)
	}
	if aks1 != aks2 {
		t.Error("expected identical AccessKeys for same EnrollToken")
	}
}

// TestIdHash_DeriveFromEnrollAccess_IdKeyDiffersFromStorageKey verifies that the
// two HKDF expand labels ("EnrollToken/IdKey" vs "EnrollToken/StorageKey")
// produce distinct, non-zero outputs.
func TestIdHash_DeriveFromEnrollAccess_IdKeyDiffersFromStorageKey(t *testing.T) {
	idh := newTestHasher(t, "seed")

	var aks AccessKeys
	if err := idh.DeriveFromEnrollAccess(EnrollToken(makeToken(0x66)), &aks); err != nil {
		t.Fatalf("DeriveFromEnrollAccess: %v", err)
	}
	if err := aks.Check(); err != nil {
		t.Fatalf("aks.Check: %v", err)
	}
	if aks.IdKey == aks.StorageKey {
		t.Error("IdKey and StorageKey must be distinct")
	}
}

// TestIdHash_DeriveFromEnrollAccess_InvalidLengthRejected verifies that an
// EnrollToken that is not exactly 32 bytes is rejected before derivation.
func TestIdHash_DeriveFromEnrollAccess_InvalidLengthRejected(t *testing.T) {
	idh := newTestHasher(t, "seed")

	var aks AccessKeys
	err := idh.DeriveFromEnrollAccess(EnrollToken(make([]byte, 16)), &aks)
	if err == nil {
		t.Error("expected error for EnrollToken with len != 32")
	}
}

// Salt isolation ---------------------------------------------------------------
//
// The three internal salts (userId, idToken, enrollToken) must all be distinct.
// We verify this indirectly: feeding the same raw 32-byte value into the card
// and enroll paths must produce different IdKeys, because the salts differ.

// TestIdHash_SaltIsolation_CardAndEnrollPathsAreSeparated verifies that the card
// and enroll derivation paths produce different IdKeys for the same raw token bytes.
func TestIdHash_SaltIsolation_CardAndEnrollPathsAreSeparated(t *testing.T) {
	idh := newTestHasher(t, "seed")
	raw := makeToken(0x77)

	var aksCard, aksEnroll AccessKeys
	idh.DeriveFromCardAccess(IdToken(raw), &aksCard)
	idh.DeriveFromEnrollAccess(EnrollToken(raw), &aksEnroll)

	if aksCard.IdKey == aksEnroll.IdKey {
		t.Error("card and enroll salts must differ: same raw token must not yield the same IdKey")
	}
}

// NewCardIdGenerator ---------------------------------------------------------------

// TestIdHash_NewCardIdGenerator_NilFactoryNilHasherIsValid verifies that the
// combination (no factory, no hasher) is accepted — it selects the random IdToken path.
func TestIdHash_NewCardIdGenerator_NilFactoryNilHasherIsValid(t *testing.T) {
	gen, err := NewCardIdGenerator(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gen == nil {
		t.Fatal("expected non-nil CardIdGenerator")
	}
}

// TestIdHash_NewCardIdGenerator_FactoryWithoutHasherIsRejected verifies that
// providing a UserIdFactory without an IdHasher is an error — the factory output
// feeds into HKDF, which requires the hasher.
func TestIdHash_NewCardIdGenerator_FactoryWithoutHasherIsRejected(t *testing.T) {
	_, err := NewCardIdGenerator(makeUserIdFactory(), nil)
	if err == nil {
		t.Error("expected error when UserIdFactory is set but IdHasher is nil")
	}
}

// GenCardIds — nil receiver (legacy path) ---------------------------------------------------------------
//
// When the CardIdGenerator itself is nil, GenCardIds falls back to a legacy
// behaviour: ClientUserId is empty and ServerCardId is a plain copy of the
// randomly-generated ClientIdToken (no HKDF derivation).

// TestIdHash_GenCardIds_NilReceiver_ClientUserIdIsEmpty verifies the legacy nil-receiver
// path leaves ClientUserId empty.
func TestIdHash_GenCardIds_NilReceiver_ClientUserIdIsEmpty(t *testing.T) {
	var gen *CardIdGenerator

	var ref CardRef
	if err := gen.GenCardIds(makeRealm(0x01), nil, &ref); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.ClientUserId != "" {
		t.Errorf("expected empty ClientUserId, got %q", ref.ClientUserId)
	}
}

// TestIdHash_GenCardIds_NilReceiver_ServerCardIdIsDirectCopyOfClientIdToken verifies
// that in the legacy path ServerCardId is copied directly from ClientIdToken, not
// HKDF-derived.
func TestIdHash_GenCardIds_NilReceiver_ServerCardIdIsDirectCopyOfClientIdToken(t *testing.T) {
	var gen *CardIdGenerator

	var ref CardRef
	if err := gen.GenCardIds(makeRealm(0x01), nil, &ref); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.ServerCardId != ref.ClientIdToken {
		t.Error("expected ServerCardId == ClientIdToken for nil receiver (legacy copy)")
	}
}

// TestIdHash_GenCardIds_NilReceiver_ClientIdTokenIsRandom verifies that two
// calls produce different ClientIdTokens (random generation).
func TestIdHash_GenCardIds_NilReceiver_ClientIdTokenIsRandom(t *testing.T) {
	var gen *CardIdGenerator

	var ref1, ref2 CardRef
	gen.GenCardIds(makeRealm(0x01), nil, &ref1)
	gen.GenCardIds(makeRealm(0x01), nil, &ref2)
	if ref1.ClientIdToken == ref2.ClientIdToken {
		t.Error("random ClientIdTokens must not collide across calls")
	}
}

// GenCardIds — without UserIdFactory (random IdToken path) ---------------------------------------------------------------
//
// When a CardIdGenerator is constructed without a UserIdFactory, ClientIdToken
// is randomly generated and ServerCardId is HKDF-derived from it (not a plain copy).

// TestIdHash_GenCardIds_NoFactory_ClientUserIdIsEmpty verifies that without a
// factory no UserId is set.
func TestIdHash_GenCardIds_NoFactory_ClientUserIdIsEmpty(t *testing.T) {
	idh := newTestHasher(t, "seed")
	gen, _ := NewCardIdGenerator(nil, idh)

	var ref CardRef
	if err := gen.GenCardIds(makeRealm(0x01), nil, &ref); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.ClientUserId != "" {
		t.Errorf("expected empty ClientUserId, got %q", ref.ClientUserId)
	}
}

// TestIdHash_GenCardIds_NoFactory_ClientIdTokenIsRandom verifies that two calls
// produce different ClientIdTokens.
func TestIdHash_GenCardIds_NoFactory_ClientIdTokenIsRandom(t *testing.T) {
	idh := newTestHasher(t, "seed")
	gen, _ := NewCardIdGenerator(nil, idh)

	var err error
	var ref1, ref2 CardRef
	gen.GenCardIds(makeRealm(0x01), nil, &ref1)
	err = ref1.Check()
	if nil != err {
		t.Fatalf("failed ref1 Check, got error %v", err)
	}
	gen.GenCardIds(makeRealm(0x01), nil, &ref2)
	err = ref2.Check()
	if nil != err {
		t.Fatalf("failed ref2 Check, got error %v", err)
	}
	if ref1.ClientIdToken == ref2.ClientIdToken {
		t.Error("random ClientIdTokens must not collide across calls")
	}
}

// TestIdHash_GenCardIds_NoFactory_ServerCardIdIsHKDFDerived verifies that
// ServerCardId is not a plain copy of ClientIdToken — it is HKDF-derived.
func TestIdHash_GenCardIds_NoFactory_ServerCardIdIsHKDFDerived(t *testing.T) {
	idh := newTestHasher(t, "seed")
	gen, _ := NewCardIdGenerator(nil, idh)

	var ref CardRef
	if err := gen.GenCardIds(makeRealm(0x01), nil, &ref); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := ref.Check(); err != nil {
		t.Fatalf("failed ref.Check, got error %v", err)
	}
	if ref.ServerCardId == ref.ClientIdToken {
		t.Error("ServerCardId must be HKDF-derived, not a plain copy of ClientIdToken")
	}
}

// TestIdHash_GenCardIds_NoFactory_ServerCardIdIsNonZero verifies that the
// HKDF-derived ServerCardId is not the zero value.
func TestIdHash_GenCardIds_NoFactory_ServerCardIdIsNonZero(t *testing.T) {
	idh := newTestHasher(t, "seed")
	gen, _ := NewCardIdGenerator(nil, idh)

	var ref CardRef
	if err := gen.GenCardIds(makeRealm(0x01), nil, &ref); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	zeros := [32]byte{}
	if ref.ServerCardId == zeros {
		t.Error("ServerCardId must not be zero")
	}
}

// GenCardIds — with UserIdFactory (deterministic path) ---------------------------------------------------------------
//
// When a UserIdFactory is provided, the full pipeline is deterministic:
// userdata → UserId → IdToken (HKDF) → ServerCardId (HKDF).

// TestIdHash_GenCardIds_WithFactory_ClientUserIdIsSet verifies that ClientUserId
// is populated from the factory output.
func TestIdHash_GenCardIds_WithFactory_ClientUserIdIsSet(t *testing.T) {
	idh := newTestHasher(t, "seed")
	gen, _ := NewCardIdGenerator(makeUserIdFactory(), idh)

	var ref CardRef
	if err := gen.GenCardIds(makeRealm(0x01), makeUserData("alice"), &ref); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.ClientUserId == "" {
		t.Error("expected ClientUserId to be set by factory")
	}
}

// TestIdHash_GenCardIds_WithFactory_Deterministic verifies that the same realm
// and userdata always produce the same ClientUserId, ClientIdToken, and ServerCardId.
func TestIdHash_GenCardIds_WithFactory_Deterministic(t *testing.T) {
	idh := newTestHasher(t, "seed")
	gen, _ := NewCardIdGenerator(makeUserIdFactory(), idh)
	realm := makeRealm(0x01)
	ud := makeUserData("alice")

	var ref1, ref2 CardRef
	if err := gen.GenCardIds(realm, ud, &ref1); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := ref1.Check(); err != nil {
		t.Fatalf("failed ref1.Check, got error %v", err)
	}
	if err := gen.GenCardIds(realm, ud, &ref2); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if err := ref2.Check(); err != nil {
		t.Fatalf("failed ref2.Check, got error %v", err)
	}
	if ref1.ClientUserId != ref2.ClientUserId {
		t.Error("ClientUserId must be deterministic")
	}
	if ref1.ClientIdToken != ref2.ClientIdToken {
		t.Error("ClientIdToken must be deterministic")
	}
	if ref1.ServerCardId != ref2.ServerCardId {
		t.Error("ServerCardId must be deterministic")
	}
}

// TestIdHash_GenCardIds_WithFactory_ServerCardIdIsNonZero verifies that the
// HKDF-derived ServerCardId is not the zero value.
func TestIdHash_GenCardIds_WithFactory_ServerCardIdIsNonZero(t *testing.T) {
	idh := newTestHasher(t, "seed")
	gen, _ := NewCardIdGenerator(makeUserIdFactory(), idh)

	var ref CardRef
	if err := gen.GenCardIds(makeRealm(0x01), makeUserData("alice"), &ref); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	zeros := [32]byte{}
	if ref.ServerCardId == zeros {
		t.Error("ServerCardId must not be zero")
	}
}

// TestIdHash_GenCardIds_WithFactory_DifferentUserDataDifferentIds verifies that
// distinct userdata produces distinct ClientUserId, ClientIdToken, and ServerCardId.
func TestIdHash_GenCardIds_WithFactory_DifferentUserDataDifferentIds(t *testing.T) {
	idh := newTestHasher(t, "seed")
	gen, _ := NewCardIdGenerator(makeUserIdFactory(), idh)
	realm := makeRealm(0x01)

	var ref1, ref2 CardRef
	gen.GenCardIds(realm, makeUserData("alice"), &ref1)
	gen.GenCardIds(realm, makeUserData("bob"), &ref2)

	if ref1.ClientUserId == ref2.ClientUserId {
		t.Error("different userdata must produce different ClientUserId")
	}
	if ref1.ClientIdToken == ref2.ClientIdToken {
		t.Error("different userdata must produce different ClientIdToken")
	}
	if ref1.ServerCardId == ref2.ServerCardId {
		t.Error("different userdata must produce different ServerCardId")
	}
}

// TestIdHash_GenCardIds_WithFactory_DifferentRealmDifferentIds verifies that the
// realm is bound into the derivation — same userdata, different realm → different tokens.
func TestIdHash_GenCardIds_WithFactory_DifferentRealmDifferentIds(t *testing.T) {
	idh := newTestHasher(t, "seed")
	gen, _ := NewCardIdGenerator(makeUserIdFactory(), idh)
	ud := makeUserData("alice")

	var ref1, ref2 CardRef
	gen.GenCardIds(makeRealm(0x01), ud, &ref1)
	gen.GenCardIds(makeRealm(0x02), ud, &ref2)

	if ref1.ClientIdToken == ref2.ClientIdToken {
		t.Error("different realms must produce different ClientIdToken")
	}
	if ref1.ServerCardId == ref2.ServerCardId {
		t.Error("different realms must produce different ServerCardId")
	}
}

// TestIdHash_GenCardIds_WithFactory_FactoryErrorPropagates verifies that an error
// returned by the UserIdFactory surfaces and dst is left untouched.
func TestIdHash_GenCardIds_WithFactory_FactoryErrorPropagates(t *testing.T) {
	failFactory := UserIdFactoryFunc(func(_ json.RawMessage) (string, error) {
		return "", wrapError(ErrValidation, "deliberate factory error")
	})
	idh := newTestHasher(t, "seed")
	gen, _ := NewCardIdGenerator(failFactory, idh)

	var ref CardRef
	err := gen.GenCardIds(makeRealm(0x01), nil, &ref)
	if err == nil {
		t.Error("expected error from failing UserIdFactory")
	}
	// dst must be untouched — all fields remain zero values.
	zeros := [32]byte{}
	if ref.ClientIdToken != zeros || ref.ServerCardId != zeros || ref.ClientUserId != "" {
		t.Error("dst CardRef must be untouched when factory errors")
	}
}

// TestIdHash_GenCardIds_NilDstReturnsError checks the nil destination guard,
// regardless of which path would have been taken.
func TestIdHash_GenCardIds_NilDstReturnsError(t *testing.T) {
	idh := newTestHasher(t, "seed")
	gen, _ := NewCardIdGenerator(nil, idh)
	if err := gen.GenCardIds(makeRealm(0x01), nil, nil); err == nil {
		t.Error("expected error for nil dst")
	}
}

// helpers ---------------------------------------------------------------

// makeRealm returns a valid 32-byte RealmId filled with the given byte value.
func makeRealm(b byte) RealmId {
	r := make(RealmId, 32)
	for i := range r {
		r[i] = b
	}
	return r
}

// makeToken returns a valid 32-byte slice filled with the given byte value.
func makeToken(b byte) []byte {
	t := make([]byte, 32)
	for i := range t {
		t[i] = b
	}
	return t
}

// newTestHasher creates an IdHasher from a short ASCII seed. Fatals on error.
func newTestHasher(t *testing.T, seed string) *IdHasher {
	t.Helper()
	idh, err := NewIdHasher([]byte(seed))
	if err != nil {
		t.Fatalf("NewIdHasher(%q): %v", seed, err)
	}
	return idh
}

// makeUserIdFactory returns a UserIdFactory that extracts the "sub" field from
// a JSON object. It is the canonical test factory throughout this file.
func makeUserIdFactory() UserIdFactory {
	return UserIdFactoryFunc(func(ud json.RawMessage) (string, error) {
		var m map[string]string
		if err := json.Unmarshal(ud, &m); err != nil {
			return "", err
		}
		return m["sub"], nil
	})
}

// makeUserData returns a minimal JSON payload with the given subject string.
func makeUserData(sub string) json.RawMessage {
	return json.RawMessage(`{"sub":"` + sub + `"}`)
}
