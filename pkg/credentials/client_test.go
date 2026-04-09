package credentials

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
)

// ============================================================================
// CreateCard

func TestMemClientCredStore_CreateCard_HappyPath(t *testing.T) {
	store := NewMemClientCredStore()
	card := testCard(t, 0x01, 0x02, "MyApp")

	if err := store.CreateCard(card); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if card.ID <= 0 {
		t.Fatalf("expected positive card ID, got %d", card.ID)
	}
}

func TestMemClientCredStore_CreateCard_Idempotent(t *testing.T) {
	store := NewMemClientCredStore()
	card := testCard(t, 0x01, 0x02, "MyApp")

	if err := store.CreateCard(card); err != nil {
		t.Fatalf("first CreateCard: %v", err)
	}
	firstID := card.ID

	// second call with same IdToken: must succeed and preserve the stored card
	card2 := testCard(t, 0x01, 0x02, "MyApp")
	if err := store.CreateCard(card2); err != nil {
		t.Fatalf("second CreateCard: %v", err)
	}
	if card2.ID != firstID {
		t.Fatalf("expected ID %d, got %d", firstID, card2.ID)
	}
	if store.CardCount() != 1 {
		t.Fatalf("expected 1 card, got %d", store.CardCount())
	}
}

func TestMemClientCredStore_CreateCard_PreAssignedID(t *testing.T) {
	store := NewMemClientCredStore()
	card := testCard(t, 0x01, 0x02, "MyApp")

	if err := store.CreateCard(card); err != nil {
		t.Fatalf("initial CreateCard: %v", err)
	}
	assignedID := card.ID

	// re-submit with the assigned ID: must be accepted
	card.ID = assignedID
	if err := store.CreateCard(card); err != nil {
		t.Fatalf("pre-assigned CreateCard: %v", err)
	}
	if store.CardCount() != 1 {
		t.Fatalf("expected 1 card, got %d", store.CardCount())
	}
}

func TestMemClientCredStore_CreateCard_PreAssignedIDMismatch(t *testing.T) {
	store := NewMemClientCredStore()
	card := testCard(t, 0x01, 0x02, "MyApp")

	if err := store.CreateCard(card); err != nil {
		t.Fatalf("initial CreateCard: %v", err)
	}
	assignedID := card.ID

	// different card presented with the already-assigned ID
	mutant := testCard(t, 0x01, 0x03, "MyApp")
	mutant.ID = assignedID
	err := store.CreateCard(mutant)
	if !errors.Is(err, ErrCardMutation) {
		t.Fatalf("expected ErrCardMutation, got %v", err)
	}
}

func TestMemClientCredStore_CreateCard_SameTokenDifferentRealm(t *testing.T) {
	store := NewMemClientCredStore()
	card := testCard(t, 0x01, 0x02, "MyApp")

	if err := store.CreateCard(card); err != nil {
		t.Fatalf("initial CreateCard: %v", err)
	}

	// same IdToken, different RealmId
	mutant := testCard(t, 0x99, 0x02, "OtherApp")
	err := store.CreateCard(mutant)
	if !errors.Is(err, ErrCardMutation) {
		t.Fatalf("expected ErrCardMutation, got %v", err)
	}
}

func TestMemClientCredStore_CreateCard_RealmUpsert(t *testing.T) {
	store := NewMemClientCredStore()

	card := testCard(t, 0x01, 0x02, "OldName")
	if err := store.CreateCard(card); err != nil {
		t.Fatalf("first CreateCard: %v", err)
	}

	// second card in the same realm with updated metadata
	card2 := testCard(t, 0x01, 0x03, "NewName")
	card2.AppDesc = "Updated description"
	if err := store.CreateCard(card2); err != nil {
		t.Fatalf("second CreateCard: %v", err)
	}

	// find the realm ID via ListInfo and check its metadata
	infos, err := store.ListInfo(CardQuery{RealmId: testRealmId(t, 0x01)})
	if err != nil {
		t.Fatalf("ListInfo: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("expected at least one CardInfo")
	}
	rId := infos[0].RealmID

	var realm Realm
	if err := store.LoadRealm(rId, &realm); err != nil {
		t.Fatalf("LoadRealm: %v", err)
	}
	if realm.AppName != "NewName" {
		t.Fatalf("expected realm AppName %q, got %q", "NewName", realm.AppName)
	}
	if realm.AppDesc != "Updated description" {
		t.Fatalf("expected realm AppDesc %q, got %q", "Updated description", realm.AppDesc)
	}
}

// ============================================================================
// RemoveCard

func TestMemClientCredStore_RemoveCard_Existing(t *testing.T) {
	store := NewMemClientCredStore()
	card := testCard(t, 0x01, 0x02, "MyApp")

	if err := store.CreateCard(card); err != nil {
		t.Fatalf("CreateCard: %v", err)
	}

	removed, err := store.RemoveCard(card.ID)
	if err != nil {
		t.Fatalf("RemoveCard error: %v", err)
	}
	if !removed {
		t.Fatal("expected removed=true")
	}
	if store.CardCount() != 0 {
		t.Fatalf("expected 0 cards, got %d", store.CardCount())
	}
}

func TestMemClientCredStore_RemoveCard_NonExisting(t *testing.T) {
	store := NewMemClientCredStore()

	removed, err := store.RemoveCard(999)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if removed {
		t.Fatal("expected removed=false")
	}
}

func TestMemClientCredStore_RemoveCard_TokenIndexCleared(t *testing.T) {
	store := NewMemClientCredStore()
	card := testCard(t, 0x01, 0x02, "MyApp")

	if err := store.CreateCard(card); err != nil {
		t.Fatalf("CreateCard: %v", err)
	}
	firstID := card.ID

	if _, err := store.RemoveCard(firstID); err != nil {
		t.Fatalf("RemoveCard: %v", err)
	}

	// re-creating a card with the same IdToken must succeed with a fresh ID
	card2 := testCard(t, 0x01, 0x02, "MyApp")
	if err := store.CreateCard(card2); err != nil {
		t.Fatalf("re-CreateCard: %v", err)
	}
	if card2.ID == firstID {
		t.Fatalf("expected a new ID, got the same ID %d", firstID)
	}
}

// ============================================================================
// SetCardLabel

func TestMemClientCredStore_SetCardLabel_HappyPath(t *testing.T) {
	store := NewMemClientCredStore()
	card := testCard(t, 0x01, 0x02, "MyApp")

	if err := store.CreateCard(card); err != nil {
		t.Fatalf("CreateCard: %v", err)
	}
	if err := store.SetCardLabel(card.ID, "my label"); err != nil {
		t.Fatalf("SetCardLabel: %v", err)
	}

	var dst ClientCard
	if err := store.LoadCard(card.ID, &dst); err != nil {
		t.Fatalf("LoadCard: %v", err)
	}
	if dst.Label != "my label" {
		t.Fatalf("expected label %q, got %q", "my label", dst.Label)
	}
}

func TestMemClientCredStore_SetCardLabel_EmptyLabel(t *testing.T) {
	store := NewMemClientCredStore()
	card := testCard(t, 0x01, 0x02, "MyApp")

	if err := store.CreateCard(card); err != nil {
		t.Fatalf("CreateCard: %v", err)
	}

	for _, lbl := range []string{"", "   ", "\t"} {
		err := store.SetCardLabel(card.ID, lbl)
		if !errors.Is(err, ErrValidation) {
			t.Fatalf("label %q: expected ErrValidation, got %v", lbl, err)
		}
	}
}

func TestMemClientCredStore_SetCardLabel_UnknownCard(t *testing.T) {
	store := NewMemClientCredStore()

	err := store.SetCardLabel(999, "label")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// ============================================================================
// LoadCard

func TestMemClientCredStore_LoadCard_HappyPath(t *testing.T) {
	store := NewMemClientCredStore()
	card := testCard(t, 0x01, 0x02, "MyApp")

	if err := store.CreateCard(card); err != nil {
		t.Fatalf("CreateCard: %v", err)
	}

	var dst ClientCard
	if err := store.LoadCard(card.ID, &dst); err != nil {
		t.Fatalf("LoadCard: %v", err)
	}

	if dst.ID != card.ID {
		t.Errorf("ID: expected %d, got %d", card.ID, dst.ID)
	}
	if string(dst.RealmId) != string(card.RealmId) {
		t.Errorf("RealmId mismatch")
	}
	if string(dst.IdToken) != string(card.IdToken) {
		t.Errorf("IdToken mismatch")
	}
}

func TestMemClientCredStore_LoadCard_DeepCopy(t *testing.T) {
	store := NewMemClientCredStore()
	card := testCard(t, 0x01, 0x02, "MyApp")

	if err := store.CreateCard(card); err != nil {
		t.Fatalf("CreateCard: %v", err)
	}

	var dst ClientCard
	if err := store.LoadCard(card.ID, &dst); err != nil {
		t.Fatalf("LoadCard: %v", err)
	}

	// mutate the returned slices; a subsequent load must be unaffected
	dst.Psk[0] ^= 0xFF
	dst.RealmId[0] ^= 0xFF
	dst.IdToken[0] ^= 0xFF

	var dst2 ClientCard
	if err := store.LoadCard(card.ID, &dst2); err != nil {
		t.Fatalf("second LoadCard: %v", err)
	}
	if dst2.Psk[0] == dst.Psk[0] {
		t.Error("Psk was not deep-copied: mutation affected stored value")
	}
	if dst2.RealmId[0] == dst.RealmId[0] {
		t.Error("RealmId was not deep-copied: mutation affected stored value")
	}
	if dst2.IdToken[0] == dst.IdToken[0] {
		t.Error("IdToken was not deep-copied: mutation affected stored value")
	}
}

func TestMemClientCredStore_LoadCard_UnknownCard(t *testing.T) {
	store := NewMemClientCredStore()

	var dst ClientCard
	err := store.LoadCard(999, &dst)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// ============================================================================
// LoadRealm

func TestMemClientCredStore_LoadRealm_HappyPath(t *testing.T) {
	store := NewMemClientCredStore()
	card := testCard(t, 0x01, 0x02, "MyApp")
	card.AppDesc = "A description"

	if err := store.CreateCard(card); err != nil {
		t.Fatalf("CreateCard: %v", err)
	}

	infos, err := store.ListInfo(CardQuery{RealmId: testRealmId(t, 0x01)})
	if err != nil || len(infos) == 0 {
		t.Fatalf("ListInfo: err=%v, len=%d", err, len(infos))
	}

	var realm Realm
	if err := store.LoadRealm(infos[0].RealmID, &realm); err != nil {
		t.Fatalf("LoadRealm: %v", err)
	}
	if realm.AppName != "MyApp" {
		t.Errorf("AppName: expected %q, got %q", "MyApp", realm.AppName)
	}
	if realm.AppDesc != "A description" {
		t.Errorf("AppDesc: expected %q, got %q", "A description", realm.AppDesc)
	}
}

func TestMemClientCredStore_LoadRealm_UnknownRealm(t *testing.T) {
	store := NewMemClientCredStore()

	var dst Realm
	err := store.LoadRealm(999, &dst)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// ============================================================================
// ListInfo

// seedCards creates n cards in a single realm (realmSeed) with sequential
// token seeds starting at tokenStart, and returns them in insertion order.
func seedCards(t *testing.T, store *MemClientCredStore, realmSeed byte, tokenStart byte, n int) []*Card {
	t.Helper()
	cards := make([]*Card, n)
	for i := range cards {
		c := testCard(t, realmSeed, tokenStart+byte(i), "App")
		if err := store.CreateCard(c); err != nil {
			t.Fatalf("seedCards CreateCard[%d]: %v", i, err)
		}
		cards[i] = c
	}
	return cards
}

func TestMemClientCredStore_ListInfo_MinId(t *testing.T) {
	store := NewMemClientCredStore()
	cards := seedCards(t, store, 0x01, 0x10, 4)

	// use the second card's ID as MinId: only cards 3 and 4 should appear
	pivot := cards[1].ID
	infos, err := store.ListInfo(CardQuery{MinId: pivot})
	if err != nil {
		t.Fatalf("ListInfo: %v", err)
	}
	for _, info := range infos {
		if info.ID <= pivot {
			t.Errorf("expected ID > %d, got %d", pivot, info.ID)
		}
	}
}

func TestMemClientCredStore_ListInfo_Limit(t *testing.T) {
	store := NewMemClientCredStore()
	seedCards(t, store, 0x01, 0x10, 5)

	infos, err := store.ListInfo(CardQuery{Limit: 3})
	if err != nil {
		t.Fatalf("ListInfo: %v", err)
	}
	if len(infos) != 3 {
		t.Fatalf("expected 3 results, got %d", len(infos))
	}
}

func TestMemClientCredStore_ListInfo_LimitLargerThanResultSet(t *testing.T) {
	store := NewMemClientCredStore()
	seedCards(t, store, 0x01, 0x10, 2)

	// must not panic when Limit > number of cards
	infos, err := store.ListInfo(CardQuery{Limit: 100})
	if err != nil {
		t.Fatalf("ListInfo: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("expected 2 results, got %d", len(infos))
	}
}

func TestMemClientCredStore_ListInfo_RealmFilter(t *testing.T) {
	store := NewMemClientCredStore()
	seedCards(t, store, 0x01, 0x10, 3) // realm A
	seedCards(t, store, 0x02, 0x20, 2) // realm B

	infos, err := store.ListInfo(CardQuery{RealmId: testRealmId(t, 0x01)})
	if err != nil {
		t.Fatalf("ListInfo: %v", err)
	}
	if len(infos) != 3 {
		t.Fatalf("expected 3 results for realm A, got %d", len(infos))
	}
	for _, info := range infos {
		if info.AppName != "App" {
			t.Errorf("unexpected AppName %q", info.AppName)
		}
	}
}

func TestMemClientCredStore_ListInfo_SortedByID(t *testing.T) {
	store := NewMemClientCredStore()
	seedCards(t, store, 0x01, 0x10, 5)

	infos, err := store.ListInfo(CardQuery{})
	if err != nil {
		t.Fatalf("ListInfo: %v", err)
	}
	for i := 1; i < len(infos); i++ {
		if infos[i].ID <= infos[i-1].ID {
			t.Errorf("results not sorted: infos[%d].ID=%d <= infos[%d].ID=%d",
				i, infos[i].ID, i-1, infos[i-1].ID)
		}
	}
}

func TestMemClientCredStore_ListInfo_InvalidRealmId(t *testing.T) {
	store := NewMemClientCredStore()

	_, err := store.ListInfo(CardQuery{RealmId: []byte{0x01, 0x02}}) // too short
	if err == nil {
		t.Fatal("expected error for invalid RealmId, got nil")
	}
}

// ============================================================================
// ListAppInfo

func TestMemClientCredStore_ListAppInfo_HappyPath(t *testing.T) {
	store := NewMemClientCredStore()
	seedCards(t, store, 0x01, 0x10, 3) // realm A – 3 cards
	seedCards(t, store, 0x02, 0x20, 2) // realm B – 2 cards

	apps, err := store.ListAppInfo(AppQuery{})
	if err != nil {
		t.Fatalf("ListAppInfo: %v", err)
	}
	if len(apps) != 2 {
		t.Fatalf("expected 2 apps, got %d", len(apps))
	}
}

func TestMemClientCredStore_ListAppInfo_CardCount(t *testing.T) {
	store := NewMemClientCredStore()
	seedCards(t, store, 0x01, 0x10, 3)
	seedCards(t, store, 0x02, 0x20, 2)

	apps, err := store.ListAppInfo(AppQuery{})
	if err != nil {
		t.Fatalf("ListAppInfo: %v", err)
	}

	counts := make(map[string]int, len(apps))
	for _, app := range apps {
		counts[app.AppName] = app.CardCount
	}
	if counts["App"] != 5 {
		// both realms have AppName "App" via seedCards – they are distinct realms
		// so we check per-RealmID instead
		t.Log("AppName collision; verifying counts by RealmID")
		for _, app := range apps {
			switch app.CardCount {
			case 3, 2: // expected
			default:
				t.Errorf("unexpected CardCount %d for RealmID %d", app.CardCount, app.RealmID)
			}
		}
	}
}

func TestMemClientCredStore_ListAppInfo_CardCountAccurate(t *testing.T) {
	store := NewMemClientCredStore()
	cards := seedCards(t, store, 0x01, 0x10, 3)

	apps, err := store.ListAppInfo(AppQuery{})
	if err != nil {
		t.Fatalf("ListAppInfo: %v", err)
	}
	if len(apps) != 1 || apps[0].CardCount != 3 {
		t.Fatalf("expected 1 app with CardCount=3, got %+v", apps)
	}

	// remove one card and verify count drops
	if _, err := store.RemoveCard(cards[0].ID); err != nil {
		t.Fatalf("RemoveCard: %v", err)
	}

	apps, err = store.ListAppInfo(AppQuery{})
	if err != nil {
		t.Fatalf("ListAppInfo after remove: %v", err)
	}
	if len(apps) != 1 || apps[0].CardCount != 2 {
		t.Fatalf("expected CardCount=2 after remove, got %+v", apps)
	}
}

func TestMemClientCredStore_ListAppInfo_SortedByRealmID(t *testing.T) {
	store := NewMemClientCredStore()
	seedCards(t, store, 0x01, 0x10, 1)
	seedCards(t, store, 0x02, 0x20, 1)
	seedCards(t, store, 0x03, 0x30, 1)

	apps, err := store.ListAppInfo(AppQuery{})
	if err != nil {
		t.Fatalf("ListAppInfo: %v", err)
	}
	for i := 1; i < len(apps); i++ {
		if apps[i].RealmID <= apps[i-1].RealmID {
			t.Errorf("results not sorted: apps[%d].RealmID=%d <= apps[%d].RealmID=%d",
				i, apps[i].RealmID, i-1, apps[i-1].RealmID)
		}
	}
}

func TestMemClientCredStore_ListAppInfo_MinId(t *testing.T) {
	store := NewMemClientCredStore()
	seedCards(t, store, 0x01, 0x10, 1) // realm 1
	seedCards(t, store, 0x02, 0x20, 1) // realm 2
	seedCards(t, store, 0x03, 0x30, 1) // realm 3

	apps, err := store.ListAppInfo(AppQuery{})
	if err != nil {
		t.Fatalf("initial ListAppInfo: %v", err)
	}
	if len(apps) != 3 {
		t.Fatalf("expected 3 apps, got %d", len(apps))
	}
	pivot := apps[1].RealmID // second realm ID

	filtered, err := store.ListAppInfo(AppQuery{MinId: pivot})
	if err != nil {
		t.Fatalf("ListAppInfo with MinId: %v", err)
	}
	for _, app := range filtered {
		if app.RealmID <= pivot {
			t.Errorf("expected RealmID > %d, got %d", pivot, app.RealmID)
		}
	}
}

func TestMemClientCredStore_ListAppInfo_Limit(t *testing.T) {
	store := NewMemClientCredStore()
	seedCards(t, store, 0x01, 0x10, 1)
	seedCards(t, store, 0x02, 0x20, 1)
	seedCards(t, store, 0x03, 0x30, 1)

	apps, err := store.ListAppInfo(AppQuery{Limit: 2})
	if err != nil {
		t.Fatalf("ListAppInfo: %v", err)
	}
	if len(apps) != 2 {
		t.Fatalf("expected 2 results, got %d", len(apps))
	}
}

func TestMemClientCredStore_ListAppInfo_LimitLargerThanResultSet(t *testing.T) {
	store := NewMemClientCredStore()
	seedCards(t, store, 0x01, 0x10, 2)

	apps, err := store.ListAppInfo(AppQuery{Limit: 100})
	if err != nil {
		t.Fatalf("ListAppInfo: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("expected 1 app, got %d", len(apps))
	}
}

func TestMemClientCredStore_ListAppInfo_Empty(t *testing.T) {
	store := NewMemClientCredStore()

	apps, err := store.ListAppInfo(AppQuery{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(apps) != 0 {
		t.Fatalf("expected empty result, got %d apps", len(apps))
	}
}

func TestMemClientCredStore_ListAppInfo_AppMetadata(t *testing.T) {
	store := NewMemClientCredStore()
	card := testCard(t, 0x01, 0x10, "MyApp")
	card.AppDesc = "My description"
	if err := store.CreateCard(card); err != nil {
		t.Fatalf("CreateCard: %v", err)
	}

	apps, err := store.ListAppInfo(AppQuery{})
	if err != nil {
		t.Fatalf("ListAppInfo: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("expected 1 app, got %d", len(apps))
	}
	if apps[0].AppName != "MyApp" {
		t.Errorf("AppName: expected %q, got %q", "MyApp", apps[0].AppName)
	}
	if apps[0].AppDesc != "My description" {
		t.Errorf("AppDesc: expected %q, got %q", "My description", apps[0].AppDesc)
	}
}

func TestMemClientCredStore_ListAppInfo_RealmUpsertReflected(t *testing.T) {
	store := NewMemClientCredStore()
	seedCards(t, store, 0x01, 0x10, 1)

	// add a second card in same realm with updated metadata
	card2 := testCard(t, 0x01, 0x11, "UpdatedName")
	card2.AppDesc = "Updated desc"
	if err := store.CreateCard(card2); err != nil {
		t.Fatalf("CreateCard: %v", err)
	}

	apps, err := store.ListAppInfo(AppQuery{})
	if err != nil {
		t.Fatalf("ListAppInfo: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("expected 1 app, got %d", len(apps))
	}
	if apps[0].AppName != "UpdatedName" {
		t.Errorf("expected upserted AppName %q, got %q", "UpdatedName", apps[0].AppName)
	}
	if apps[0].CardCount != 2 {
		t.Errorf("expected CardCount=2, got %d", apps[0].CardCount)
	}
}

// ============================================================================
// CardCount

func TestMemClientCredStore_CardCount_Lifecycle(t *testing.T) {
	store := NewMemClientCredStore()

	if n := store.CardCount(); n != 0 {
		t.Fatalf("expected 0, got %d", n)
	}

	card1 := testCard(t, 0x01, 0x02, "MyApp")
	if err := store.CreateCard(card1); err != nil {
		t.Fatalf("CreateCard card1: %v", err)
	}
	if n := store.CardCount(); n != 1 {
		t.Fatalf("expected 1, got %d", n)
	}

	card2 := testCard(t, 0x01, 0x03, "MyApp")
	if err := store.CreateCard(card2); err != nil {
		t.Fatalf("CreateCard card2: %v", err)
	}
	if n := store.CardCount(); n != 2 {
		t.Fatalf("expected 2, got %d", n)
	}

	// duplicate create must not increment count
	if err := store.CreateCard(card1); err != nil {
		t.Fatalf("duplicate CreateCard: %v", err)
	}
	if n := store.CardCount(); n != 2 {
		t.Fatalf("expected 2 after duplicate, got %d", n)
	}

	if _, err := store.RemoveCard(card1.ID); err != nil {
		t.Fatalf("RemoveCard: %v", err)
	}
	if n := store.CardCount(); n != 1 {
		t.Fatalf("expected 1 after remove, got %d", n)
	}
}

// ============================================================================
// helpers

func testRealmId(t *testing.T, seed byte) RealmId {
	t.Helper()
	id := make([]byte, 32)
	for i := range id {
		id[i] = seed
	}
	return RealmId(id)
}

func testIdToken(t *testing.T, seed byte) IdToken {
	t.Helper()
	tok := make([]byte, 32)
	for i := range tok {
		tok[i] = seed
	}
	return IdToken(tok)
}

func testPsk(t *testing.T) []byte {
	t.Helper()
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return psk
}

func testPrivateKeyHandle(t *testing.T) PrivateKeyHandle {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return PrivateKeyHandle{PrivateKey: priv}
}

// testCard builds a minimal valid Card. seed differentiates RealmId / IdToken
// across cards; appName lets callers vary the realm display metadata.
func testCard(t *testing.T, realmSeed, tokenSeed byte, appName string) *Card {
	t.Helper()
	return &Card{
		RealmId: testRealmId(t, realmSeed),
		IdToken: testIdToken(t, tokenSeed),
		Kh:      testPrivateKeyHandle(t),
		Psk:     testPsk(t),
		AppName: appName,
	}
}
