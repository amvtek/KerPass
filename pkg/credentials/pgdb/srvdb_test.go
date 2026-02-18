package pgdb

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"

	"code.kerpass.org/golang/pkg/credentials"

	"github.com/jackc/pgx/v5"
)

const testDSN = "host=localhost port=25432 database=kpdb user=postgres password=notasecret sslmode=disable search_path=kerpass_test,public"

var testRealmId = newID(0x1F)

var storageAdapter *credentials.SrvStorageAdapter

func TestPing(t *testing.T) {
	ctx := context.Background() // t.Context() gets in the way when controlling transaction
	pgconn := newConn(ctx, t)
	err := pgconn.Ping(ctx)
	if nil != err {
		t.Fatalf("failed connection test, got error %v", err)
	}
}

func TestServerCredStore_newServerCredStore(t *testing.T) {
	ctx := context.Background()
	newServerCredStore(ctx, t)
}

func TestServerCredStore_SaveRealm_Success(t *testing.T) {
	ctx := context.Background()
	store := newEmptyCredStore(ctx, t)

	// generates valid credentials.Realm
	realm := credentials.Realm{
		RealmId: newID(0x11),
		AppName: "Test Realm",
		AppLogo: []byte{0x01, 0x02, 0x03},
	}

	// saves it using SaveRealm
	err := store.SaveRealm(ctx, &realm)
	if err != nil {
		t.Fatalf("Failed to save realm: %v", err)
	}

	// make sure realm table has 1 row
	realms, err := store.ListRealm(ctx)
	if err != nil {
		t.Fatalf("Failed to list realms after save: %v", err)
	}
	if len(realms) != 1 {
		t.Errorf("Expected 1 realm after save, got %d", len(realms))
	}
}

func TestServerCredStore_SaveRealm_Fail(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// generates a non valid credentials.Realm
	realm := credentials.Realm{
		RealmId: []byte{0x01}, // Too short - invalid
		AppName: "",           // Empty - invalid
	}

	// makes sure SaveRealm returns non nil error
	err := store.SaveRealm(ctx, &realm)
	if err == nil {
		t.Error("Expected SaveRealm to fail with invalid realm, but it succeeded")
	}
}

func TestServerCredStore_LoadRealm_Success(t *testing.T) {
	ctx := context.Background()
	store := newEmptyCredStore(ctx, t)

	// generates valid credentials.Realm
	originalRealm := credentials.Realm{
		RealmId: newID(0x12),
		AppName: "Test Realm for Load",
		AppLogo: []byte{0x04, 0x05, 0x06},
	}

	// saves it using SaveRealm
	err := store.SaveRealm(ctx, &originalRealm)
	if err != nil {
		t.Fatalf("Failed to save realm: %v", err)
	}

	// uses LoadRealm to reload saved Realm...
	var loadedRealm credentials.Realm
	err = store.LoadRealm(ctx, originalRealm.RealmId, &loadedRealm)
	if err != nil {
		t.Fatalf("Failed to load realm: %v", err)
	}

	// make sure reloaded Realm is same as saved one...
	if !bytes.Equal(loadedRealm.RealmId, originalRealm.RealmId) {
		t.Error("Loaded RealmId doesn't match original")
	}
	if loadedRealm.AppName != originalRealm.AppName {
		t.Errorf("Loaded AppName doesn't match original: got %s, want %s", loadedRealm.AppName, originalRealm.AppName)
	}
	if !bytes.Equal(loadedRealm.AppLogo, originalRealm.AppLogo) {
		t.Error("Loaded AppLogo doesn't match original")
	}
}

func TestServerCredStore_LoadRealm_Fail(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// attempt loading realm with non existing id
	nonExistentRealmId := newID(0x99)
	var realm credentials.Realm
	err := store.LoadRealm(ctx, nonExistentRealmId, &realm)

	// make sure you get credentials.ErrNotFound
	if !errors.Is(err, credentials.ErrNotFound) {
		t.Errorf("Expected credentials.ErrNotFound, got %v", err)
	}
}

func TestServerCredStore_ListRealm(t *testing.T) {
	ctx := context.Background()
	store := newEmptyCredStore(ctx, t)

	// Insert 4 distinct Realm in realm table
	testRealms := []credentials.Realm{
		{RealmId: newID(0x13), AppName: "Realm 1", AppLogo: []byte{0x01}},
		{RealmId: newID(0x14), AppName: "Realm 2", AppLogo: []byte{0x02}},
		{RealmId: newID(0x15), AppName: "Realm 3", AppLogo: []byte{0x03}},
		{RealmId: newID(0x16), AppName: "Realm 4", AppLogo: []byte{0x04}},
	}

	for _, realm := range testRealms {
		err := store.SaveRealm(ctx, &realm)
		if err != nil {
			t.Fatalf("Failed to save realm %s: %v", realm.AppName, err)
		}
	}

	//  Make sure ListRealm returns all inserted Realm...
	realms, err := store.ListRealm(ctx)
	if err != nil {
		t.Fatalf("Failed to list realms after insert: %v", err)
	}
	if len(realms) != len(testRealms) {
		t.Errorf("Expected %d realms, got %d", len(testRealms), len(realms))
	}

	// Verify each realm was returned (simplified check - just count)
	realmMap := make(map[string]bool)
	for _, realm := range realms {
		realmMap[realm.AppName] = true
	}

	for _, testRealm := range testRealms {
		if !realmMap[testRealm.AppName] {
			t.Errorf("Realm %s not found in list results", testRealm.AppName)
		}
	}
}

func TestServerCredStore_ListRealm_empty(t *testing.T) {
	ctx := context.Background()
	store := newEmptyCredStore(ctx, t)

	// Make sure ListReam returns an empty slice.
	realms, err := store.ListRealm(ctx)
	if err != nil {
		t.Fatalf("ListRealm failed with error: %v", err)
	}
	if len(realms) != 0 {
		t.Errorf("Expected empty realm slice, got %d realms", len(realms))
	}
}

func TestServerCredStore_RemoveRealm(t *testing.T) {
	ctx := context.Background()
	store := newEmptyCredStore(ctx, t)

	// Add 1 Realm
	realm := credentials.Realm{
		RealmId: newID(0x17),
		AppName: "Realm to Remove",
		AppLogo: []byte{0x07, 0x08, 0x09},
	}
	err := store.SaveRealm(ctx, &realm)
	if err != nil {
		t.Fatalf("Failed to save realm: %v", err)
	}

	// Make sure RemoveRealm succeeds
	err = store.RemoveRealm(ctx, realm.RealmId)
	if err != nil {
		t.Fatalf("Failed to remove realm: %v", err)
	}

	// Call RemoveRealm a second time, it shall return ErrNotFound...
	err = store.RemoveRealm(ctx, realm.RealmId)
	if !errors.Is(err, credentials.ErrNotFound) {
		t.Errorf("Expected credentials.ErrNotFound, got %v", err)
	}
}

func TestServerCredStore_SaveEnrollAuthorization_Success(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// Save 4 distinct EnrollAuthorization in testRealm
	var err error
	for i := range 4 {
		ea := credentials.EnrollAuthorization{}
		eat, err := initEnrollAuth(&ea)
		if nil != err {
			t.Fatalf("Failed initEnrollAuth #%d, got error %v", i, err)
		}

		err = store.SaveEnrollAuthorization(ctx, eat, &ea)
		if err != nil {
			t.Fatalf("Failed to save authorization #%d: %v", i, err)
		}
	}

	// Verify final count
	finalCount, err := store.AuthorizationCount(ctx)
	if err != nil {
		t.Fatalf("Failed authorizations count, got error %v", err)
	} else if finalCount != 4 {
		t.Fatalf("Expected 4 authorizations, got %d", finalCount)
	}
}

func TestServerCredStore_SaveEnrollAuthorization_InvalidRealm(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// Create authorization with non-existent realm
	nonExistentRealmID := newID(0xFF) // Different from testRealmId
	ea := credentials.EnrollAuthorization{}
	eat, err := initEnrollAuth(&ea)
	if nil != err {
		t.Fatalf("Failed initEnrollAuth, got error %v", err)
	}
	ea.RealmId = credentials.RealmId(nonExistentRealmID)

	// Save the authorization
	err = store.SaveEnrollAuthorization(ctx, eat, &ea)
	if err == nil {
		t.Error("Expected error when saving authorization with non-existent realm, but got none")
	}
}

func TestServerCredStore_PopEnrollAuthorization(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// Create and save an authorization
	ea := credentials.EnrollAuthorization{}
	enrollToken, err := initEnrollAuth(&ea)
	if nil != err {
		t.Fatalf("Failed initEnrollAuth, got error %v", err)
	}
	err = store.SaveEnrollAuthorization(ctx, enrollToken, &ea)
	if err != nil {
		t.Fatalf("Failed to save authorization: %v", err)
	}

	// Check that enrollToken is not used as a database key
	var used int
	row := store.DB.QueryRow(
		ctx,
		`SELECT COUNT(id) FROM enroll_authorization WHERE aid = $1`,
		[]byte(enrollToken),
	)
	err = row.Scan(&used)
	if nil != err {
		t.Fatalf("Failed enroll_authorization counting query, got error %v", err)
	}
	if 0 != used {
		t.Fatalf("enrollToken used as a database key")
	}

	// Pop the authorization
	var poppedEA credentials.EnrollAuthorization
	err = store.PopEnrollAuthorization(ctx, enrollToken, &poppedEA)
	if nil != err {
		t.Fatalf("Failed to pop authorization, got error %v", err)
	}

	// Check that AuthorizationCount is zero
	count, err := store.AuthorizationCount(ctx)
	if err != nil {
		t.Errorf("Failed authorization count after pop, got error %v", err)
	} else if count != 0 {
		t.Errorf("Expected 0 authorizations after pop, got %d", count)
	}

	// Check that the popped EnrollAuthorization has expected AppName and zero length AppLogo
	if poppedEA.AppName != "Test App 1F" {
		t.Errorf("Expected AppName 'Test App 1F', got '%s'", poppedEA.AppName)
	}
	if len(poppedEA.AppLogo) != 0 {
		t.Errorf("Expected empty AppLogo, got %d bytes", len(poppedEA.AppLogo))
	}
}

func TestServerCredStore_PopEnrollAuthorization_WithLogo(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	expectedLogo := []byte{0x01, 0x02, 0x03, 0x04}

	// Use plain SQL to modify the testRealm
	_, err := store.DB.Exec(ctx,
		`UPDATE realm SET app_name = $1, app_logo = $2 WHERE rid = $3`,
		"Updated Test App",
		expectedLogo,
		testRealmId,
	)
	if err != nil {
		t.Fatalf("Failed to update realm: %v", err)
	}

	// Save 4 distinct EnrollAuthorization in testRealm
	var atk credentials.EnrollToken
	authTokens := make([]credentials.EnrollToken, 0, 4)
	for i := range 4 {
		ea := credentials.EnrollAuthorization{}
		atk, err = initEnrollAuth(&ea)
		if nil != err {
			t.Fatalf("Failed initEnrollAuth #%d, got error %v", i, err)
		}
		err = store.SaveEnrollAuthorization(ctx, atk, &ea)
		if err != nil {
			t.Fatalf("Failed to save authorization #%d: %v", i, err)
		}
		authTokens = append(authTokens, atk)
	}

	// Check initial count
	initialCount, err := store.AuthorizationCount(ctx)
	if nil != err {
		t.Errorf("Failed counting authorizations, got error %v", err)
	} else if initialCount != 4 {
		t.Errorf("Expected 4 authorizations before popping, got %d", initialCount)
	}

	// Pop all authorizations and check their data
	for i, authToken := range authTokens {
		var poppedEA credentials.EnrollAuthorization
		err = store.PopEnrollAuthorization(ctx, authToken, &poppedEA)
		if nil != err {
			t.Errorf("Failed to pop authorization #%d, got error %v", i+1, err)
			continue
		}

		// Check AppName and AppLogo
		if poppedEA.AppName != "Updated Test App" {
			t.Errorf("Authorization #%d: Expected AppName 'Updated Test App', got '%s'", i+1, poppedEA.AppName)
		}
		if !bytes.Equal(poppedEA.AppLogo, expectedLogo) {
			t.Errorf("Authorization #%d: AppLogo content doesn't match expected", i+1)
		}
	}

	// Check final count
	finalCount, err := store.AuthorizationCount(ctx)
	if nil != err {
		t.Errorf("Failed final authorization count, got error %v", err)
	} else if finalCount != 0 {
		t.Errorf("Expected 0 authorizations after popping all, got %d", finalCount)
	}
}

func TestServerCredStore_AuthorizationCount(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// Start with empty count
	count, err := store.AuthorizationCount(ctx)
	if err != nil {
		t.Fatalf("Failed initial authorization count, got error %v", err)
	} else if count != 0 {
		t.Errorf("Expected 0 authorizations, got %d", count)
	}

	// Add some test authorizations
	authIDs := [][]byte{newID(0x3B), newID(0x4C), newID(0x5D)}
	for _, authID := range authIDs {
		_, err := store.DB.Exec(ctx,
			`INSERT INTO enroll_authorization(aid, realm_id) 
			 SELECT v.aid, r.id
			 FROM (VALUES ($1::bytea, $2::bytea)) v(aid, rid)
			 INNER JOIN realm r ON (r.rid = v.rid)`,
			authID,
			testRealmId,
		)
		if err != nil {
			t.Fatalf("Failed to setup test data: %v", err)
		}
	}

	// Verify count
	count, err = store.AuthorizationCount(ctx)
	if nil != err {
		t.Fatalf("Failed final authorization count, got error %v", err)
	} else if count != len(authIDs) {
		t.Errorf("Expected %d authorizations, got %d", len(authIDs), count)
	}
}

func TestServerCredStore_SaveCard_Success(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// Get initial card count
	initialCount, err := store.CardCount(ctx)
	if nil != err {
		t.Errorf("Failed initial card count, got error %v", err)
	} else if initialCount != 0 {
		t.Errorf("Expected 0 cards initially, got %d", initialCount)
	}

	// Generate random card in testRealm
	var card credentials.ServerCard
	idToken, err := initCard(&card)
	if err != nil {
		t.Fatalf("Failed to generate random card: %v", err)
	}
	card.RealmId = testRealmId

	// Save the card
	err = store.SaveCard(ctx, idToken, &card)
	if err != nil {
		t.Errorf("SaveCard failed: %v", err)
	}

	// Check that idToken is not used as a database key
	var used int
	row := store.DB.QueryRow(
		ctx,
		`SELECT COUNT(id) FROM card WHERE cid = $1`,
		[]byte(idToken),
	)
	err = row.Scan(&used)
	if nil != err {
		t.Fatalf("Failed card counting query, got error %v", err)
	}
	if 0 != used {
		t.Fatalf("idToken used as a database key")
	}

	// Check final card count
	finalCount, err := store.CardCount(ctx)
	if nil != err {
		t.Errorf("Failed final card count, got error %v", err)
	} else if finalCount != 1 {
		t.Errorf("Expected 1 card after saving, got %d", finalCount)
	}
}

func TestServerCredStore_SaveCard_Fail(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// Generate random card with non-existent realm
	var card credentials.ServerCard
	idToken, err := initCard(&card)
	if err != nil {
		t.Fatalf("Failed to generate random card: %v", err)
	}
	card.RealmId = newID(0xFF) // Non-existent realm

	// Save the card - this should fail due to foreign key constraint
	err = store.SaveCard(ctx, idToken, &card)
	if err == nil {
		t.Error("Expected SaveCard to fail with non-existent realm, but it succeeded")
	}
}

func TestServerCredStore_LoadCard_Success(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// Generate random card in testRealm
	var originalCard credentials.ServerCard
	idtkn, err := initCard(&originalCard)
	if err != nil {
		t.Fatalf("Failed to generate random card: %v", err)
	}
	originalCard.RealmId = testRealmId

	// Save the card
	err = store.SaveCard(ctx, idtkn, &originalCard)
	if err != nil {
		t.Fatalf("Failed to save card: %v", err)
	}

	// Load the card using LoadCard
	var retrievedCard credentials.ServerCard
	err = store.LoadCard(ctx, idtkn, &retrievedCard)
	if nil != err {
		t.Fatalf("LoadCard failed to retrieve the saved card, got error %v", err)
	}

	// Make sure retrieved card is same as original card
	if !bytes.Equal(retrievedCard.CardId, originalCard.CardId) {
		t.Error("Retrieved CardId doesn't match original")
	}
	if !bytes.Equal(retrievedCard.RealmId, originalCard.RealmId) {
		t.Error("Retrieved RealmId doesn't match original")
	}
	if !bytes.Equal(retrievedCard.Psk, originalCard.Psk) {
		t.Error("Retrieved Psk doesn't match original")
	}

	// Compare Kh using MarshalBinary
	originalKh, err := originalCard.Kh.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal original Kh: %v", err)
	}
	retrievedKh, err := retrievedCard.Kh.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal retrieved Kh: %v", err)
	}
	if !bytes.Equal(originalKh, retrievedKh) {
		t.Error("Retrieved Kh doesn't match original")
	}
}

func TestServerCredStore_LoadCard_Fail(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// Try to load a card with a non-existent ID
	nonExistentCardId := credentials.IdToken(newID(0x99))
	var retrievedCard credentials.ServerCard

	// Check that LoadCard returns error for non-existent card
	err := store.LoadCard(ctx, nonExistentCardId, &retrievedCard)
	if nil == err {
		t.Fatal("LoadCard returned nil error for non-existent card")
	}
	if !errors.Is(err, credentials.ErrNotFound) {
		t.Errorf("LoadCard returned non expected error %v", err)
	}
}

func TestServerCredStore_RemoveCard_Success(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// Check that CardCount is 0 initially
	initialCount, err := store.CardCount(ctx)
	if nil != err {
		t.Errorf("Failed initial card count, got error %v", err)
	} else if initialCount != 0 {
		t.Errorf("Expected 0 cards initially, got %d", initialCount)
	}

	// Generate random card in testRealm
	var card credentials.ServerCard
	idToken, err := initCard(&card)
	if err != nil {
		t.Fatalf("Failed to generate random card: %v", err)
	}
	card.RealmId = testRealmId

	// Save the card in store
	err = store.SaveCard(ctx, idToken, &card)
	if err != nil {
		t.Fatalf("Failed to save card: %v", err)
	}

	// Check that CardCount is 1
	countAfterSave, err := store.CardCount(ctx)
	if nil != err {
		t.Errorf("Failed after save card count, got error %v", err)
	} else if countAfterSave != 1 {
		t.Errorf("Expected 1 card after saving, got %d", countAfterSave)
	}

	// Remove card
	removed := store.RemoveCard(ctx, card.CardId)
	if !removed {
		t.Error("RemoveCard should return true for existing card, but returned false")
	}

	// Check that CardCount is 0 after removal
	countAfterRemove, err := store.CardCount(ctx)
	if nil != err {
		t.Errorf("Failed after removal card count, got error %v", err)
	} else if countAfterRemove != 0 {
		t.Errorf("Expected 0 cards after removal, got %d", countAfterRemove)
	}

	// Rerun RemoveCard & check it returned false
	removedAgain := store.RemoveCard(ctx, card.CardId)
	if removedAgain {
		t.Error("RemoveCard should return false for already removed card, but returned true")
	}
}

func TestServerCredStore_RemoveCard_Fail(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// Try to remove a card that doesn't exist
	nonExistentCardId := credentials.ServerCardIdKey(newID(0x88))

	// Check that removing non-existing card returns false
	removed := store.RemoveCard(ctx, nonExistentCardId)
	if removed {
		t.Error("RemoveCard should return false for non-existing card, but returned true")
	}
}

func TestServerCredStore_CardCount(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// Check that CardCount is 0 initially
	initialCount, err := store.CardCount(ctx)
	if nil != err {
		t.Fatalf("Failed initial card count, got error %v", err)
	} else if initialCount != 0 {
		t.Errorf("Expected 0 cards initially, got %d", initialCount)
	}

	// Generate & save 4 random cards
	cards := make([]credentials.ServerCard, 4)
	for i := range cards {
		idToken, err := initCard(&cards[i])
		if err != nil {
			t.Fatalf("Failed to generate card %d: %v", i+1, err)
		}
		cards[i].RealmId = testRealmId

		// Save the card
		err = store.SaveCard(ctx, idToken, &cards[i])
		if err != nil {
			t.Fatalf("Failed to save card %d: %v", i+1, err)
		}

		// Check that CardCount increments by 1 after saving each new card
		expectedCount := i + 1
		currentCount, err := store.CardCount(ctx)
		if nil != err {
			t.Errorf("Failed step %d card count, got error %v", i, err)
		} else if currentCount != expectedCount {
			t.Errorf("After saving card %d: expected count %d, got %d", i+1, expectedCount, currentCount)
		}
	}

	// Final verification - should have 4 cards total
	finalCount, err := store.CardCount(ctx)
	if nil != err {
		t.Errorf("Failed final card count, got error %v", err)
	} else if finalCount != 4 {
		t.Errorf("Expected 4 cards total, got %d", finalCount)
	}
}

func newConn(ctx context.Context, t *testing.T) *pgx.Conn {
	if nil != dbInitError {
		// dbInitError is set by init block below
		t.Fatalf("Failed kerpass_test schema initialization, got error %v", dbInitError)
	}
	pgconn, err := pgx.Connect(ctx, testDSN)
	if nil != err {
		t.Fatalf("failed pgx.Connect, got error %v", err)
	}

	return pgconn
}

var dbInitError error

func init() {
	pgconn, err := pgx.Connect(context.Background(), testDSN)
	if nil == err {
		err = ServerCredStoreMigrate(pgconn, "kerpass_test")
	}
	dbInitError = err

	// initializes global storageAdapter
	idHasher, err := credentials.NewIdHasher(nil)
	if nil != err {
		panic(wrapError(err, "failed instantiating idHasher"))
	}
	storageAdapter, err = credentials.NewSrvStorageAdapter(idHasher)
	if nil != err {
		panic(wrapError(err, "failed instantiating storageAdapter"))
	}

}

func newServerCredStore(ctx context.Context, t *testing.T) *ServerCredStore {
	pgconn := newConn(ctx, t)
	tx, err := pgconn.Begin(ctx)
	if nil != err {
		t.Fatalf("failed starting transaction, got error %v", err)
	}

	batch := &pgx.Batch{}
	batch.Queue("DELETE FROM realm")
	batch.Queue(`DELETE FROM enroll_authorization`)
	batch.Queue("DELETE FROM card")
	batch.Queue("INSERT INTO realm(rid, app_name) VALUES ($1, $2)", testRealmId, "Test App 1F")

	br := tx.SendBatch(ctx, batch)
	defer br.Close()
	for qnum := range 4 {
		_, err = br.Exec()
		if nil != err {
			t.Fatalf("failed tx initialization step #%d, got error %v", qnum, err)
		}
	}
	t.Cleanup(func() {
		err := tx.Rollback(ctx)
		if nil != err {
			t.Logf("failed rolling back test transaction, got error %v", err)
		} else {
			t.Log("rolled back test transaction")
		}
	})

	return &ServerCredStore{DB: tx, cardAdapter: storageAdapter}
}

func newEmptyCredStore(ctx context.Context, t *testing.T) *ServerCredStore {
	pgconn := newConn(ctx, t)
	tx, err := pgconn.Begin(ctx)
	if nil != err {
		t.Fatalf("failed starting transaction, got error %v", err)
	}

	batch := &pgx.Batch{}
	batch.Queue("DELETE FROM realm")
	batch.Queue(`DELETE FROM enroll_authorization`)
	batch.Queue("DELETE FROM card")

	br := tx.SendBatch(ctx, batch)
	defer br.Close()
	for qnum := range 3 {
		_, err = br.Exec()
		if nil != err {
			t.Fatalf("failed tx initialization step #%d, got error %v", qnum, err)
		}
	}
	t.Cleanup(func() {
		err := tx.Rollback(ctx)
		if nil != err {
			t.Logf("failed rolling back test transaction, got error %v", err)
		} else {
			t.Log("rolled back test transaction")
		}
	})
	return &ServerCredStore{DB: tx, cardAdapter: storageAdapter}
}

func newID(val byte) []byte {
	dst := make([]byte, 32)
	for i := range len(dst) {
		dst[i] = val
	}
	return dst
}

// initCard set random id & keys on dst.
// initCard returns the IdToken from which the dst identifier was derived.
func initCard(dst *credentials.ServerCard) (credentials.IdToken, error) {
	idtkn := credentials.IdToken(make([]byte, 32))
	rand.Read(idtkn)

	aks := credentials.AccessKeys{}
	err := storageAdapter.GetCardAccess(idtkn, &aks)
	if nil != err {
		return nil, err
	}

	dst.CardId = aks.IdKey[:]

	keypair, err := ecdh.X25519().GenerateKey(rand.Reader)
	if nil != err {
		return nil, err
	}
	dst.Kh = credentials.PublicKeyHandle{PublicKey: keypair.PublicKey()}

	psk := make([]byte, 32)
	rand.Read(psk)
	dst.Psk = psk

	return idtkn, nil
}

// initEnrollAuth set random id on dst.
// initEnrollAuth returns the EnrollToken from which the dst identifier was derived.
func initEnrollAuth(dst *credentials.EnrollAuthorization) (credentials.EnrollToken, error) {
	enrtkn := credentials.EnrollToken(make([]byte, 32))
	rand.Read(enrtkn)

	aks := credentials.AccessKeys{}
	err := storageAdapter.GetEnrollAuthorizationAccess(enrtkn, &aks)
	if nil != err {
		return nil, err
	}

	dst.EnrollId = aks.IdKey[:]
	dst.RealmId = credentials.RealmId(testRealmId)
	dst.AppName = "???"

	return enrtkn, nil
}
