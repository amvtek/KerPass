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

const testDSN = "host=localhost port=5432 database=kerpass_db user=postgres password=notasecret sslmode=disable search_path=kerpass_test,public"

var testRealmId = newID(0x1F)

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

func TestServerCredStore_SaveEnrollAuthorization_Success(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// Test data - 4 distinct authorizations in testRealm
	authIDs := [][]byte{
		newID(0x10),
		newID(0x20),
		newID(0x30),
		newID(0x40),
	}

	// Save 4 distinct EnrollAuthorization in testRealm
	for i, authID := range authIDs {
		ea := credentials.EnrollAuthorization{
			AuthorizationId: authID,
			RealmId:         testRealmId,
		}

		err := store.SaveEnrollAuthorization(ctx, ea)
		if err != nil {
			t.Errorf("Failed to save authorization #%d: %v", i+1, err)
		}
	}

	// Verify final count
	finalCount, err := store.AuthorizationCount(ctx)
	if err != nil {
		t.Errorf("Failed authorizations count, got error %v", err)
	} else if finalCount != len(authIDs) {
		t.Errorf("Expected %d authorizations, got %d", len(authIDs), finalCount)
	}
}

func TestServerCredStore_SaveEnrollAuthorization_InvalidRealm(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// Create authorization with non-existent realm
	authID := newID(0x50)
	nonExistentRealmID := newID(0xFF) // Different from testRealmId

	ea := credentials.EnrollAuthorization{
		AuthorizationId: authID,
		RealmId:         nonExistentRealmID,
	}

	// This should error due to foreign key constraint
	err := store.SaveEnrollAuthorization(ctx, ea)
	if err == nil {
		t.Error("Expected error when saving authorization with non-existent realm, but got none")
	}
}

func TestServerCredStore_PopEnrollAuthorization(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// Create and save an authorization
	authID := newID(0x60)
	ea := credentials.EnrollAuthorization{
		AuthorizationId: authID,
		RealmId:         testRealmId,
	}

	err := store.SaveEnrollAuthorization(ctx, ea)
	if err != nil {
		t.Fatalf("Failed to save authorization: %v", err)
	}

	// Pop the authorization
	var poppedEA credentials.EnrollAuthorization
	err = store.PopEnrollAuthorization(ctx, authID, &poppedEA)
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
		`UPDATE realm SET app_name = $1, app_logo = $2 WHERE id = $3`,
		"Updated Test App",
		expectedLogo,
		testRealmId,
	)
	if err != nil {
		t.Fatalf("Failed to update realm: %v", err)
	}

	// Save and pop 4 different authorizations
	authIDs := [][]byte{
		newID(0x70),
		newID(0x71),
		newID(0x72),
		newID(0x73),
	}

	// Save all authorizations first
	for _, authID := range authIDs {
		ea := credentials.EnrollAuthorization{
			AuthorizationId: authID,
			RealmId:         testRealmId,
		}
		err := store.SaveEnrollAuthorization(ctx, ea)
		if err != nil {
			t.Fatalf("Failed to save authorization %x: %v", authID, err)
		}
	}

	// Check initial count
	initialCount, err := store.AuthorizationCount(ctx)
	if nil != err {
		t.Errorf("Failed counting authorizations, got error %v", err)
	} else if initialCount != len(authIDs) {
		t.Errorf("Expected %d authorizations before popping, got %d", len(authIDs), initialCount)
	}

	// Pop all authorizations and check their data
	for i, authID := range authIDs {
		var poppedEA credentials.EnrollAuthorization
		err = store.PopEnrollAuthorization(ctx, authID, &poppedEA)
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
			`INSERT INTO enroll_authorization(id, realm_id) VALUES ($1, $2)`,
			authID, testRealmId)
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
	err = initCard(&card)
	if err != nil {
		t.Fatalf("Failed to generate random card: %v", err)
	}
	card.RealmId = testRealmId

	// Save the card
	err = store.SaveCard(ctx, card)
	if err != nil {
		t.Errorf("SaveCard failed: %v", err)
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
	err := initCard(&card)
	if err != nil {
		t.Fatalf("Failed to generate random card: %v", err)
	}
	card.RealmId = newID(0xFF) // Non-existent realm

	// Save the card - this should fail due to foreign key constraint
	err = store.SaveCard(ctx, card)
	if err == nil {
		t.Error("Expected SaveCard to fail with non-existent realm, but it succeeded")
	}
}

func TestServerCredStore_LoadCard_Success(t *testing.T) {
	ctx := context.Background()
	store := newServerCredStore(ctx, t)

	// Generate random card in testRealm
	var originalCard credentials.ServerCard
	err := initCard(&originalCard)
	if err != nil {
		t.Fatalf("Failed to generate random card: %v", err)
	}
	originalCard.RealmId = testRealmId

	// Save the card
	err = store.SaveCard(ctx, originalCard)
	if err != nil {
		t.Fatalf("Failed to save card: %v", err)
	}

	// Load the card using LoadCard
	var retrievedCard credentials.ServerCard
	err = store.LoadCard(ctx, originalCard.CardId, &retrievedCard)
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
	nonExistentCardId := newID(0x99)
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
	err = initCard(&card)
	if err != nil {
		t.Fatalf("Failed to generate random card: %v", err)
	}
	card.RealmId = testRealmId

	// Save the card in store
	err = store.SaveCard(ctx, card)
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

	// Remove card using RemoveCard
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
	nonExistentCardId := newID(0x88)

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
		err := initCard(&cards[i])
		if err != nil {
			t.Fatalf("Failed to generate card %d: %v", i+1, err)
		}
		cards[i].RealmId = testRealmId

		// Save the card
		err = store.SaveCard(ctx, cards[i])
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
	batch.Queue("INSERT INTO realm(id, app_name) VALUES ($1, $2)", testRealmId, "Test App 1F")

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
	return &ServerCredStore{DB: tx}
}

func newID(val byte) []byte {
	dst := make([]byte, 32)
	for i := range len(dst) {
		dst[i] = val
	}
	return dst
}

// initCard set random id & keys on dst.
func initCard(dst *credentials.ServerCard) error {
	cardId := make([]byte, 32)
	rand.Read(cardId)
	dst.CardId = cardId

	keypair, err := ecdh.X25519().GenerateKey(rand.Reader)
	if nil != err {
		return err
	}
	dst.Kh = credentials.PublicKeyHandle{PublicKey: keypair.PublicKey()}

	psk := make([]byte, 32)
	rand.Read(psk)
	dst.Psk = psk

	return nil
}
