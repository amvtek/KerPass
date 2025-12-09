package credentials

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestRealmInfo_MockStore(t *testing.T) {
	var err error

	// Setup
	store := NewMemServerCredStore()
	realmID := make([]byte, 32)
	for i := range realmID {
		realmID[i] = byte(i)
	}

	testRealm := Realm{
		RealmId: realmID,
		AppName: "Test Application",
		AppLogo: []byte("logo-data-here"),
	}

	// Save realm to store
	ctx := context.Background()
	if err = store.SaveRealm(ctx, testRealm); err != nil {
		t.Fatalf("Failed to save test realm: %v", err)
	}

	loadedRealm := Realm{}
	if err = store.LoadRealm(ctx, realmID, &loadedRealm); err != nil {
		t.Fatalf("Failed to reload test realm, got error %v", err)
	}
	if !reflect.DeepEqual(loadedRealm, testRealm) {
		t.Fatalf("Failed reloaded realm verif, got %+v != %+v", loadedRealm, testRealm)
	}
}

func TestRealmInfo_SuccessfulRetrieval(t *testing.T) {
	// Setup
	store, server := newRealmInfoServer(t)
	defer server.Close()

	realmID := make([]byte, 32)
	for i := range realmID {
		realmID[i] = byte(i)
	}

	testRealm := Realm{
		RealmId: realmID,
		AppName: "Test Application",
		AppLogo: []byte("logo-data-here"),
	}

	// Save realm to store
	ctx := context.Background()
	if err := store.SaveRealm(ctx, testRealm); err != nil {
		t.Fatalf("Failed to save test realm: %v", err)
	}

	// Test GetRealmInfo
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	retrievedRealm, err := GetRealmInfo(ctx, server.URL, realmID)
	if err != nil {
		t.Fatalf("GetRealmInfo failed: %v", err)
	}

	// Verify
	if string(retrievedRealm.RealmId) != string(testRealm.RealmId) {
		t.Errorf("RealmId mismatch: got %v, want %v", retrievedRealm.RealmId, testRealm.RealmId)
	}
	if retrievedRealm.AppName != testRealm.AppName {
		t.Errorf("AppName mismatch: got %s, want %s", retrievedRealm.AppName, testRealm.AppName)
	}
	if string(retrievedRealm.AppLogo) != string(testRealm.AppLogo) {
		t.Errorf("AppLogo mismatch: got %v, want %v", retrievedRealm.AppLogo, testRealm.AppLogo)
	}
}

func TestRealmInfo_NotFound(t *testing.T) {
	// Setup
	_, server := newRealmInfoServer(t)
	defer server.Close()

	// Test with non-existent realm
	nonExistentID := make([]byte, 32)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := GetRealmInfo(ctx, server.URL, nonExistentID)
	if err == nil {
		t.Fatal("Expected error for non-existent realm, got nil")
	}

	// Verify error type - should be ErrNotFound
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Expected ErrNotFound or wrapped version, got: %v", err)
	}
}

func TestRealmInfo_InvalidRealmIDLength(t *testing.T) {
	// Setup
	_, server := newRealmInfoServer(t)
	defer server.Close()

	// Test with invalid realm ID length (less than 32 bytes)
	invalidID := make([]byte, 31)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := GetRealmInfo(ctx, server.URL, invalidID)
	if err == nil {
		t.Fatal("Expected error for invalid realm ID length, got nil")
	}
}

func TestRealmInfo_ServerReturns404(t *testing.T) {
	// Create a test server that returns 404 for any request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	realmID := make([]byte, 32)
	_, err := GetRealmInfo(ctx, server.URL, realmID)
	if err == nil {
		t.Fatal("Expected error for 404 response, got nil")
	}
}

func TestRealmInfo_ContextCancellation(t *testing.T) {
	// Setup slow handler to test context cancellation
	store := NewMemServerCredStore()
	handler, err := NewRealmInfoHandler(store)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	// Wrap handler to add delay
	slowHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		handler.ServeHTTP(w, r)
	})

	server := httptest.NewServer(slowHandler)
	defer server.Close()

	// Test with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	realmID := make([]byte, 32)
	_, err = GetRealmInfo(ctx, server.URL, realmID)
	if err == nil {
		t.Fatal("Expected timeout error, got nil")
	}
	if ctx.Err() != context.DeadlineExceeded {
		t.Errorf("Expected deadline exceeded, got: %v", err)
	}
}

func TestRealmInfo_ConcurrentAccess(t *testing.T) {
	// Setup
	store, server := newRealmInfoServer(t)
	defer server.Close()

	// Create multiple test realms
	numRealms := 10
	realms := make([]Realm, numRealms)
	for i := 0; i < numRealms; i++ {
		realmID := make([]byte, 32)
		realmID[0] = byte(i)
		realms[i] = Realm{
			RealmId: realmID,
			AppName: "Test App " + string(rune('A'+i)),
		}
		if err := store.SaveRealm(context.Background(), realms[i]); err != nil {
			t.Fatalf("Failed to save realm %d: %v", i, err)
		}
	}

	// Concurrent access test
	ctx := context.Background()
	errors := make(chan error, numRealms)

	for i := 0; i < numRealms; i++ {
		go func(idx int) {
			_, err := GetRealmInfo(ctx, server.URL, realms[idx].RealmId)
			errors <- err
		}(i)
	}

	// Collect results
	for i := 0; i < numRealms; i++ {
		err := <-errors
		if err != nil {
			t.Errorf("Concurrent request %d failed: %v", i, err)
		}
	}
}

func TestRealmInfo_EmptyRealm(t *testing.T) {
	// Setup
	store, server := newRealmInfoServer(t)
	defer server.Close()

	// Test retrieval of realm with minimal data
	realmID := make([]byte, 32)

	// Realm with only required fields
	minimalRealm := Realm{
		RealmId: realmID,
		AppName: "Minimal App",
		// AppLogo intentionally omitted
	}

	ctx := context.Background()
	if err := store.SaveRealm(ctx, minimalRealm); err != nil {
		t.Fatalf("Failed to save minimal realm: %v", err)
	}

	// Retrieve and verify
	retrieved, err := GetRealmInfo(ctx, server.URL, realmID)
	if err != nil {
		t.Fatalf("GetRealmInfo failed: %v", err)
	}

	if retrieved.AppName != minimalRealm.AppName {
		t.Errorf("AppName mismatch: got %s, want %s", retrieved.AppName, minimalRealm.AppName)
	}
	if len(retrieved.AppLogo) != 0 {
		t.Errorf("Expected empty AppLogo, got %v", retrieved.AppLogo)
	}
}

func newRealmInfoServer(t *testing.T) (ServerCredStore, *httptest.Server) {
	store := NewMemServerCredStore()

	// Create handler and test server
	handler, err := NewRealmInfoHandler(store)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	// create mux
	mux := http.NewServeMux()
	mux.Handle("GET /get-realm-infos/{realmId}", handler)

	return store, httptest.NewServer(mux)
}
