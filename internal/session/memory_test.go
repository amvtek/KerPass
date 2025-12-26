package session

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestMemStoreGet(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lifetime := 32 * time.Second
		store := getStore(t, lifetime)

		// Get with a non registered key
		// we use inner KeyFacto to generate this key so that it is valid...
		k := store.KeyFacto.New(6345678)
		_, found := store.Get(k)
		if found {
			t.Error("[0]: store.Get reports found on missing key")
		}

		// Add a value to the store
		err := store.Set(k, "data")
		if nil != err {
			t.Fatalf("[1]: Failed store.Set, got error %v", err)
		}

		// Advance the clock just before expiration limit
		time.Sleep(lifetime - 1*time.Nanosecond)
		v, found := store.Get(k)
		if !found {
			t.Error("[2]: store.Get reports not found on existing key")
		}
		if v != "data" {
			t.Errorf(`[3]: retrieved invalid v "%s" != "data"`, v)
		}

		// Pass the expiration limit
		time.Sleep(2 * time.Nanosecond)
		v, found = store.Get(k)
		if found {
			t.Error("[4]: store.Get reports found on expired key")
		}

	})
}

func TestMemStorePop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lifetime := 16 * time.Second
		store := getStore(t, lifetime)

		// Pop with a non valid key
		k := Sid{}
		_, found := store.Pop(k)
		if found {
			t.Fatal("store.Pop reports found on invalid key")
		}

		// Pop with a non registered key
		// we use inner KeyFacto to generate this key so that it is valid...
		k = store.KeyFacto.New(0xFFEEDDCC_BBAA9988)
		_, found = store.Pop(k)
		if found {
			t.Errorf("store.Pop reports found on missing key")
		}

		// Save data in store
		k, err := store.Save("something")
		if nil != err {
			t.Fatalf("store.Save failed, got error %v", err)
		}

		// try Pop, Pop, Set, Pop, Get, Set multiple times
		deltas := []time.Duration{
			4 * time.Second,
			4 * time.Second,
			4 * time.Second,
			4*time.Second - 1*time.Nanosecond,
		}
		var s string
		for step, delta := range deltas {
			time.Sleep(delta) // advance the clock of delta
			s, found = store.Pop(k)
			if !found {
				t.Fatalf("[%d] store.Pop reports not found with registered key", step)
			}
			if "something" != s {
				t.Fatalf("[%d] store.Pop returned non expected value %s", step, s)
			}
			_, found = store.Pop(k)
			if found {
				t.Fatalf("[%d] store.Pop reports found with missing key", step)
			}
			err = store.Set(k, "some data")
			if nil != err {
				t.Fatalf("[%d] store.Set failed, got error %v", step, err)
			}
			s, found = store.Pop(k)
			if !found {
				t.Fatalf("[%d] store.Pop reports not found with registered key", step)
			}
			if "some data" != s {
				t.Fatalf("[%d] store.Pop returned non expected value %s", step, s)
			}
			_, found = store.Get(k)
			if found {
				t.Fatalf("[%d] store.Get reports found with missing key", step)
			}
			err = store.Set(k, "something")
			if nil != err {
				t.Fatalf("[%d] store.Set failed, got error %v", step, err)
			}

		}
		s, found = store.Get(k)
		if !found {
			t.Fatal("store.Get reports not found with registered key")
		}
		if "something" != s {
			t.Fatalf("store.Pop returned non expected value %s", s)
		}

		// advance the clock to expire the key
		time.Sleep(2 * time.Nanosecond)
		_, found = store.Pop(k)
		if found {
			t.Fatal("store.Pop reports found with expired key")
		}

	})
}

func getStore(t *testing.T, lifetime time.Duration) *MemStore[Sid, string] {
	sidfacto, err := NewSidFactory(lifetime)
	if nil != err {
		t.Fatalf("Failed NewSidFactory, got error %v", err)
	}

	ms := &MemStore[Sid, string]{KeyFacto: sidfacto}

	return ms
}
