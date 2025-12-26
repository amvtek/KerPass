package session

import (
	"sync"
)

const (
	numSlot = 16
)

type TimedKey interface {
	comparable
	Timed
}

type slot[K TimedKey, V any] struct {
	mut   sync.RWMutex
	t     int64
	store map[K]V
}

// MemStore is an in memory session Store that automatically expires keys.
type MemStore[K TimedKey, V any] struct {
	KeyFacto KeyFactory[K]
	slots    [numSlot]slot[K, V]
}

// NewMemStore instantiates a new MemStore.
// It errors if kf is nil.
func NewMemStore[K TimedKey, V any](kf KeyFactory[K]) (*MemStore[K, V], error) {
	if nil == kf {
		return nil, newError("nil KeyFactory")
	}

	return &MemStore[K, V]{KeyFacto: kf}, nil
}

// Get returns the value indexed by key.
// The bool flag is true if the key exists in the MemStore.
func (self *MemStore[K, V]) Get(key K) (V, bool) {
	var v V
	var present bool

	if err := self.KeyFacto.Check(key); nil != err {
		return v, present
	}

	ts := key.T()
	slot := &(self.slots[ts%numSlot])
	slot.mut.RLock()
	defer slot.mut.RUnlock()

	if ts == slot.t {
		v, present = slot.store[key]
	}

	return v, present

}

// Pop removes the key from the MemStore and returns the associated value.
// The bool flag is true if the key was found in the MemStore.
func (self *MemStore[K, V]) Pop(key K) (V, bool) {
	var v V
	var present bool

	if err := self.KeyFacto.Check(key); nil != err {
		return v, present
	}

	ts := key.T()
	slot := &(self.slots[ts%numSlot])
	slot.mut.Lock()
	defer slot.mut.Unlock()

	if ts == slot.t {
		v, present = slot.store[key]
		delete(slot.store, key)
	}

	return v, present

}

// Set registers key, data in the MemStore.
// It errors if key is not valid.
func (self *MemStore[K, V]) Set(key K, data V) error {
	// validate key
	err := self.KeyFacto.Check(key)
	if nil != err {
		return wrapError(err, "invalid key")
	}

	// lock storage
	ts := key.T()
	slot := &(self.slots[ts%numSlot])
	slot.mut.Lock()
	defer slot.mut.Unlock()

	if ts != slot.t || nil == slot.store {
		// slot contains expired data
		slot.t = ts
		slot.store = make(map[K]V)
	}
	slot.store[key] = data

	return nil
}

// Save registers data in the MemStore using a new key.
// Save returns the key indexing data.
func (self *MemStore[K, V]) Save(data V) (K, error) {
	var key K

	// generates a key
	key = self.KeyFacto.New(0)

	// lock storage
	ts := key.T()
	slot := &(self.slots[ts%numSlot])
	slot.mut.Lock()
	defer slot.mut.Unlock()

	if ts != slot.t || nil == slot.store {
		// slot contains expired data
		slot.t = ts
		slot.store = make(map[K]V)
	}
	slot.store[key] = data

	return key, nil
}
