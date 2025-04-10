package noise

import (
	"sync"
)

type registry[T any] struct {
	mut     sync.RWMutex
	entries map[string]T
}

func newRegistry[T any]() *registry[T] {
	return &registry[T]{entries: make(map[string]T)}
}

func registrySet[T any](self *registry[T], name string, value T) error {
	self.mut.Lock()
	defer self.mut.Unlock()
	_, conflict := self.entries[name]
	if conflict {
		return ErrRegistrationConflict
	}
	self.entries[name] = value
	return nil
}

func registryGet[T any](self *registry[T], name string) (T, bool) {
	self.mut.RLock()
	defer self.mut.RUnlock()
	rv, ok := self.entries[name]
	return rv, ok
}
