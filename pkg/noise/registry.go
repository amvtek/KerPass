package noise

import (
	"sync"
)

// registry holds an inner map[string]T with a mutex to protect accesses.
type registry[T any] struct {
	mut     sync.RWMutex
	entries map[string]T
}

// newRegistry returns a registry[T] pointer.
func newRegistry[T any]() *registry[T] {
	return &registry[T]{entries: make(map[string]T)}
}

// registrySet adds a new entry to self registry. It errors if name is already in use.
func registrySet[T any](self *registry[T], name string, value T) error {
	self.mut.Lock()
	defer self.mut.Unlock()
	_, conflict := self.entries[name]
	if conflict {
		return newError("name %s already in use", name)
	}
	self.entries[name] = value
	return nil
}

// registryGet returns the value referenced by name and a bool indicating if this value
// exists in the registry.
func registryGet[T any](self *registry[T], name string) (T, bool) {
	self.mut.RLock()
	defer self.mut.RUnlock()
	rv, ok := self.entries[name]
	return rv, ok
}
