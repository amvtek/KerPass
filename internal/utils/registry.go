package utils

import (
	"maps"
	"sync"
)

// Registry holds an inner map[string]T with a mutex to protect accesses.
type Registry[T any] struct {
	mut     sync.RWMutex
	entries map[string]T
}

// NewRegistry returns a Registry[T] pointer.
func NewRegistry[T any]() *Registry[T] {
	return &Registry[T]{entries: make(map[string]T)}
}

// RegistrySet adds a new entry to the Registry. It errors if name is already in use.
func RegistrySet[T any](registry *Registry[T], name string, value T) error {
	registry.mut.Lock()
	defer registry.mut.Unlock()
	_, conflict := registry.entries[name]
	if conflict {
		return newError("name %s already in use", name)
	}
	registry.entries[name] = value
	return nil
}

// RegistryGet returns the value referenced by name and a bool indicating if this value
// exists in the Registry.
func RegistryGet[T any](registry *Registry[T], name string) (T, bool) {
	registry.mut.RLock()
	defer registry.mut.RUnlock()
	rv, ok := registry.entries[name]
	return rv, ok
}

// RegistryEntries returns a copy of the data in the registry.
func RegistryEntries[T any](registry *Registry[T]) map[string]T {
	registry.mut.RLock()
	defer registry.mut.RUnlock()
	return maps.Clone(registry.entries)
}
