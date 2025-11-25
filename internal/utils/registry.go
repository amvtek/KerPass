package utils

import (
	"maps"
	"sync"
)

// Registry holds an inner map[K]V with a mutex to protect accesses.
type Registry[K comparable, V any] struct {
	mut     sync.RWMutex
	entries map[K]V
}

// NewRegistry returns a Registry[K, V] pointer.
func NewRegistry[K comparable, V any]() *Registry[K, V] {
	return &Registry[K, V]{entries: make(map[K]V)}
}

// RegistrySet adds a new entry to the Registry. It errors if name is already in use.
func RegistrySet[K comparable, V any](registry *Registry[K, V], name K, value V) error {
	registry.mut.Lock()
	defer registry.mut.Unlock()
	_, conflict := registry.entries[name]
	if conflict {
		return newError("name already in use")
	}
	registry.entries[name] = value
	return nil
}

// RegistryGet returns the value referenced by name and a bool indicating if this value
// exists in the Registry.
func RegistryGet[K comparable, V any](registry *Registry[K, V], name K) (V, bool) {
	registry.mut.RLock()
	defer registry.mut.RUnlock()
	rv, ok := registry.entries[name]
	return rv, ok
}

// RegistryEntries returns a copy of the data in the registry.
func RegistryEntries[K comparable, V any](registry *Registry[K, V]) map[K]V {
	registry.mut.RLock()
	defer registry.mut.RUnlock()
	return maps.Clone(registry.entries)
}
