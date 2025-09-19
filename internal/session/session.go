package session

type Store[K comparable, V any] interface {
	Get(key K) (V, bool)
	Pop(key K) (V, bool)
	Set(key K, data V) error
	Save(data V) (K, error)
}

type KeyFactory[K comparable] interface {
	New() K
	Check(key K) error
}
