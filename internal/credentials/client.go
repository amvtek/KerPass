package credentials

import (
	"sync"
)

type ClientCredStore interface {

	// SaveCard saves card in the ClientCredStore
	// It errors if the card could not be saved.
	SaveCard(card Card) error

	// RemoveCard removes the Card with cardId identifier from the ClientCredStore.
	// It returns true if the Card was effectively removed.
	RemoveCard(cardId []byte) bool

	// Size returns the number of Card in the ClientCredStore.
	Size() int
}

// Card holds keys necessary for validating/generating EPHEMSEC OTP/OTK.
type Card struct {
	RealmId []byte           `json:"1" cbor:"1,keyasint"`
	CardId  []byte           `json:"2" cbor:"2,keyasint"`
	Kh      PrivateKeyHandle `json:"3" cbor:"3,keyasint"` // uses Kh.PrivateKey to obtain the ecdh.PrivateKey
	Psk     []byte           `json:"4" cbor:"4,keyasint"`
	AppName string           `json:"5" cbor:"5,keyasint"`
	AppLogo []byte           `json:"6" cbor:"6,keyasint,omitempty"`
}

// Check returns an error if the Card is invalid.
func (self Card) Check() error {
	if len(self.RealmId) < 32 {
		return newError("Invalid RealmId, length < 32")
	}
	if len(self.CardId) != 32 {
		return newError("Invalid CardId, length != 32")
	}
	if nil == self.Kh.PrivateKey {
		return newError("nil PrivateKey")
	}
	if len(self.Psk) < 32 {
		return newError("Invalid Psk, length < 32")
	}
	if len(self.AppName) == 0 {
		return newError("Empty AppName")
	}

	return nil
}

// MemClientCredStore provides "in memory" implementation of ClientCredStore.
type MemClientCredStore struct {
	mut  sync.Mutex
	data map[[32]byte]Card
}

func NewMemClientCredStore() *MemClientCredStore {

	return &MemClientCredStore{data: make(map[[32]byte]Card)}
}

// SaveCard saves card in the MemClientCredStore
// It errors if the card could not be saved.
func (self *MemClientCredStore) SaveCard(card Card) error {
	err := card.Check()
	if nil != err {
		return wrapError(err, "Invalid card")
	}

	var cardkey [32]byte
	copy(cardkey[:], card.CardId)
	self.mut.Lock()
	defer self.mut.Unlock()
	self.data[cardkey] = card

	return nil
}

// RemoveCard removes the Card with cardId identifier from the MemClientCredStore.
// It returns true if the Card was effectively removed.
func (self *MemClientCredStore) RemoveCard(cardId []byte) bool {
	if len(cardId) != 32 {
		return false
	}
	var cardkey [32]byte
	copy(cardkey[:], cardId)

	self.mut.Lock()
	defer self.mut.Unlock()

	_, found := self.data[cardkey]
	if found {
		delete(self.data, cardkey)
	}

	return found
}

// Size returns the number of Card in the MemClientCredStore.
func (self *MemClientCredStore) Size() int {
	self.mut.Lock()
	defer self.mut.Unlock()

	return len(self.data)
}

var _ ClientCredStore = &MemClientCredStore{}
