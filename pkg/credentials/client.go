package credentials

import (
	"bytes"
	"encoding/gob"
	"sync"
)

type ClientCredStore interface {

	// SaveCard saves card in the ClientCredStore and returns the assigned ID.
	// It errors if the card could not be saved.
	SaveCard(card Card) (int, error)

	// RemoveCard removes the Card with cId ID from the ClientCredStore.
	// It returns true if the Card was effectively removed.
	RemoveCard(cId int) (bool, error)

	// LoadById loads the Card with ID cid into dst.
	// It returns true if the Card was found and successfully loaded.
	LoadById(cid int, dst *Card) (bool, error)

	// ListInfo returns a list of CardInfo that matches qry.
	ListInfo(qry CardQuery) ([]CardInfo, error)

	// CardCount returns the number of Card in the ClientCredStore.
	// It returns -1 in case of error.
	CardCount() int
}

// Card holds keys necessary for validating/generating EPHEMSEC OTP/OTK.
type Card struct {
	ID      int              `json:"-" cbor:"-"` // ClientCredStore identifier
	RealmId []byte           `json:"1" cbor:"1,keyasint"`
	IdToken []byte           `json:"2" cbor:"2,keyasint"` // used by Server to reference the Card
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
	if len(self.IdToken) != 32 {
		return newError("Invalid IdToken, length != 32")
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

// Info returns a CardInfo{} extracted from self.
func (self Card) Info() CardInfo {
	return CardInfo{ID: self.ID, RealmId: self.RealmId, AppName: self.AppName, AppLogo: self.AppLogo}
}

// CardInfo holds Card information useful for display.
// CardInfo can be used to read Card cbor/json encoding.
type CardInfo struct {
	ID      int    `json:"-" cbor:"-"` // ClientCredStore identifier
	RealmId []byte `json:"1" cbor:"1,keyasint"`
	AppName string `json:"5" cbor:"5,keyasint"`
	AppLogo []byte `json:"6" cbor:"6,keyasint,omitempty"`
}

// CardQuery parametrizes ClientCredStore ListInfo.
type CardQuery struct {
	RealmId []byte
	MinId   int // minimum Card.ID
	Limit   int // maximum number of selected items
}

// MemClientCredStore provides "in memory" implementation of ClientCredStore.
type MemClientCredStore struct {
	mut      sync.Mutex
	maxInt   int
	cardTbl  map[int]Card
	tokenIdx map[[32]byte]int
}

func NewMemClientCredStore() *MemClientCredStore {
	return &MemClientCredStore{
		cardTbl:  make(map[int]Card),
		tokenIdx: make(map[[32]byte]int),
	}
}

// SaveCard saves card in the MemClientCredStore
// It errors if the card could not be saved.
func (self *MemClientCredStore) SaveCard(card Card) (int, error) {
	err := card.Check()
	if nil != err {
		return 0, wrapError(err, "Invalid card")
	}

	var cardkey [32]byte
	copy(cardkey[:], card.IdToken)

	self.mut.Lock()
	defer self.mut.Unlock()

	// assign card.ID
	var curcard Card
	if card.ID > 0 {
		// card must match an existing card
		curcard, found := self.cardTbl[card.ID]
		if !found {
			return 0, newError("pre assigned ID is for non existing Card")
		}
		if (bytes.Compare(card.IdToken, curcard.IdToken) != 0) || (bytes.Compare(card.RealmId, curcard.RealmId) != 0) {
			return 0, wrapError(ErrCardMutation, "ID in use with a different Card")
		}
	} else {
		// a card may exist with same IdToken
		cId, found := self.tokenIdx[cardkey]
		if found {
			curcard = self.cardTbl[cId]
			if bytes.Compare(card.RealmId, curcard.RealmId) != 0 {
				return 0, wrapError(ErrCardMutation, "A Card with same IdToken exists in a different Realm")
			}
			card.ID = cId
		} else {
			self.maxInt += 1
			card.ID = self.maxInt
		}
	}
	self.cardTbl[card.ID] = card
	self.tokenIdx[cardkey] = card.ID

	return card.ID, nil
}

// RemoveCard removes the Card with cId ID from the MemClientCredStore.
// It returns true if the Card was effectively removed.
func (self *MemClientCredStore) RemoveCard(cId int) (bool, error) {
	self.mut.Lock()
	defer self.mut.Unlock()

	card, found := self.cardTbl[cId]
	if found {
		delete(self.cardTbl, cId)

		var cardkey [32]byte
		copy(cardkey[:], card.IdToken)
		delete(self.tokenIdx, cardkey)
	}

	return found, nil
}

// LoadById loads the Card with ID cid into dst.
// It returns true if the Card was found and successfully loaded.
func (self *MemClientCredStore) LoadById(cid int, dst *Card) (bool, error) {
	self.mut.Lock()
	defer self.mut.Unlock()

	var err error
	card, found := self.cardTbl[cid]
	if found {
		var buf bytes.Buffer
		err = gob.NewEncoder(&buf).Encode(card)
		if nil != err {
			return false, wrapError(err, "failed copy serialization")
		}
		err = gob.NewDecoder(&buf).Decode(dst)
		if nil != err {
			return false, wrapError(err, "failed copy deserialization")
		}
	}

	return found, nil
}

// ListInfo returns a list of CardInfo that matches qry.
func (self *MemClientCredStore) ListInfo(qry CardQuery) ([]CardInfo, error) {
	return nil, newError("not implemented")
}

// Size returns the number of Card in the MemClientCredStore.
func (self *MemClientCredStore) CardCount() int {
	self.mut.Lock()
	defer self.mut.Unlock()

	return len(self.cardTbl)
}

var _ ClientCredStore = &MemClientCredStore{}
