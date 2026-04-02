package credentials

import (
	"bytes"
	"slices"
	"strings"
	"sync"
)

type ClientCredStore interface {

	// CreateCard saves card in the ClientCredStore.
	// It errors if the card could not be saved.
	CreateCard(card *Card) error

	// RemoveCard removes the card with cId ID from the ClientCredStore.
	// It returns true if the Card was effectively removed.
	RemoveCard(cId int) (bool, error)

	// SetCardLabel assign a new label to the card with cId ID.
	// It errors if the label could not be assigned.
	SetCardLabel(cId int, lbl string) error

	// LoadCard copies ClientCard with ID cId into dst.
	// It errors if the ClientCard could not be copied.
	LoadCard(cId int, dst *ClientCard) error

	// LoadRealm copies the Realm keyed by rId into dst.
	// It errors if the Realm could not be copied
	LoadRealm(rId int, dst *Realm) error

	// ListInfo returns a list of CardInfo that matches qry.
	ListInfo(qry CardQuery) ([]CardInfo, error)

	// CardCount returns the number of Card in the ClientCredStore.
	// It returns -1 in case of error.
	CardCount() int
}

// Card holds the keys necessary for validating/generating EPHEMSEC OTP/OTK & related Realm informations.
type Card struct {
	ID      int              `json:"-" cbor:"-"` // ClientCredStore identifier
	RealmId RealmId          `json:"rid" cbor:"1,keyasint"`
	IdToken IdToken          `json:"idt" cbor:"2,keyasint"`                         // used as CardId with OTK
	UserId  string           `json:"user_id,omitempty" cbor:"3,keyasint,omitempty"` // used as CardId with OTP
	Kh      PrivateKeyHandle `json:"sk" cbor:"4,keyasint"`                          // uses Kh.PrivateKey to obtain the ecdh.PrivateKey
	Psk     []byte           `json:"psk" cbor:"5,keyasint"`
	AppName string           `json:"app_name" cbor:"6,keyasint"`
	AppDesc string           `json:"app_desc,omitempty" cbor:"7,keyasint,omitempty"`
	AppLogo []byte           `json:"app_logo,omitempty" cbor:"8,keyasint,omitempty"`
	Label   string           `json:"label,omitempty" cbor:"9,keyasint,omitempty"`
}

// Check returns an error if the Card is invalid.
func (self *Card) Check() error {
	if nil == self {
		return wrapError(ErrValidation, "nil Card")
	}
	if err := self.RealmId.Check(); nil != err {
		return wrapError(err, "failed RealmId validation")
	}
	if err := self.IdToken.Check(); nil != err {
		return wrapError(err, "failed IdToken validation")
	}
	if nil == self.Kh.PrivateKey {
		return wrapError(ErrValidation, "nil PrivateKey")
	}
	if len(self.Psk) < 32 {
		return wrapError(ErrValidation, "Invalid Psk, length < 32")
	}
	if len(self.AppName) == 0 {
		return wrapError(ErrValidation, "Empty AppName")
	}

	return nil
}

// ClientExport copies the credential fields of the Card into dst as a ClientCard.
// It performs a deep copy of all byte slices (RealmId, IdToken, Psk) to ensure
// the resulting ClientCard is independent of the source Card.
// It errors if dst is nil or if the resulting ClientCard fails validation.
func (self *Card) ClientExport(dst *ClientCard) error {
	if nil == dst {
		return wrapError(ErrValidation, "nil dst ClientCard")
	}

	dst.ID = self.ID

	realmId := make([]byte, len(self.RealmId))
	copy(realmId, self.RealmId)
	dst.RealmId = RealmId(realmId)

	idToken := make([]byte, len(self.IdToken))
	copy(idToken, self.IdToken)
	dst.IdToken = IdToken(idToken)

	dst.UserId = self.UserId

	dst.Kh = self.Kh // inner PrivateKey is immutable

	psk := make([]byte, len(self.Psk))
	copy(psk, self.Psk)
	dst.Psk = psk

	dst.Label = self.Label

	return wrapError(dst.Check(), "failed ClientCard.Check")

}

// RealmExport copies the app display fields of the Card into dst as a Realm.
// It performs a deep copy of byte slices (RealmId, AppLogo) to ensure
// the resulting Realm is independent of the source Card.
// It errors if dst is nil or if the resulting Realm fails validation.
func (self *Card) RealmExport(dst *Realm) error {
	if nil == dst {
		return wrapError(ErrValidation, "nil dst Realm")
	}

	realmId := make([]byte, len(self.RealmId))
	copy(realmId, self.RealmId)
	dst.RealmId = RealmId(realmId)

	dst.AppName = self.AppName

	dst.AppDesc = self.AppDesc

	appLogo := make([]byte, len(self.AppLogo))
	copy(appLogo, self.AppLogo)
	dst.AppLogo = appLogo

	return wrapError(dst.Check(), "failed Realm.Check")
}

// ClientCard holds Card information useful to generate & submit OTP/OTK.
type ClientCard struct {
	ID      int              `json:"-" cbor:"-"` // ClientCredStore identifier
	RealmId RealmId          `json:"rid" cbor:"1,keyasint"`
	IdToken IdToken          `json:"idt" cbor:"2,keyasint"`                         // used as CardId with OTK
	UserId  string           `json:"user_id,omitempty" cbor:"3,keyasint,omitempty"` // used as CardId with OTP
	Kh      PrivateKeyHandle `json:"sk" cbor:"4,keyasint"`                          // uses Kh.PrivateKey to obtain the ecdh.PrivateKey
	Psk     []byte           `json:"psk" cbor:"5,keyasint"`
	Label   string           `json:"label,omitempty" cbor:"9,keyasint,omitempty"`
}

// Check returns an error if the ClientCard is invalid.
func (self *ClientCard) Check() error {
	if nil == self {
		return wrapError(ErrValidation, "nil Card")
	}
	if err := self.RealmId.Check(); nil != err {
		return wrapError(err, "failed RealmId validation")
	}
	if err := self.IdToken.Check(); nil != err {
		return wrapError(err, "failed IdToken validation")
	}
	if nil == self.Kh.PrivateKey {
		return wrapError(ErrValidation, "nil PrivateKey")
	}
	if len(self.Psk) < 32 {
		return wrapError(ErrValidation, "Invalid Psk, length < 32")
	}

	return nil
}

// CardInfo holds Card information useful for display.
type CardInfo struct {
	ID      int    `json:"id" cbor:"1,keyasint"` // ClientCredStore identifier
	RealmID int    `json:"rid" cbor:"1,keyasint"`
	AppName string `json:"app_name" cbor:"6,keyasint"`
	AppDesc string `json:"app_desc,omitempty" cbor:"7,keyasint,omitempty"`
	Label   string `json:"label,omitempty" cbor:"9,keyasint,omitempty"`
}

// CardQuery parametrizes ClientCredStore ListInfo.
type CardQuery struct {
	RealmId []byte
	MinId   int // minimum Card.ID
	Limit   int // maximum number of selected items
}

// Check returns an error if the CardQuery is invalid.
func (self *CardQuery) Check() error {
	if len(self.RealmId) > 0 {
		realmId := RealmId(self.RealmId)
		return wrapError(realmId.Check(), "invalid RealmId")
	}

	return nil
}

// MemClientCredStore provides "in memory" implementation of ClientCredStore.
type MemClientCredStore struct {
	mut         sync.Mutex
	nextCardID  int
	nextRealmID int
	cardTbl     map[int]ClientCard
	tokenIdx    map[[32]byte]int
	realmTbl    map[int]Realm
	realmIdx    map[[32]byte]int
}

func NewMemClientCredStore() *MemClientCredStore {
	return &MemClientCredStore{
		nextCardID:  1,
		nextRealmID: 1,
		cardTbl:     make(map[int]ClientCard),
		tokenIdx:    make(map[[32]byte]int),
		realmTbl:    make(map[int]Realm),
		realmIdx:    make(map[[32]byte]int),
	}
}

// CreateCard saves card in the MemClientCredStore
// It errors if the card could not be saved.
func (self *MemClientCredStore) CreateCard(card *Card) error {
	err := card.Check()
	if nil != err {
		return wrapError(err, "Invalid card")
	}

	self.mut.Lock()
	defer self.mut.Unlock()

	// set realm
	// note that existing realm are updated each time a new card is added.
	var realm Realm
	err = card.RealmExport(&realm)
	if nil != err {
		return wrapError(err, "failed extracting Realm")
	}
	rkey := [32]byte(card.RealmId) // RealmId has validation rule that checks length == 32
	rId, found := self.realmIdx[rkey]
	if !found {
		rId = self.nextRealmID
		self.nextRealmID += 1
		self.realmIdx[rkey] = rId
	}
	self.realmTbl[rId] = realm

	// assign card.ID
	cardkey := [32]byte(card.IdToken) // IdToken has validation rule that checks length == 32
	var curcard ClientCard
	if card.ID > 0 {
		// card must match an existing card
		curcard, found = self.cardTbl[card.ID]
		if !found {
			return newError("pre assigned ID is for non existing Card")
		}
		if (bytes.Compare(card.IdToken, curcard.IdToken) != 0) || (bytes.Compare(card.RealmId, curcard.RealmId) != 0) {
			return wrapError(ErrCardMutation, "ID in use with a different Card")
		}
		return nil // curcard left unchanged
	} else {
		// a card may exist with same IdToken
		cId, found := self.tokenIdx[cardkey]
		if found {
			curcard = self.cardTbl[cId]
			if bytes.Compare(card.RealmId, curcard.RealmId) != 0 {
				return wrapError(ErrCardMutation, "A Card with same IdToken exists in a different Realm")
			}
			card.ID = cId
			return nil // curcard left unchanged
		}
	}
	card.ID = self.nextCardID
	self.nextCardID += 1

	err = card.ClientExport(&curcard)
	if nil != err {
		return wrapError(err, "failed extracting ClientCard")
	}

	self.cardTbl[card.ID] = curcard
	self.tokenIdx[cardkey] = card.ID

	return nil
}

// RemoveCard removes the Card with cId ID from the MemClientCredStore.
// It returns true if the Card was effectively removed.
func (self *MemClientCredStore) RemoveCard(cId int) (bool, error) {
	self.mut.Lock()
	defer self.mut.Unlock()

	card, found := self.cardTbl[cId]
	if found {
		delete(self.cardTbl, cId)
		delete(self.tokenIdx, [32]byte(card.IdToken))
	}

	return found, nil
}

// SetCardLabel assign a new label to the card with cId ID.
// It errors if the label could not be assigned.
func (self *MemClientCredStore) SetCardLabel(cId int, lbl string) error {
	lbl = strings.TrimSpace(lbl)
	if "" == lbl {
		return wrapError(ErrValidation, "empty label")
	}
	self.mut.Lock()
	defer self.mut.Unlock()

	card, found := self.cardTbl[cId]
	if !found {
		return wrapError(ErrNotFound, "missing card")
	}
	card.Label = lbl
	self.cardTbl[cId] = card

	return nil
}

// LoadCard copies ClientCard with ID cId into dst.
// It errors if the ClientCard could not be copied.
func (self *MemClientCredStore) LoadCard(cId int, dst *ClientCard) error {
	self.mut.Lock()
	defer self.mut.Unlock()

	card, found := self.cardTbl[cId]
	if !found {
		return wrapError(ErrNotFound, "missing card")
	}

	dst.ID = cId

	realmId := make([]byte, len(card.RealmId))
	copy(realmId, card.RealmId)
	dst.RealmId = RealmId(realmId)

	idToken := make([]byte, len(card.IdToken))
	copy(idToken, card.IdToken)
	dst.IdToken = IdToken(idToken)

	dst.UserId = card.UserId

	dst.Kh = card.Kh

	psk := make([]byte, len(card.Psk))
	copy(psk, card.Psk)
	dst.Psk = psk

	dst.Label = card.Label

	return nil

}

func (self *MemClientCredStore) LoadRealm(rId int, dst *Realm) error {
	self.mut.Lock()
	defer self.mut.Unlock()

	return self.loadRealm(rId, dst)

}

func (self *MemClientCredStore) loadRealm(rId int, dst *Realm) error {

	realm, found := self.realmTbl[rId]
	if !found {
		return wrapError(ErrNotFound, "missing realm")
	}

	realmId := make([]byte, len(realm.RealmId))
	copy(realmId, realm.RealmId)
	dst.RealmId = RealmId(realmId)

	dst.AppName = realm.AppName

	dst.AppDesc = realm.AppDesc

	appLogo := make([]byte, len(realm.AppLogo))
	copy(appLogo, realm.AppLogo)
	dst.AppLogo = appLogo

	return nil
}

// ListInfo returns a list of CardInfo that matches qry.
func (self *MemClientCredStore) ListInfo(qry CardQuery) ([]CardInfo, error) {
	err := qry.Check()
	if nil != err {
		return nil, wrapError(err, "invalid CardQuery")
	}

	self.mut.Lock()
	defer self.mut.Unlock()

	var infos []CardInfo
	rlmCache := make(map[int]Realm)

	var targetRealm [32]byte
	checkRealm := len(qry.RealmId) > 0
	if checkRealm {
		targetRealm = [32]byte(qry.RealmId)
	}

	for cId, card := range self.cardTbl {
		if cId <= qry.MinId {
			continue
		}
		rk := [32]byte(card.RealmId)
		if checkRealm && targetRealm != rk {
			continue
		}
		rId, found := self.realmIdx[rk]
		if !found {
			// this should not happen if the MemClientCredStore is used properly
			continue
		}
		realm, found := rlmCache[rId]
		if !found {
			err = self.loadRealm(rId, &realm)
			if nil != err {
				return nil, wrapError(err, "failed loading realm")
			}
			rlmCache[rId] = realm
		}

		info := CardInfo{
			ID:      cId,
			RealmID: rId,
			AppName: realm.AppName,
			AppDesc: realm.AppDesc,
			Label:   card.Label,
		}
		infos = append(infos, info)
	}

	// sort infos by ID
	slices.SortFunc(infos, func(c0, c1 CardInfo) int {
		return c0.ID - c1.ID
	})

	// enforce qry.Limit
	if qry.Limit > 0 && len(infos) > qry.Limit {

		infos = infos[0:qry.Limit]
	}

	return infos, nil

}

// Size returns the number of Card in the MemClientCredStore.
func (self *MemClientCredStore) CardCount() int {
	self.mut.Lock()
	defer self.mut.Unlock()

	return len(self.cardTbl)
}

var _ ClientCredStore = &MemClientCredStore{}
