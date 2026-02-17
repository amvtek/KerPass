package credentials

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
)

// KeyStore allows loading KerPass service "static" Keypair.
// Those Keypairs are used to secure service connections.
type KeyStore interface {
	// GetServerKey loads realm static Keypair in srvkey.
	// It returns true if the Keypair was effectively loaded.
	GetServerKey(ctx context.Context, realmId []byte, name string, srvkey *ServerKey) bool

	// SaveServer saves srvkey in the KeyStore.
	// It errors if the srvkey could not be saved.
	SaveServerKey(ctx context.Context, name string, srvkey ServerKey) error
}

// ServerKey holds an ecdh.PrivateKey with Realm certificate.
type ServerKey struct {
	RealmId     []byte           `json:"1" cbor:"1,keyasint"`
	Kh          PrivateKeyHandle `json:"2" cbor:"2,keyasint"` // uses Kh.PrivateKey to obtain the ecdh.PrivateKey
	Certificate []byte           `json:"3" cbor:"3,keyasint"`
}

// Check returns an error if the ServerKey is invalid.
func (self ServerKey) Check() error {
	if len(self.RealmId) != 32 {
		return newError("Invalid RealmId, length != 32")
	}
	if nil == self.Kh.PrivateKey {
		return newError("nil Keypair")
	}
	if 0 == len(self.Certificate) {
		return newError("Empty Certificate")
	}

	return nil
}

// ServerCredStore gives access to KerPass server credential database.
type ServerCredStore interface {

	// ListRealm lists the Realm in the ServerCredStore.
	// It errors if the ServerCredStore is not reachable.
	ListRealm(ctx context.Context) ([]Realm, error)

	// LoadRealm loads realm data for realmId into dst.
	// It errors if realm data were not successfully loaded.
	LoadRealm(ctx context.Context, realmId RealmId, dst *Realm) error

	// SaveRealm saves realm into the ServerCredStore.
	// SaveRealm may modify realm before/after saving it, eg to record actual storage key.
	// It errors if realm could not be saved.
	SaveRealm(ctx context.Context, realm *Realm) error

	// RemoveRealm removes the Realm with realmId identifier from the ServerCredStore.
	// It errors if the ServerCredStore is not reachable or if realmId does not exists.
	RemoveRealm(ctx context.Context, realmId RealmId) error

	// PopEnrollAuthorization loads authorization data and remove it from the ServerCredStore.
	// It errors if authorization data were not successfully loaded.
	PopEnrollAuthorization(ctx context.Context, authorizationId []byte, authorization *EnrollAuthorization) error

	// SaveEnrollAuthorization saves authorization in the ServerCredStore.
	// SaveEnrollAuthorization may modify authorization before/after saving it, eg to record actual storage key.
	// It errors if the authorization could not be saved.
	SaveEnrollAuthorization(ctx context.Context, authorization *EnrollAuthorization) error

	// AuthorizationCount returns the number of EnrollAuthorization in the ServerCredStore.
	AuthorizationCount(ctx context.Context) (int, error)

	// LoadCard loads stored card data in dst.
	// It errors if card data were not successfully loaded.
	LoadCard(ctx context.Context, cardId ServerCardAccess, dst *ServerCard) error

	// SaveCard saves card in the ServerCredStore.
	// SaveCard may modify card before/after saving it, eg to record actual storage key.
	// It errors if the card could not be saved.
	SaveCard(ctx context.Context, card *ServerCard) error

	// RemoveCard removes the ServerCard with cardId identifier from the ServerCredStore.
	// It returns true if the ServerCard was effectively removed.
	RemoveCard(ctx context.Context, cardId ServerCardKey) bool

	// CountCard returns the number of ServerCard in the ServerCredStore.
	CardCount(ctx context.Context) (int, error)
}

// A Realm is a trusted domain managed by a single authority,
// within which Cards and Application can mutually verify each other’s identity.
type Realm struct {
	RealmId RealmId `json:"id" cbor:"1,keyasint"`
	AppName string  `json:"app_name" cbor:"2,keyasint"`
	AppDesc string  `json:"app_desc,omitempty" cbor:"3,keyasint,omitempty"`
	AppLogo []byte  `json:"app_logo,omitempty" cbor:"4,keyasint,omitempty"`
}

// Check returns an error if the Realm is invalid.
func (self *Realm) Check() error {
	if nil == self {
		return newError("nil Realm")
	}
	if len(self.RealmId) < 32 {
		return newError("Invalid RealmId, length < 32")
	}
	if 0 == len(strings.TrimSpace(self.AppName)) {
		return newError("Empty AppName")
	}

	return nil
}

// EnrollAuthorization contains Card creation information.
type EnrollAuthorization struct {
	AuthorizationId []byte          `json:"-" cbor:"-"`
	RealmId         []byte          `json:"rid" cbor:"1,keyasint"`
	AppName         string          `json:"app_name" cbor:"2,keyasint"`
	AppDesc         string          `json:"app_desc,omitempty" cbor:"3,keyasint,omitempty"`
	AppLogo         []byte          `json:"app_logo,omitempty" cbor:"4,keyasint,omitempty"`
	UserData        json.RawMessage `json:"user_data,omitempty" cbor:"5,keyasint,omitempty"`
}

// Check returns an error if the EnrollAuthorization is invalid.
func (self *EnrollAuthorization) Check() error {
	if nil == self {
		return newError("nil EnrollAuthorization")
	}
	if len(self.AuthorizationId) != 32 {
		return newError("Invalid AuthorizationId, length != 32")
	}
	if len(self.RealmId) < 32 {
		return newError("Invalid RealmId, length < 32")
	}
	if 0 == len(strings.TrimSpace(self.AppName)) {
		return newError("Empty AppName")
	}

	return nil
}

// ServerCard holds keys necessary for validating/generating EPHEMSEC OTP/OTK.
type ServerCard struct {
	CardId     ServerCardIdKey `json:"-" cbor:"-"`
	RealmId    RealmId         `json:"rid" cbor:"2,keyasint"`
	Kh         PublicKeyHandle `json:"pubkey" cbor:"3,keyasint"` // uses Kh.PublicKey to obtain the ecdh.PublicKey
	Psk        []byte          `json:"psk" cbor:"4,keyasint"`
	AccessKeys *AccessKeys     `json:"-" cbor:"-"`
}

// Check returns an error if the ServerCard is invalid.
func (self *ServerCard) Check() error {
	if nil == self {
		return newError("nil ServerCard")
	}
	var err error
	if err = self.CardId.Check(); err != nil {
		return wrapError(err, "failed CardId validation")
	}
	if err = self.RealmId.Check(); err != nil {
		return wrapError(err, "failed RealmId validation")
	}
	if nil == self.Kh.PublicKey {
		return newError("nil PublicKey")
	}
	if len(self.Psk) < 32 {
		return newError("Invalid Psk, length < 32")
	}

	return nil
}

// MemKeyStore provides "in memory" implementation of KeyStore.
type MemKeyStore struct {
	mut  sync.Mutex
	data map[keyref]ServerKey
}

func NewMemKeyStore() *MemKeyStore {
	return &MemKeyStore{data: make(map[keyref]ServerKey)}
}

type keyref struct {
	realmkey [32]byte
	name     string
}

// GetServerKey loads realm static Keypair in srvkey.
// It returns true if the Keypair was effectively loaded.
func (self *MemKeyStore) GetServerKey(_ context.Context, realmId []byte, name string, srvkey *ServerKey) bool {
	if len(realmId) != 32 {
		return false
	}
	kr := keyref{name: name}
	copy(kr.realmkey[:], realmId)

	self.mut.Lock()
	defer self.mut.Unlock()

	keydata, found := self.data[kr]
	if found {
		*srvkey = keydata
	}

	return found
}

// SaveServer saves srvkey in the KeyStore.
// It errors if the srvkey could not be saved.
func (self *MemKeyStore) SaveServerKey(_ context.Context, name string, srvkey ServerKey) error {
	err := srvkey.Check()
	if nil != err {
		return wrapError(err, "can not save invalid srvkey")
	}

	kr := keyref{name: name}
	copy(kr.realmkey[:], srvkey.RealmId)

	self.mut.Lock()
	defer self.mut.Unlock()

	self.data[kr] = srvkey

	return nil
}

var _ KeyStore = &MemKeyStore{}

// MemServerCredStore provides "in memory" implementation of ServerCredStore.
type MemServerCredStore struct {
	mut            sync.Mutex
	realms         map[[32]byte]Realm
	authorizations map[[32]byte]EnrollAuthorization
	cards          map[[32]byte]ServerCard
}

func NewMemServerCredStore() *MemServerCredStore {
	return &MemServerCredStore{
		realms:         make(map[[32]byte]Realm),
		authorizations: make(map[[32]byte]EnrollAuthorization),
		cards:          make(map[[32]byte]ServerCard),
	}
}

// ListRealm lists the Realms in the ServerCredStore.
// It errors if the ServerCredStore is not reachable.
func (self *MemServerCredStore) ListRealm(_ context.Context) ([]Realm, error) {
	self.mut.Lock()
	defer self.mut.Unlock()

	realms := make([]Realm, 0, len(self.realms))
	for _, realm := range self.realms {
		realms = append(realms, realm)
	}

	return realms, nil
}

// LoadRealm loads realm data for realmId into dst.
// It errors if realm data were not successfully loaded.
func (self *MemServerCredStore) LoadRealm(_ context.Context, realmId RealmId, dst *Realm) error {
	if len(realmId) != 32 {
		return wrapError(ErrNotFound, "invalid realmId")
	}
	self.mut.Lock()
	defer self.mut.Unlock()

	realm, found := self.realms[[32]byte(realmId)]
	if !found {
		return wrapError(ErrNotFound, "unknown realmId")
	}
	*dst = realm
	dst.RealmId = realmId

	return nil
}

// SaveRealm saves realm into the ServerCredStore.
// It errors if realm could not be saved.
func (self *MemServerCredStore) SaveRealm(_ context.Context, realm *Realm) error {
	err := realm.Check()
	if nil != err {
		return wrapError(err, "Invalid realm")
	}

	self.mut.Lock()
	defer self.mut.Unlock()

	self.realms[[32]byte(realm.RealmId)] = *realm

	return nil

}

// RemoveRealm removes the Realm with realmId identifier from the ServerCredStore.
// It errors if the ServerCredStore is not reachable or if realmId does not exists.
func (self *MemServerCredStore) RemoveRealm(_ context.Context, realmId RealmId) error {
	if len(realmId) != 32 {
		return wrapError(ErrNotFound, "invalid realmId")
	}

	rid := [32]byte(realmId)

	self.mut.Lock()
	defer self.mut.Unlock()

	_, found := self.realms[rid]
	if !found {
		return wrapError(ErrNotFound, "unknown realmId")
	}

	delete(self.realms, rid)

	return nil

}

// PopEnrollAuthorization loads authorization data and remove it from the MemServerCredStore.
// It errors if authorization data were not successfully loaded.
func (self *MemServerCredStore) PopEnrollAuthorization(_ context.Context, authorizationId []byte, authorization *EnrollAuthorization) error {
	if len(authorizationId) != 32 {
		return wrapError(ErrNotFound, "invalid authorizationId")
	}
	var atk [32]byte
	copy(atk[:], authorizationId)

	self.mut.Lock()
	defer self.mut.Unlock()

	atd, found := self.authorizations[atk]
	if !found {
		return wrapError(ErrNotFound, "unknown authorizationId")
	}

	*authorization = atd
	authorization.AuthorizationId = authorizationId
	delete(self.authorizations, atk)

	return nil
}

// SaveEnrollAuthorization saves atz authorization in the MemServerCredStore.
// It errors if the authorization could not be saved.
func (self *MemServerCredStore) SaveEnrollAuthorization(_ context.Context, atz *EnrollAuthorization) error {
	err := atz.Check()
	if nil != err {
		return wrapError(err, "can not save invalid authorization")
	}

	self.mut.Lock()
	defer self.mut.Unlock()

	self.authorizations[[32]byte(atz.AuthorizationId)] = *atz

	return nil
}

// AuthorizationCount returns the number of EnrollAuthorization in the MemServerCredStore.
func (self *MemServerCredStore) AuthorizationCount(_ context.Context) (int, error) {
	self.mut.Lock()
	defer self.mut.Unlock()

	return len(self.authorizations), nil
}

// LoadCard loads stored card data in dst.
// It errors if card data were not successfully loaded.
func (self *MemServerCredStore) LoadCard(_ context.Context, cardId ServerCardAccess, dst *ServerCard) error {

	var ck [32]byte
	switch v := cardId.(type) {
	case IdToken:
		ck = [32]byte(v)
	default:
		return wrapError(ErrNotFound, "non supported cardId type")
	}

	self.mut.Lock()
	defer self.mut.Unlock()

	var err error
	card, found := self.cards[ck]
	if found {
		*dst = card
	} else {
		err = wrapError(ErrNotFound, "unknown cardId")
	}

	return err
}

// SaveCard saves card in the MemServerCredStore.
// It errors if the card could not be saved.
func (self *MemServerCredStore) SaveCard(_ context.Context, card *ServerCard) error {
	err := card.Check()
	if nil != err {
		return wrapError(err, "can not save invalid card")
	}

	self.mut.Lock()
	defer self.mut.Unlock()

	self.cards[[32]byte(card.CardId)] = *card

	return nil
}

// RemoveCard removes the ServerCard with cardId identifier from the MemServerCredStore.
// It returns true if the ServerCard was effectively removed.
func (self *MemServerCredStore) RemoveCard(_ context.Context, cardId ServerCardKey) bool {
	var ck [32]byte
	switch v := cardId.(type) {
	case ServerCardIdKey:
		ck = [32]byte(v)
	case IdToken:
		ck = [32]byte(v)
	default:
		// cardId type is not supported
		return false
	}

	self.mut.Lock()
	defer self.mut.Unlock()

	_, found := self.cards[ck]
	if found {
		delete(self.cards, ck)
	}

	return found
}

// CardCount returns the number of ServerCard in the MemServerCredStore.
func (self *MemServerCredStore) CardCount(_ context.Context) (int, error) {
	self.mut.Lock()
	defer self.mut.Unlock()

	return len(self.cards), nil
}

var _ ServerCredStore = &MemServerCredStore{}
