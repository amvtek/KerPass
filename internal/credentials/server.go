package credentials

import (
	"sync"
)

// KeyStore allows loading KerPass service "static" Keypair.
// Those Keypairs are used to secure service connections.
type KeyStore interface {
	// GetServerKey loads realm static Keypair in srvkey.
	// It returns true if the Keypair was effectively loaded.
	GetServerKey(realmId []byte, srvkey *ServerKey) bool

	// SaveServer saves srvkey in the KeyStore.
	// It errors if the srvkey could not be saved.
	SaveServerKey(srvkey ServerKey) error
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
	// PopEnrollAuthorization loads authorization data and remove it from the ServerCredStore.
	// It returns true if authorization data were successfully loaded.
	PopEnrollAuthorization(authorizationId []byte, authorization *EnrollAuthorization) bool

	// SaveEnrollAuthorization saves authorization in the ServerCredStore.
	// It errors if the authorization could not be saved.
	SaveEnrollAuthorization(authorization EnrollAuthorization) error

	// AuthorizationCount returns the number of EnrollAuthorization in the ServerCredStore.
	AuthorizationCount() int

	// SaveCard saves card in the ServerCredStore.
	// It errors if the card could not be saved.
	SaveCard(card ServerCard) error

	// RemoveCard removes the ServerCard with cardId identifier from the ServerCredStore.
	// It returns true if the ServerCard was effectively removed.
	RemoveCard(cardId []byte) bool

	// CountCard returns the number of ServerCard in the ServerCredStore.
	CardCount() int
}

// EnrollAuthorization contains Card creation information.
type EnrollAuthorization struct {
	AuthorizationId []byte `json:"-" cbor:"-"`
	RealmId         []byte `json:"1" cbor:"1,keyasint"`
	AppName         string `json:"2" cbor:"2,keyasint"`
	AppLogo         []byte `json:"3" cbor:"3,keyasint,omitempty"`
}

// Check returns an error if the EnrollAuthorization is invalid.
func (self EnrollAuthorization) Check() error {
	if len(self.AuthorizationId) != 32 {
		return newError("Invalid AuthorizationId, length != 32")
	}
	if len(self.RealmId) < 32 {
		return newError("Invalid RealmId, length < 32")
	}
	if 0 == len(self.AppName) {
		return newError("Empty AppName")
	}

	return nil
}

// ServerCard holds keys necessary for validating/generating EPHEMSEC OTP/OTK.
type ServerCard struct {
	CardId  []byte          `json:"-" cbor:"-"`
	RealmId []byte          `json:"1" cbor:"1,keyasint"`
	Kh      PublicKeyHandle `json:"2" cbor:"2,keyasint"` // uses Kh.PublicKey to obtain the ecdh.PublicKey
	Psk     []byte          `json:"3" cbor:"3,keyasint"`
}

// Check returns an error if the ServerCard is invalid.
func (self ServerCard) Check() error {
	if len(self.CardId) != 32 {
		return newError("Invalid CardId, length != 32")
	}
	if len(self.RealmId) < 32 {
		return newError("Invalid RealmId, length < 32")
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
	data map[[32]byte]ServerKey
}

func NewMemKeyStore() *MemKeyStore {
	return &MemKeyStore{data: make(map[[32]byte]ServerKey)}
}

// GetServerKey loads realm static Keypair in srvkey.
// It returns true if the Keypair was effectively loaded.
func (self *MemKeyStore) GetServerKey(realmId []byte, srvkey *ServerKey) bool {
	if len(realmId) != 32 {
		return false
	}
	var realmkey [32]byte
	copy(realmkey[:], realmId)

	self.mut.Lock()
	defer self.mut.Unlock()

	keydata, found := self.data[realmkey]
	if found {
		*srvkey = keydata
	}

	return found
}

// SaveServer saves srvkey in the KeyStore.
// It errors if the srvkey could not be saved.
func (self *MemKeyStore) SaveServerKey(srvkey ServerKey) error {
	err := srvkey.Check()
	if nil != err {
		return wrapError(err, "can not save invalid srvkey")
	}

	var realmkey [32]byte
	copy(realmkey[:], srvkey.RealmId)

	self.mut.Lock()
	defer self.mut.Unlock()

	self.data[realmkey] = srvkey

	return nil
}

var _ KeyStore = &MemKeyStore{}

// MemServerCredStore provides "in memory" implementation of ServerCredStore.
type MemServerCredStore struct {
	mut            sync.Mutex
	authorizations map[[32]byte]EnrollAuthorization
	cards          map[[32]byte]ServerCard
}

func NewMemServerCredStore() *MemServerCredStore {
	return &MemServerCredStore{
		authorizations: make(map[[32]byte]EnrollAuthorization),
		cards:          make(map[[32]byte]ServerCard),
	}
}

// PopEnrollAuthorization loads authorization data and remove it from the MemServerCredStore.
// It returns true if authorization data were successfully loaded.
func (self *MemServerCredStore) PopEnrollAuthorization(authorizationId []byte, authorization *EnrollAuthorization) bool {
	if len(authorizationId) != 32 {
		return false
	}
	var atk [32]byte
	copy(atk[:], authorizationId)

	self.mut.Lock()
	defer self.mut.Unlock()

	atd, found := self.authorizations[atk]
	if found {
		*authorization = atd
		authorization.AuthorizationId = authorizationId
		delete(self.authorizations, atk)
	}

	return found
}

// SaveEnrollAuthorization saves authorization in the MemServerCredStore.
// It errors if the authorization could not be saved.
func (self *MemServerCredStore) SaveEnrollAuthorization(authorization EnrollAuthorization) error {
	err := authorization.Check()
	if nil != err {
		return wrapError(err, "can not save invalid authorization")
	}

	var atk [32]byte
	copy(atk[:], authorization.AuthorizationId)

	self.mut.Lock()
	defer self.mut.Unlock()

	self.authorizations[atk] = authorization

	return nil
}

// AuthorizationCount returns the number of EnrollAuthorization in the MemServerCredStore.
func (self *MemServerCredStore) AuthorizationCount() int {
	self.mut.Lock()
	defer self.mut.Unlock()

	return len(self.authorizations)
}

// SaveCard saves card in the MemServerCredStore.
// It errors if the card could not be saved.
func (self *MemServerCredStore) SaveCard(card ServerCard) error {
	err := card.Check()
	if nil != err {
		return wrapError(err, "can not save invalid card")
	}

	var ck [32]byte
	copy(ck[:], card.CardId)

	self.mut.Lock()
	defer self.mut.Unlock()

	self.cards[ck] = card

	return nil
}

// RemoveCard removes the ServerCard with cardId identifier from the MemServerCredStore.
// It returns true if the ServerCard was effectively removed.
func (self *MemServerCredStore) RemoveCard(cardId []byte) bool {
	if len(cardId) != 32 {
		return false
	}

	var ck [32]byte
	copy(ck[:], cardId)

	self.mut.Lock()
	defer self.mut.Unlock()

	_, found := self.cards[ck]
	if found {
		delete(self.cards, ck)
	}

	return found
}

// CardCount returns the number of ServerCard in the MemServerCredStore.
func (self *MemServerCredStore) CardCount() int {
	self.mut.Lock()
	defer self.mut.Unlock()

	return len(self.cards)
}

var _ ServerCredStore = &MemServerCredStore{}
