package credentials

// KeyStore allows loading KerPass service "static" Keypair.
// Those Keypairs are used to secure service connections.
type KeyStore interface {
	// GetServerKey loads realm static Keypair in srvkey.
	// It returns true if the Keypair was effectively loaded.
	GetServerKey(realmId []byte, srvkey *ServerKey) bool
}

// ServerKey holds an ecdh.PrivateKey with Realm certificate.
type ServerKey struct {
	RealmId     []byte           `json:"1" cbor:"1,keyasint"`
	Kh          PrivateKeyHandle `json:"2" cbor:"2,keyasint"` // uses Kh.PrivateKey to obtain the ecdh.PrivateKey
	Certificate []byte           `json:"3" cbor:"3,keyasint"`
}

// Check returns an error if the ServerKey is invalid.
func (self ServerKey) Check() error {
	if len(self.RealmId) < 32 {
		return newError("Invalid RealmId, length < 32")
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
	// GetEnrollAuthorization loads enrollment authorization data into metas.
	// It returns true if authorization data were successfully loaded.
	GetEnrollAuthorization(authorizationId []byte, metas *EnrollMeta) bool

	// SaveCard saves card in the ServerCredStore.
	// It errors if the card could not be saved.
	SaveCard(card ServerCard) error

	// RemoveCard removes the ServerCard with cardId identifier from the ServerCredStore.
	// It returns true if the ServerCard was effectively removed.
	RemoveCard(cardId []byte) bool
}

// EnrollMeta contains Card creation information.
type EnrollMeta struct {
	RealmId []byte `json:"1" cbor:"1,keyasint"`
	AppName string `json:"2" cbor:"2,keyasint"`
	AppLogo []byte `json:"3" cbor:"3,keyasint,omitempty"`
}

// Check returns an error if the EnrollMeta is invalid.
func (self EnrollMeta) Check() error {
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
	RealmId []byte          `json:"1" cbor:"1,keyasint"`
	CardId  []byte          `json:"2" cbor:"2,keyasint"`
	Kh      PublicKeyHandle `json:"3" cbor:"3,keyasint"` // uses Kh.PublicKey to obtain the ecdh.PublicKey
	Psk     []byte          `json:"4" cbor:"4,keyasint"`
}

// Check returns an error if the ServerCard is invalid.
func (self ServerCard) Check() error {
	if len(self.RealmId) < 32 {
		return newError("Invalid RealmId, length < 32")
	}
	if len(self.CardId) < 32 {
		return newError("Invalid CardId, length < 32")
	}
	if nil == self.Kh.PublicKey {
		return newError("nil PublicKey")
	}
	if len(self.Psk) < 32 {
		return newError("Invalid Psk, length < 32")
	}

	return nil
}
