package credentials

type ClientCredStore interface {

	// SaveCard saves card in the ClientCredStore
	// It errors if the card could not be saved.
	SaveCard(card Card) error

	// RemoveCard removes the Card with cardId identifier from the ClientCredStore.
	// It returns true if the Card was effectively removed.
	RemoveCard(cardId []byte) bool
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
	if len(self.CardId) < 32 {
		return newError("Invalid CardId, length < 32")
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
