package credentials

import (
	"strings"

	"code.kerpass.org/golang/internal/transport"
)

type sealType int

const (
	KsSealNone = sealType(0) // TODO: phase out, all ServerCredStore must encrypt ServerCard keys.
	KsSealAead = sealType(1)
)

var cborSrz = transport.WrapInSafeSerializer(transport.NewCBORSerializer())

// SrvStoreCard is the storage representation of a ServerCard.
// It separates identity (ID, RealmId) from encrypted key material (KeyData).
type SrvStoreCard struct {
	ID       ServerCardIdKey
	RealmId  RealmId
	SealType sealType
	KeyData  []byte
}

// Check returns an error if the SrvStoreCard is invalid.
func (self *SrvStoreCard) Check() error {
	if nil == self {
		return wrapError(ErrValidation, "nil SrvStoreCard")
	}
	if err := self.ID.Check(); err != nil {
		return wrapError(ErrValidation, "failed ID validation")
	}
	if err := self.RealmId.Check(); err != nil {
		return wrapError(ErrValidation, "failed RealmId validation")
	}

	return nil
}

// SrvStoreEnrollAuthorization is the storage representation of an EnrollAuthorization.
// It allows encrypting the UserData.
type SrvStoreEnrollAuthorization struct {
	ID       EnrollIdKey
	RealmId  RealmId
	AppName  string
	AppDesc  string
	AppLogo  []byte
	SealType sealType
	UserData []byte
}

// Check returns an error if the SrvStoreEnrollAuthorization is invalid.
func (self *SrvStoreEnrollAuthorization) Check() error {
	if nil == self {
		return wrapError(ErrValidation, "nil SrvStoreEnrollAuthorization")
	}
	if err := self.ID.Check(); err != nil {
		return wrapError(ErrValidation, "failed ID validation")
	}
	if err := self.RealmId.Check(); err != nil {
		return wrapError(ErrValidation, "failed RealmId validation")
	}
	if 0 == len(strings.TrimSpace(self.AppName)) {
		return wrapError(ErrValidation, "empty AppName")
	}

	return nil
}

// SrvStorageAdapter transforms ServerCard and EnrollAuthorization into encrypted storage representations.
// It uses IdHasher-derived keys to protect sensitive key material and user data at rest.
type SrvStorageAdapter struct {
	idh *IdHasher
}

// NewSrvStorageAdapter creates a SrvStorageAdapter using the provided IdHasher for key derivation.
func NewSrvStorageAdapter(idHasher *IdHasher) (*SrvStorageAdapter, error) {
	if nil == idHasher {
		return nil, wrapError(ErrValidation, "nil idHasher")
	}

	return &SrvStorageAdapter{idh: idHasher}, nil
}

// GetCardAccess derives AccessKeys from a ServerCardAccess credential.
// The returned keys are used to encrypt/decrypt card data in storage.
func (self *SrvStorageAdapter) GetCardAccess(sca ServerCardAccess, dst *AccessKeys) error {
	return wrapError(self.idh.DeriveFromCardAccess(sca, dst), "failed obtaining Card access keys")
}

// ToCardStorage serializes a ServerCard into storage form.
// It marshals key material (Kh, Psk) and seals it using the provided AccessKeys.
func (self *SrvStorageAdapter) ToCardStorage(aks *AccessKeys, src *ServerCard, dst *SrvStoreCard) error {
	var err error

	// check src
	if nil != src {
		src.CardId = aks.IdKey[:]
	}
	err = src.Check()
	if nil != err {
		return wrapError(err, "Invalid src ServerCard")
	}

	// check dst
	if nil == dst {
		return newError("nil dst SrvStoreCard")
	}

	// serialize the keys
	srzkeys, err := cborSrz.Marshal(srvCardKey{
		Kh:  src.Kh,
		Psk: src.Psk,
	})
	if nil != err {
		return wrapError(err, "failed keys serialization")
	}

	// TODO: use aks to encrypt srzkeys

	// initializes dst
	dst.ID = src.CardId
	dst.RealmId = src.RealmId
	dst.SealType = KsSealNone
	dst.KeyData = srzkeys

	return nil
}

// FromCardStorage deserializes and decrypts a SrvStoreCard into a ServerCard.
// It unseals KeyData using the provided AccessKeys and reconstructs the card.
func (self *SrvStorageAdapter) FromCardStorage(aks *AccessKeys, src *SrvStoreCard, dst *ServerCard) error {
	if err := src.Check(); err != nil {
		return wrapError(err, "failed src validation")
	}

	if nil == dst {
		return wrapError(ErrValidation, "nil dst")
	}

	// TODO: use aks to decrypt src.KeyData

	// unmarshal src.KeyData
	var ck srvCardKey
	err := cborSrz.Unmarshal(src.KeyData, &ck)
	if nil != err {
		return wrapError(err, "failed unmarshalling KeyData")
	}

	// initializes dst
	dst.CardId = src.ID
	dst.RealmId = src.RealmId
	dst.Kh = ck.Kh
	dst.Psk = ck.Psk

	return nil

}

// GetEnrollAuthorizationAccess derives AccessKeys from an EnrollAccess credential.
// The returned keys are used to encrypt/decrypt user data in storage.
func (self *SrvStorageAdapter) GetEnrollAuthorizationAccess(ea EnrollAccess, dst *AccessKeys) error {
	return wrapError(self.idh.DeriveFromEnrollAccess(ea, dst), "failed obtaining EnrollAuthorization access keys")
}

// ToEnrollAuthorizationStorage serializes an EnrollAuthorization into storage form.
// It hashes the EnrollToken identifier that grants authorization to create a new Card and encrypts the UserData.
func (self *SrvStorageAdapter) ToEnrollAuthorizationStorage(aks *AccessKeys, src *EnrollAuthorization, dst *SrvStoreEnrollAuthorization) error {
	var err error

	// check src
	if nil != src {
		src.EnrollId = aks.IdKey[:]
	}
	err = src.Check()
	if nil != err {
		return wrapError(err, "Invalid src EnrollAuthorization")
	}

	// check dst
	if nil == dst {
		return newError("nil dst SrvStoreEnrollAuthorization")
	}

	// TODO: use aks to encrypt UserData
	dst.SealType = KsSealNone
	dst.UserData = src.UserData

	// initializes dst
	dst.ID = src.EnrollId
	dst.RealmId = src.RealmId
	dst.AppName = src.AppName
	dst.AppDesc = src.AppDesc
	dst.AppLogo = src.AppLogo

	return nil
}

// FromEnrollAuthorizationStorage deserializes and decrypts a SrvStoreEnrollAuthorization into an EnrollAuthorization.
// It unseals UserData using the provided AccessKeys and reconstructs the EnrollAuthorization.
func (self *SrvStorageAdapter) FromEnrollAuthorizationStorage(aks *AccessKeys, src *SrvStoreEnrollAuthorization, dst *EnrollAuthorization) error {
	if err := src.Check(); err != nil {
		return wrapError(err, "failed src validation")
	}

	if nil == dst {
		return wrapError(ErrValidation, "nil dst")
	}

	// TODO: use aks to decrypt src.UserData
	dst.UserData = src.UserData

	// initializes dst
	dst.EnrollId = src.ID
	dst.RealmId = src.RealmId
	dst.AppName = src.AppName
	dst.AppDesc = src.AppDesc
	dst.AppLogo = src.AppLogo
	dst.AccessKeys = aks

	return nil

}

// srvCardKey holds the sensitive key material extracted from ServerCard for serialization.
type srvCardKey struct {
	Kh  PublicKeyHandle `cbor:"1,keyasint"`
	Psk []byte          `cbor:"2,keyasint"`
}

// Check returns an error if the srvCardKey is invalid.
func (self srvCardKey) Check() error {
	if nil == self.Kh.PublicKey {
		return newError("nil PublicKey")
	}
	if len(self.Psk) < 32 {
		return newError("Invalid Psk, length < 32")
	}

	return nil
}
