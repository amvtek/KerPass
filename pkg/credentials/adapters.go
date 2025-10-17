package credentials

import (
	"context"

	"code.kerpass.org/golang/internal/transport"
)

type sealType int

const (
	KsSealNone = sealType(0)
	KsSealMac  = sealType(1)
	KsSealAead = sealType(2)
)

type contextKey string

const (
	authIdTokenKey = contextKey("AUTHORIZATION_ID_TOKEN")
	cardIdTokenKey = contextKey("CARD_ID_TOKEN")
)

var cborSrz = transport.WrapInSafeSerializer(transport.CBORSerializer{})

type SrvStoreCard struct {
	ID       []byte
	RealmId  []byte
	SealType sealType
	KeyData  []byte
}

type SrvCardStorageAdapter struct {
	sealType sealType
	sealkey  []byte
}

func (self *SrvCardStorageAdapter) GetStorageId(cardIdToken []byte) ([]byte, error) {
	var storeId []byte
	var err error

	sealtype := KsSealNone
	if nil != self {
		sealtype = self.sealType
	}
	switch sealtype {
	case KsSealNone, KsSealMac:
		storeId = cardIdToken
	case KsSealAead:
		// TODO: replace cardIdToken by hash...
		err = newError("TODO: missing AEAD seal implementation")
	default:
		err = newError("Non supported sealType")
	}

	return storeId, err

}

func (self *SrvCardStorageAdapter) ToStorage(cardIdToken []byte, src ServerCard, dst *SrvStoreCard) error {
	var err error

	// check src
	src.CardId = cardIdToken
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

	sealtype := KsSealNone
	if nil != self {
		sealtype = self.sealType
	}
	switch sealtype {
	case KsSealNone:
		dst.ID = cardIdToken
		dst.KeyData = srzkeys

	case KsSealMac:
		dst.ID = cardIdToken
		// TODO:
		// Add mac tag to srzkeys
		// this tag shall bind srzkeys to CardId & RealmId
		return newError("Missing implementation: KsSealMac")

	case KsSealAead:
		// TODO:
		// 1. dst.ID = hash(CardId)
		// 2. derive AEAD key from sealkey, CardId
		//    dst.KeyData = aead.Seal(srzkey, adddata)
		//    and adddata contains RealmId & something related to CardId...
		return newError("Missing implementation: KsSealAEAD")

	default:
		return newError("Invalid seal type")
	}
	dst.RealmId = src.RealmId
	dst.SealType = sealtype

	return err
}

func (self *SrvCardStorageAdapter) FromStorage(cardIdToken []byte, src SrvStoreCard, dst *ServerCard) error {

	// check dst
	if nil == dst {
		return newError("nil dst ServerCard")
	}

	// check seal type compatibility
	sealtype := KsSealNone
	if nil != self {
		sealtype = self.sealType
	}
	if src.SealType != sealtype {
		return newError("src sealType not compatible with adapter")
	}

	var srzkeys []byte
	switch sealtype {
	case KsSealNone:
		dst.CardId = src.ID
		srzkeys = src.KeyData

	case KsSealMac:
		dst.CardId = src.ID
		// TODO: check mac tag on KeyData & set srzkeys...
		return newError("Missing implementation: KsSealMac")

	case KsSealAead:
		// TODO:
		// 1. derive CardId from cardIdToken
		// 2. derive aead key from sealkey & cardIdToken
		// 3. unseal KeyData using aead key & set srzkeys
		return newError("Missing implementation: KsSealAEAD")

	default:
		return newError("Invalid seal type")
	}

	var ck srvCardKey
	err := cborSrz.Unmarshal(srzkeys, &ck)
	if nil != err {
		return wrapError(err, "failed unmarshalling KeyData")
	}

	// fill dst
	dst.RealmId = src.RealmId
	dst.Kh = ck.Kh
	dst.Psk = ck.Psk

	return nil
}

// srvCardKey is an helper struct used for transforming ServerCard keys into KeyData bytes.
type srvCardKey struct {
	Kh  PublicKeyHandle `cbor:"1,keyasint"`
	Psk []byte          `cbor:"2,keyasint"`
}

func (self srvCardKey) Check() error {
	if nil == self.Kh.PublicKey {
		return newError("nil PublicKey")
	}
	if len(self.Psk) < 32 {
		return newError("Invalid Psk, length < 32")
	}

	return nil
}

// GetCardIdToken returns ctx CARD_ID_TOKEN or nil if the value is unset.
func GetCardIdToken(ctx context.Context) []byte {
	var rv []byte
	rv, _ = ctx.Value(cardIdTokenKey).([]byte)
	return rv
}

// SetCardIdToken returns a Context deriving from ctx with value as CARD_ID_TOKEN value.
func SetCardIdToken(ctx context.Context, value []byte) context.Context {
	return context.WithValue(ctx, cardIdTokenKey, value)
}
