package credentials

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"slices"

	"golang.org/x/crypto/hkdf"
)

const (
	// DO NOT EDIT THOSE CONSTANTS
	defaultHashingSeed = "Hashing seed must be stored reliably and should not be changed"

	markRealm = byte('R')
	markInfo  = byte('I')
)

const (
	saltUserId = iota
	saltIdToken
	saltEnrollToken
	numSalts
)

var (
	// DO NOT EDIT saltNames values
	saltNames = []string{
		"salt:card:UserId/IdToken",
		"salt:card:IdToken/Derivation",
		"salt:authorization:EnrollToken/Derivation",
	}
)

// UserIdFactory defines the interface used to deterministically derive a
// UserId string from arbitrary user-provided data.
//
// Implementations must ensure that the returned UserId is stable for the same
// input and normalized consistently, as it may participate in cryptographic
// derivations (e.g., IdToken generation).
type UserIdFactory interface {
	// MakeUserId returns an UserId string generated after processing "User Data" ud
	MakeUserId(ud json.RawMessage) (string, error)
}

// UserIdFactoryFunc is an adapter type to allow using ordinary functions as UserIdFactory.
type UserIdFactoryFunc func(json.RawMessage) (string, error)

func (self UserIdFactoryFunc) MakeUserId(ud json.RawMessage) (string, error) {
	return self(ud)
}

// CardRef represents the client/server linkage for a Card credential.
type CardRef struct {
	// ClientIdToken is held by the client and used to derive access keys.
	ClientIdToken [32]byte

	// ClientUserId is optional.
	// When present it is used to derive a ClientIdToken.
	ClientUserId string

	// ServerCardId is held by the server and used to load a Card.
	// It derives from ClientIdToken.
	ServerCardId [32]byte
}

// AccessKeys holds the result of HKDF-based derivations from either IdToken or EnrollToken.
type AccessKeys struct {
	// IdKey is used as a server-side identifier for Card or EnrollAuthorization subjects.
	IdKey [32]byte

	// StorageKey is used to protect subject sensitive data.
	StorageKey [32]byte
}

// Check returns an error if the AccessKeys are invalid.
func (self *AccessKeys) Check() error {
	if nil == self {
		return wrapError(ErrValidation, "nil AccessKey")
	}
	zeros := [32]byte{}
	if self.IdKey == zeros {
		return wrapError(ErrValidation, "IdKey is 0")
	}
	if self.StorageKey == zeros {
		return wrapError(ErrValidation, "StorageKey is 0")
	}

	return nil
}

// IdHasher manages domain-separated HKDF-based derivations used by the credential system.
//
// It encapsulates context-specific salts derived from a high-entropy server seed.
//
// IdHasher is safe for concurrent use.
type IdHasher struct {
	salts [numSalts][32]byte
}

// NewIdHasher initializes an IdHasher using the provided seed as the root secret for
// all HKDF-based derivations performed by this instance.
//
// The seed is used to derive context-specific salts and functions as a server-side
// diversification secret (similar to a pepper).
//
// Security considerations:
//
//   - If IdTokens are high-entropy (e.g., randomly generated 256-bit values), seed
//     secrecy provides defense-in-depth and domain separation but is not strictly
//     required to preserve IdToken unpredictability.
//
//   - If IdTokens may be deterministically derived from low-entropy inputs (e.g., UserId),
//     keeping the seed secret prevents offline enumeration and precomputation attacks
//     in case server-side card storage is exposed.
//
// Changing the seed invalidates all previously derived identifiers and will prevent existing
// cards from being located. The seed should therefore be **stable** for the lifetime of stored
// credentials within a given deployment.
//
// For production use, the seed should be generated with high entropy and stored using appropriate
// operational protections.
func NewIdHasher(seed []byte) (*IdHasher, error) {
	if 0 == len(seed) {
		seed = []byte(defaultHashingSeed)
	}
	prk := hkdf.Extract(sha256.New, seed, nil)

	var rdr io.Reader
	var err error
	idh := &IdHasher{}
	for i := range numSalts {
		rdr = hkdf.Expand(sha256.New, prk, []byte(saltNames[i]))
		_, err = io.ReadFull(rdr, idh.salts[i][:])
		if nil != err {
			return nil, wrapError(err, "failed initializing salts[%d]", i)
		}
	}

	return idh, nil
}

// IdTokenOfUserId deterministically derives a 32-byte IdToken from a (realmId, userId) pair.
//
// The derivation uses HKDF with a context-specific salt derived from the IdHasher seed.
// If userId has low entropy, the secrecy of the seed protects against offline guessing attacks.
//
// realmId must be exactly 32 bytes and uniquely identify a security domain. The returned IdToken
// is suitable for subsequent key derivations but must not be assumed to contain full entropy
// unless userId does.
func (self *IdHasher) IdTokenOfUserId(realmId []byte, userId string, dst []byte) ([]byte, error) {
	if len(realmId) != 32 {
		return nil, wrapError(ErrValidation, "invalid realmId, length != 32")
	}
	if "" == userId {
		return nil, wrapError(ErrValidation, "empty userId")
	}
	if len(userId) > 255 {
		return nil, wrapError(ErrValidation, "invalid userId, len  > 255")
	}

	// generates key derivation info
	var info bytes.Buffer
	info.Write([]byte{markInfo, byte(len("UserId/IdToken"))})
	info.Write([]byte("UserId/IdToken"))
	info.Write([]byte{markRealm, byte(len(realmId))})
	info.Write(realmId)

	// userId is a low quality input key material
	// good IdToken are generated randomly, but they are only usable with OTK not OTP...
	rdr := hkdf.New(sha256.New, []byte(userId), self.salts[saltUserId][:], info.Bytes())
	dst = slices.Grow(dst, 32)[:32]
	rdr.Read(dst)

	return dst, nil
}

// DeriveFromCardAccess derives access keys from a [ServerCardAccess] key.
//
// It produces domain-separated keys for:
//   - IdKey: used as a server-side card identifier.
//   - StorageKey: used to protect card-related stored data.
//
// The derivation is deterministic and bound to the IdHasher seed.
func (self *IdHasher) DeriveFromCardAccess(sca ServerCardAccess, dst *AccessKeys) error {
	var err error

	if chk, ok := sca.(interface{ Check() error }); ok {
		err = chk.Check()
		if nil != err {
			return wrapError(err, "failed sca Check")
		}
	}

	var idtkn IdToken
	switch v := sca.(type) {
	case IdToken:
		idtkn = v
	case OtpId:
		idtkn, err = self.IdTokenOfUserId(v.Realm, v.Username, nil)
		if nil != err {
			return wrapError(err, "failed deriving IdToken")
		}

	default:
		return wrapError(ErrValidation, "non supported ServerCardAccess")
	}

	return wrapError(self.deriveFromIdToken(idtkn, dst), "failed deriveFromIdToken")

}

// deriveFromIdToken derives access keys from a 32-byte [IdToken].
//
// It produces domain-separated keys for:
//   - IdKey: used as a server-side card identifier.
//   - StorageKey: used to protect card-related stored data.
//
// The derivation is deterministic and bound to the IdHasher seed. The IdToken must
// contain sufficient entropy for the intended security level.
func (self *IdHasher) deriveFromIdToken(idToken []byte, dst *AccessKeys) error {
	prk := hkdf.Extract(sha256.New, idToken, self.salts[saltIdToken][:])

	var rdr io.Reader
	var err error

	// IdKey derivation
	rdr = hkdf.Expand(sha256.New, prk, []byte("IdToken/IdKey"))
	_, err = io.ReadFull(rdr, dst.IdKey[:])
	if nil != err {
		return wrapError(err, "failed IdKey derivation")
	}

	// StorageKey derivation
	rdr = hkdf.Expand(sha256.New, prk, []byte("IdToken/StorageKey"))
	_, err = io.ReadFull(rdr, dst.StorageKey[:])
	if nil != err {
		return wrapError(err, "failed StorageKey derivation")
	}

	return nil
}

// DeriveFromEnrollAccess derives access keys from an [EnrollAccess].
//
// It produces domain-separated keys for:
//   - IdKey: used as a server-side EnrollAuthorization identifier.
//   - StorageKey: used to protect EnrollAuthorization  user data.
//
// The derivation is deterministic and bound to the IdHasher seed.
func (self *IdHasher) DeriveFromEnrollAccess(ea EnrollAccess, dst *AccessKeys) error {
	var err error

	// check ea validity
	if chk, ok := ea.(interface{ Check() error }); ok {
		err = chk.Check()
		if nil != err {
			return wrapError(err, "failed ea Check")
		}
	}

	switch v := ea.(type) {
	case EnrollToken:
		return wrapError(self.deriveFromEnrollToken(v, dst), "failed deriveFromEnrollToken")
	default:
		return wrapError(ErrValidation, "non supported ServerCardAccess")
	}
}

// deriveFromEnrollToken derives access keys from a 32-byte [EnrollToken].
//
// It produces domain-separated keys for:
//   - IdKey: used as a server-side EnrollAuthorization identifier.
//   - StorageKey: used to protect EnrollAuthorization  user data.
//
// The derivation is deterministic and bound to the IdHasher seed. EnrollToken must
// contain sufficient entropy for the intended security level.
func (self *IdHasher) deriveFromEnrollToken(enrollToken []byte, dst *AccessKeys) error {
	prk := hkdf.Extract(sha256.New, enrollToken, self.salts[saltEnrollToken][:])

	var rdr io.Reader
	var err error

	// IdKey derivation
	rdr = hkdf.Expand(sha256.New, prk, []byte("EnrollToken/IdKey"))
	_, err = io.ReadFull(rdr, dst.IdKey[:])
	if nil != err {
		return wrapError(err, "failed IdKey derivation")
	}

	// StorageKey derivation
	rdr = hkdf.Expand(sha256.New, prk, []byte("EnrollToken/StorageKey"))
	_, err = io.ReadFull(rdr, dst.StorageKey[:])
	if nil != err {
		return wrapError(err, "failed StorageKey derivation")
	}

	return nil
}

// CardIdGenerator coordinates generation of client and server identifiers for a Card credential.
type CardIdGenerator struct {
	uid UserIdFactory
	idh *IdHasher
}

func NewCardIdGenerator(uid UserIdFactory, idh *IdHasher) (*CardIdGenerator, error) {
	if nil != uid && nil == idh {
		return nil, wrapError(ErrValidation, "nil IdHasher when using UserIdFactory")
	}

	return &CardIdGenerator{uid: uid, idh: idh}, nil
}

// GenCardIds initializes dst CardRef.
func (self *CardIdGenerator) GenCardIds(realmId []byte, userdata json.RawMessage, dst *CardRef) error {
	if nil == dst {
		return wrapError(ErrValidation, "nil dst")
	}
	if nil == self {
		// TODO: 2026-02-11
		// Unsure we should provide a default implementation in case self is nil
		// For now this ease transitioning from not using any CardId
		dst.ClientUserId = ""
		rand.Read(dst.ClientIdToken[:])
		copy(dst.ServerCardId[:], dst.ClientIdToken[:])
		return nil
	}
	if nil != self.uid && nil == self.idh {
		return wrapError(ErrValidation, "nil IdHasher when using UserIdFactory")
	}

	var err error

	// generate ClientUserId
	if nil == self.uid {
		dst.ClientUserId = ""
	} else {
		userId, err := self.uid.MakeUserId(userdata)
		if nil != err {
			return wrapError(err, "failed generating UserId")
		}
		dst.ClientUserId = userId
	}

	// generate ClientIdToken
	if "" == dst.ClientUserId {
		rand.Read(dst.ClientIdToken[:])

	} else {
		_, err = self.idh.IdTokenOfUserId(realmId, dst.ClientUserId, dst.ClientIdToken[:])
		if nil != err {
			return wrapError(err, "failed generating IdToken")
		}
	}

	// generate CardServerId
	aks := AccessKeys{}
	err = self.idh.deriveFromIdToken(dst.ClientIdToken[:], &aks)
	if nil != err {
		return wrapError(err, "failed deriving IdToken access keys")
	}
	dst.ServerCardId = aks.IdKey

	return nil

}
