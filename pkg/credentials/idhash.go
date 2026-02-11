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
	saltAuthId
	numSalts
)

var (
	// DO NOT EDIT saltNames values
	saltNames = []string{
		"salt:card:UserId/IdToken",
		"salt:card:IdToken/Derivation",
		"salt:authorization:AuthId/Derivation",
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
	// ClientIdToken is held by the client and used to derive operational keys.
	ClientIdToken [32]byte

	// ClientUserId is optional.
	// When present it is used to derive a ClientIdToken.
	ClientUserId string

	// ServerCardId is held by the server and used to load a Card.
	// It derives from ClientIdToken.
	ServerCardId [32]byte
}


// DerivedKeys holds the result of HKDF-based derivations from either IdToken or AuthorizationId.
type DerivedKeys struct {
	// IdKey is used as a server-side identifier for Card or EnrollAuthorization subjects.
	IdKey [32]byte

	// StorageKey is used to protect subject sensitive data.
	StorageKey [32]byte
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

// DeriveFromIdToken derives operational keys from a 32-byte IdToken.
//
// It produces domain-separated keys for:
//   - IdKey: used as a server-side card identifier.
//   - StorageKey: used to protect card-related stored data.
//
// The derivation is deterministic and bound to the IdHasher seed. The IdToken must
// contain sufficient entropy for the intended security level.
func (self *IdHasher) DeriveFromIdToken(idToken []byte, dst *DerivedKeys) error {
	if 32 != len(idToken) {
		return wrapError(ErrValidation, "invalid idToken, length != 32")
	}

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

// DeriveFromAuthorizationId derives operational keys from a 32-byte AuthorizationId.
//
// It produces domain-separated keys for:
//   - IdKey: used as a server-side Authorization identifier.
//   - StorageKey: used to protect Authorization  stored data.
//
// The derivation is deterministic and bound to the IdHasher seed. AuthorizationId must
// contain sufficient entropy for the intended security level.
func (self *IdHasher) DeriveFromAuthorizationId(authId []byte, dst *DerivedKeys) error {
	if 32 != len(authId) {
		return wrapError(ErrValidation, "invalid authId, length != 32")
	}

	prk := hkdf.Extract(sha256.New, authId, self.salts[saltAuthId][:])

	var rdr io.Reader
	var err error

	// IdKey derivation
	rdr = hkdf.Expand(sha256.New, prk, []byte("AuthId/IdKey"))
	_, err = io.ReadFull(rdr, dst.IdKey[:])
	if nil != err {
		return wrapError(err, "failed IdKey derivation")
	}

	// StorageKey derivation
	rdr = hkdf.Expand(sha256.New, prk, []byte("AuthId/StorageKey"))
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
		// generates a random idToken
		rand.Read(dst.ClientIdToken[:])
	} else {
		_, err = self.idh.IdTokenOfUserId(realmId, dst.ClientUserId, dst.ClientIdToken[:])
		if nil != err {
			return wrapError(err, "failed generating IdToken")
		}
	}

	// generate CardServerId
	dks := DerivedKeys{}
	err = self.idh.DeriveFromIdToken(dst.ClientIdToken[:], &dks)
	if nil != err {
		return wrapError(err, "failed obtaining IdToken derived keys")
	}
	dst.ServerCardId = dks.IdKey

	return nil

}
