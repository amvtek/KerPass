package credentials

// ServerCardKey is a sealed interface representing any key that can locate a Card
// on the server side. It is the sum type for all card lookup strategies.
//
// Variants:
//   - [ServerCardIdKey]: a 32-byte derived key, produced by hashing an IdToken.
//   - [ServerCardId]:    a surrogate integer key, for store implementations that
//     maintain their own indexed identity.
//   - [IdToken]:         a 32-byte client-held token. Implements both lookup and access.
//   - [OtpId]:           a (realm, username) pair for OTP-based authentication paths.
type ServerCardKey interface {
	isServerCardKey()
}

// ServerCardIdKey is a 32-byte server-side card identifier derived from an IdToken
//
// It provides direct, opaque access to a Card without exposing the originating IdToken.
type ServerCardIdKey []byte

// Check returns an error if the ServerCardIdKey is not a valid 32-byte key.
func (self ServerCardIdKey) Check() error {
	if len(self) < 32 {
		return wrapError(ErrValidation, "len < 32")
	}

	return nil
}

// isServerCardKey seals ServerCardIdKey as a variant of [ServerCardKey].
func (self ServerCardIdKey) isServerCardKey() {}

// ServerCardId is a surrogate integer key for store implementations that maintain
// their own indexed identity (e.g. auto-increment primary keys).
//
// Support for ServerCardId is optional and depends on the [ServerCredStore] implementation.
// It is intended as a fast-path lookup alternative to [ServerCardIdKey].
type ServerCardId int

// isServerCardKey seals ServerCardId as a variant of [ServerCardKey].
func (self ServerCardId) isServerCardKey() {}

// ServerCardAccess is a sealed interface representing keys that can both locate
// and read Card secrets. It extends [ServerCardKey] with access rights.
//
// Variants:
//   - [IdToken]: the client-held 32-byte token; grants access when presented directly.
//   - [OtpId]:   a (realm, username) pair; grants access via the OTP authentication path.
type ServerCardAccess interface {
	ServerCardKey
	isServerCardAccess()
}

// IdToken is a 32-byte client-held credential.
//
// IdTokens are either randomly generated (high-entropy) or deterministically derived
// from a UserId via HKDF (see [IdHasher.IdTokenOfUserId]). In the latter case,
// secrecy of the [IdHasher] seed is required to prevent offline enumeration.
//
// As [ServerCardKey], an IdToken can locate a Card by first deriving its [ServerCardIdKey]
// via [IdHasher.DeriveFromIdToken].
// As [ServerCardAccess], it additionally grants the right to read Card secrets.
type IdToken []byte

// OtkId is an alias for [IdToken] used as an identifier when authenticating with OTK.
type OtkId = IdToken

// Check returns an error if the IdToken is not exactly 32 bytes.
func (self IdToken) Check() error {
	if len(self) != 32 {
		return wrapError(ErrValidation, "len != 32")
	}

	return nil
}

// isServerCardKey seals IdToken as a variant of [ServerCardKey].
func (self IdToken) isServerCardKey() {}

// isServerCardAccess seals IdToken as a variant of [ServerCardAccess].
func (self IdToken) isServerCardAccess() {}

// OtpId identifies a Card via the OTP authentication path, using a (realm, username) pair.
//
// It is used when a client authenticates with a one-time password rather than presenting
// an IdToken directly. The server resolves OtpId to a Card by looking up the username
// within the given realm.
type OtpId struct {
	Realm    RealmId
	Username string
}

// Check returns an error if the OtpId is invalid.
func (self OtpId) Check() error {
	err := self.Realm.Check()
	if nil != err {
		return wrapError(err, "Invalid Realm")
	}

	return nil
}

// isServerCardKey seals OtpId as a variant of [ServerCardKey].
func (self OtpId) isServerCardKey() {}

// isServerCardAccess seals OtpId as a variant of [ServerCardAccess].
func (self OtpId) isServerCardAccess() {}

// EnrollKey is a sealed interface representing any key that can locate an
// EnrollAuthorization on the server side. It is the sum type for all the
// lookup strategies.
//
// Variants:
//   - [EnrollIdKey]: a 32-byte derived key, produced by hashing an EnrollToken.
//   - [EnrollId]:    a surrogate integer key, for store implementations that
//     maintain their own indexed identity.
//   - [EnrollToken]: a 32-byte client-held token. Implements both lookup and access.
type EnrollKey interface {
	isEnrollKey()
}

// EnrollIdKey is a 32-byte server-side EnrollAuthorization identifier derived from an EnrollToken
//
// It provides direct, opaque access to an EnrollAuthorization without exposing the originating EnrollToken.
type EnrollIdKey []byte

// Check returns an error if the EnrollIdKey is not a valid 32-byte key.
func (self EnrollIdKey) Check() error {
	if len(self) < 32 {
		return wrapError(ErrValidation, "len < 32")
	}

	return nil
}

// isEnrollKey seals EnrollIdKey as a variant of [EnrollKey].
func (self EnrollIdKey) isEnrollKey() {}

// EnrollId is a surrogate integer key for store implementations that maintain
// their own indexed identity (e.g. auto-increment primary keys).
//
// Support for EnrollId is optional and depends on the [ServerCredStore] implementation.
// It is intended as a fast-path lookup alternative to [EnrollIdKey].
type EnrollId int

// isEnrollKey seals EnrollId as a variant of [EnrollKey].
func (self EnrollId) isEnrollKey() {}

// EnrollAccess is a sealed interface representing keys that can both locate
// and read EnrollAuthorization secrets. It extends [EnrollKey] with access rights.
//
// Variants:
//   - [EnrollToken]: the client-held 32-byte token; It grants the right  to register a card in a [Realm].
type EnrollAccess interface {
	EnrollKey
	isEnrollAccess()
}

// EnrollToken is a 32-byte client-held credential.
//
// EnrollTokens are randomly generated (256 bits entropy)
//
// As [EnrollKey], an EnrollToken can locate an [EnrollAuthorization]
// by first deriving its [EnrollIdKey] via [IdHasher.DeriveFromEnrollToken].
// As [EnrollAccess], it additionally grants the right to read [EnrollAuthorization]
// secrets and register a new [ServerCard] in the [EnrollAuthorization.Realm].
type EnrollToken []byte

// Check returns an error if the EnrollToken is not exactly 32 bytes.
func (self EnrollToken) Check() error {
	if len(self) != 32 {
		return wrapError(ErrValidation, "len != 32")
	}

	return nil
}

// isEnrollKey seals EnrollToken as a variant of [EnrollKey].
func (self EnrollToken) isEnrollKey() {}

// isEnrollAccess seals EnrollToken as a variant of [EnrollAccess].
func (self EnrollToken) isEnrollAccess() {}

// RealmId is the root hash of the Realm's CA public key Merkle tree.
//
// It is a stable, permanent identifier for a security domain: it does not change
// when the active CA signing key is rotated. Because the Merkle tree commits to
// all authorized CA keys, a RealmId is self-sufficient — it is all that is needed
// to validate any certificate issued within the realm.
//
// RealmId is not randomly generated: it is deterministically derived from CA key
// material and must be at least 32 bytes.
type RealmId []byte

// Check returns an error if the RealmId is not at least 32 bytes.
func (self RealmId) Check() error {
	if len(self) < 32 {
		return wrapError(ErrValidation, "len < 32")
	}

	return nil
}
