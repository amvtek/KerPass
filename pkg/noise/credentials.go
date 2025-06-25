package noise

import (
	"strings"
)

// RMQ:
// Credentials extraction & verification was integrated to HandshakeState.ReadMessage
// While this brings benefits (decrease number of protocol roundtrips and fail early in case of DOS attacks)
// It adds a new dimension to noise protocols that requires peer reviews.
// Hence it has been removed.

// CredentialVerifier is used to track verification state of a certain credential
// transmitted in an handshake message.
type CredentialVerifier interface {

	// ReadSize returns the expected size of the next data to be passed to Verify.
	ReadSize(hs *HandshakeState) int

	// Verify uses data to perform some validation. If the validation fails it returns
	// a non nil error, otherwise it returns a nil error and an integer in [0..len(data)] range
	// that indicates the number of bytes to be removed from the data buffer prior to continue
	// processing the handshake.
	//
	// data to be verified are plaintext extracted from received handshake messages. For example data maybe
	// a user identifier, a public key or a public key certificate...
	//
	// Verify may update the provided HandshakeState. This can be leveraged for example to add psks to an
	// HandshakeState after having verified an userId...
	//
	// Verify shall not retain hs or data.
	Verify(hs *HandshakeState, data []byte) (int, error)

	// Reset clears internal state to allow reuse with another handshake.
	Reset()
}

// VerifierProvider holds CredentialVerifiers to be used in a noise protocol handshake.
type VerifierProvider struct {
	staticKeyVerifier CredentialVerifier
	extName           string
	extVerifier       CredentialVerifier
	loaders           string
}

// SetVerifier registers a CredentialVerifier with the VerifierProvider.
//
// registration name normally corresponds to HandshakePattern tokens eg "s", "rs"...
//
// This implementation of VerifierProvider supports registering at most 2 CredentialVerifiers.
// A static key verifier that can be registered with names "s" or "rs".
// An "extension" verifier that can be registered with any other name.
func (self *VerifierProvider) SetVerifier(name string, cv CredentialVerifier) {
	name = strings.TrimPrefix(strings.TrimSpace(name), "r")
	switch name {
	case "s":
		self.staticKeyVerifier = cv
	default:
		self.extName = name
		self.extVerifier = cv
	}
}

// SetLoaders allows declaring which HandshakeState credentials (eg psks, password...)
// are loaded by the verifiers registered with the VerifierProvider.
func (self *VerifierProvider) SetLoaders(names ...string) {
	self.loaders = strings.Join(names, " ")
}

// Get returns the CredentialVerifier that corresponds to name if any.
func (self *VerifierProvider) Get(name string) CredentialVerifier {
	if nil == self {
		return nil
	}
	name = strings.TrimPrefix(strings.TrimSpace(name), "r")
	switch name {
	case "s":
		return self.staticKeyVerifier
	case self.extName:
		return self.extVerifier
	default:
		return nil
	}
}

// ShouldLoad returns true if name corresponds to a loader registered with the VerifierProvider.
func (self *VerifierProvider) ShouldLoad(name string) bool {
	if nil == self {
		return false
	}
	for loader := range strings.FieldsSeq(self.loaders) {
		if loader == name {
			return true
		}
	}
	return false
}

// Reset resets all the CredentialVerifier in the VerifierProvider.
//
// It is safe to call Reset on a nil VerifierProvider.
func (self *VerifierProvider) Reset() {
	if nil == self {
		return
	}
	if nil != self.staticKeyVerifier {
		self.staticKeyVerifier.Reset()
	}
	if nil != self.extVerifier {
		self.extVerifier.Reset()
	}
}

// AcceptOrRejectAnyKey is a CredentialVerifier that allows accepting or rejecting any static key.
//
// AcceptAnyOrRejectAnyKey is provided to help testing noise protocol implementations.
type AcceptOrRejectAnyKey struct {
	step int

	// desired verification status. If nil all verified static keys are valid...
	Status error
}

// NewAcceptOrRejectAnyKey returns a CredentialVerifier that always fails.
// Change the Status field to nil for Verify to always succeed.
func NewAcceptOrRejectAnyKey() *AcceptOrRejectAnyKey {
	return &AcceptOrRejectAnyKey{Status: errNoStaticKeyVerifier}
}

// ReadSize returns the byte size of inner configuration DH PublicKey.
func (self *AcceptOrRejectAnyKey) ReadSize(hs *HandshakeState) int {
	switch self.step {
	case 0:
		return hs.DHLen()
	default:
		return 0
	}
}

// Verify errors if inner Status is not nil.
func (self *AcceptOrRejectAnyKey) Verify(_ *HandshakeState, data []byte) (int, error) {
	self.step += 1
	return 0, wrapError(self.Status, "Verify configured to always fail")
}

// Reset clears internal state to allow reuse with another handshake.
func (self *AcceptOrRejectAnyKey) Reset() {
	self.step = 0
}
