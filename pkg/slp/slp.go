package slp

import (
	"crypto/sha256"
	"net/url"
	"slices"

	"code.kerpass.org/golang/internal/transport"
	"code.kerpass.org/golang/pkg/credentials"
	"code.kerpass.org/golang/pkg/ephemsec"
)

const (
	minSlp = 0

	// Slp{Name} enumerates supported OTP/OTK authentication protocols
	// Slp is a short for Simple Login Protocol
	SlpDirect = uint16(0) // one way authentication through direct disclosure of OTP/OTK
	SlpCpace  = uint16(1) // mutual authentication proving OTP/OTK knowledge using CPACE PAKE
	SlpNXpsk2 = uint16(2) // mutual authentication proving OTK knowledge using Noise NXpsk2

	maxSlp = 2

	// marks below are used as Tag for TLV encoding
	markRealm        = byte('R')
	markAgentContext = byte('A')
)

var ctapSrz = transport.WrapInSafeSerializer(transport.NewCTAP2Serializer())

// AppAuthRequest details relying Application authentication requirements.
// It is forwarded by a relying Application to a KerPass CardAgent.
type AppAuthRequest struct {
	// Application Realm Identifier
	// RealmId encodes a "PKI context" that allows validating Application public key certificates
	RealmId []byte `json:"rId" cbor:"1,keyasint"`

	// Url where to submit CardChallengeRequest request
	AuthServerGetChalUrl string `json:"getChalUrl" cbor:"2,keyasint"`

	// Enumerates Application supported Authentication methods
	AllowedMethods []AuthMethod `json:"methods" cbor:"3,keyasint"`
}

// Check validates the AppAuthRequest and returns an error if invalid.
func (self AppAuthRequest) Check() error {
	if len(self.RealmId) < 32 {
		return wrapError(ErrInvalidMsg, "Invalid RealmId, len < 32")
	}

	err := checkUrl(self.AuthServerGetChalUrl)
	if nil != err {
		return wrapError(err, "failed AuthServerGetChalUrl validation")
	}

	if 0 == len(self.AllowedMethods) {
		return wrapError(ErrInvalidMsg, "Empty AllowedMethods")
	}
	if len(self.AllowedMethods) > 8 {
		return wrapError(ErrInvalidMsg, "len(AllowedMethods) > 8")
	}
	for pos, mtd := range self.AllowedMethods {
		err = mtd.Check()
		if nil != err {
			return wrapError(err, "AllowedMethods[%d] is invalid", pos)
		}
	}

	return nil
}

// AuthMethod binds a Slp authentication protocol to an EPHEMSEC OTP/OTK generation scheme.
type AuthMethod struct {
	// One of the enumerated Slp authentication protocol
	Protocol uint16 `json:"proto" cbor:"1,keyasint"`

	// One of the registered EPHEMSEC scheme
	Scheme uint16 `json:"scheme" cbor:"2,keyasint"`
}

// Check validates the AuthMethod and returns an error if invalid.
func (self AuthMethod) Check() error {
	pro := self.Protocol
	if pro < minSlp || pro > maxSlp {
		return wrapError(ErrInvalidSlp, "invalid Protocol")
	}
	sch, err := ephemsec.GetScheme(self.Scheme)
	if nil != err {
		return wrapError(err, "invalid Scheme")
	}
	switch pro {
	case SlpNXpsk2:
		if 256 != sch.B() {
			return wrapError(ErrUnsafeMethod, "SlpNXpsk2 unsafe with OTP")
		}
		if sch.P() < 33 {
			return wrapError(ErrUnsafeMethod, "SlpNXpsk2 unsafe with OTK having less than 256 bits entropy")
		}
	case SlpCpace:
		if 256 == sch.B() {
			return wrapError(ErrNotSupported, "Usage of OTK with SlpCpace not supported")
		}
	}

	return nil
}

// ReadInt decodes an integer into an AuthMethod by extracting Protocol from bits 16-17 and Scheme from bits 0-15.
// It validates the decoded AuthMethod and returns an error if invalid.
func (self *AuthMethod) ReadInt(v int) error {
	uv := uint32(v & 0x3FFFF) // mask keeps the lowest 18 bits of v
	mtd := AuthMethod{Protocol: uint16(uv >> 16), Scheme: uint16(uv)}
	err := mtd.Check()
	if nil != err {
		return wrapError(err, "can not decode valid AuthMethod")
	}
	*self = mtd

	return nil
}

// EncodeToInt encodes the AuthMethod into an integer with Protocol in bits 16-17 and Scheme in bits 0-15.
func (self AuthMethod) EncodeToInt() int {
	uv := (uint32(self.Protocol) << 16) | uint32(self.Scheme)

	return int(uv)
}

// CardChallengeRequest allows obtaining EPHEMSEC ephemeral key & nonce.
// It is submitted by a KerPass CardAgent to a relying application AuthServer.
type CardChallengeRequest struct {
	// Application Realm Identifier
	// RealmId encodes a "PKI context" that allows validating Application public key certificates
	RealmId []byte `json:"rId" cbor:"1,keyasint"`

	// CardAgent selected AuthMethod Id
	// It is the index of the selected AuthMethod in related AppAuthRequest.AllowedMethods
	SelectedMethod AuthMethod `json:"mtd" cbor:"2,keyasint"`

	// CardAgent acquired Url that corresponds to where the AppAuthRequest was obtained.
	// AuthServer may refuse CardChallengeRequest request if this url is not legit.
	// CardAgent & AuthServer independently append this Url to their EPHEMSEC OTP/OTK generation context.
	AppContextUrl string `json:"appUrl" cbor:"3,keyasint"`
}

// Check validates the CardChallengeRequest and returns an error if invalid.
func (self CardChallengeRequest) Check() error {
	if len(self.RealmId) < 32 {
		return wrapError(ErrInvalidMsg, "Invalid RealmId, len < 32")
	}

	err := self.SelectedMethod.Check()
	if nil != err {
		return wrapError(err, "failed SelectedMethod validation")
	}

	err = checkUrl(self.AppContextUrl)
	if nil != err {
		return wrapError(err, "failed AppContextUrl validation")
	}

	return nil
}

// CardChallenge contains AuthServer generated EPHEMSEC ephemeral key & nonce.
// It is returned by relying Application AuthServer in response to CardChallengeRequest.
type CardChallenge struct {
	// AuthServer generated SessionId
	SessionId []byte `json:"sId" cbor:"1,keyasint"`

	// AuthServer generated ephemeral key
	// E is compatible with the EPHEMSEC scheme selected in related CardChallengeRequest.
	E credentials.PublicKeyHandle `json:"E" cbor:"2,keyasint"`

	// AuthServer generated nonce
	INonce []byte `json:"nonce" cbor:"3,keyasint"`

	// AuthServer EPHEMSEC static key
	// It is set if the selected EPHEMSEC scheme uses E1S2 or E2S2 key exchange pattern
	S credentials.PublicKeyHandle `json:"S" cbor:"4,keyasint,omitzero"`

	// Static key certificate
	// It is set if the selected EPHEMSEC scheme uses E1S2 or E2S2 key exchange pattern
	StaticKeyCert []byte `json:"cert" cbor:"5,keyasint,omitempty"`

	// Url where to start the selected authentication protocol
	// CardAgent & AuthServer independently append this Url to their EPHEMSEC OTP/OTK generation context
	AuthServerLoginUrl string `json:"loginUrl" cbor:"6,keyasint"`

	// Url where to go following successful Slp authentication
	// CardAgent & AuthServer independently append this Url to their EPHEMSEC OTP/OTK generation context
	AppStartUrl string `json:"appStartUrl" cbor:"7,keyasint"`
}

// Check validates the CardChallenge and returns an error if invalid.
func (self CardChallenge) Check() error {
	if 0 == len(self.SessionId) {
		return wrapError(ErrInvalidMsg, "empty SessionId")
	}

	if self.E.IsZero() {
		return wrapError(ErrInvalidMsg, "missing E PublicKey")
	}

	nsz := len(self.INonce)
	if nsz < 16 || nsz > 64 {
		// INonce size range is specified in EPHEMSEC
		return wrapError(ErrInvalidMsg, "invalid INonce length")
	}

	if !self.S.IsZero() {
		if self.E.Curve() != self.S.Curve() {
			return wrapError(ErrInvalidMsg, "E,S are using different Curves")
		}
		if 0 == len(self.StaticKeyCert) {
			return wrapError(ErrInvalidMsg, "empty StaticKeyCert")
		}
	}

	err := checkUrl(self.AuthServerLoginUrl)
	if nil != err {
		return wrapError(ErrInvalidMsg, "failed AuthServerLoginUrl validation")
	}

	err = checkUrl(self.AppStartUrl)
	if nil != err {
		return wrapError(ErrInvalidMsg, "failed AppStartUrl validation")
	}

	return nil

}

// AgentAuthContext simplifies canonical hashing (through CBOR encoding) for EPHEMSEC context preparation
// AgentAuthContext is the 1st component of the KerPass EPHEMSEC context
// It is derived independently by CardAgent & AuthServer
// CardApp & AuthServer independently append RealmId to this context prior to use it as EPHEMSEC input
type AgentAuthContext struct {
	SelectedProtocol     uint16 `cbor:"1,keyasint"`
	SessionId            []byte `cbor:"2,keyasint"`
	StaticKeyCert        []byte `cbor:"3,keyasint,omitempty"`
	AppContextUrl        string `cbor:"4,keyasint"`
	AuthServerGetChalUrl string `cbor:"5,keyasint"`
	AuthServerLoginUrl   string `cbor:"6,keyasint"`
	AppStartUrl          string `cbor:"7,keyasint"`
}

// Sum returns the sha256 digest of CTAP2 serialization of the AgentAuthContext.
// Sum errors if the AgentAuthContext is nil or CTAP2 serialization failed.
func (self *AgentAuthContext) Sum(dst []byte) ([]byte, error) {
	if nil == self {
		return nil, wrapError(ErrInvalidMsg, "nil AgentAuthContext")
	}
	srzctx, err := ctapSrz.Marshal(self)
	if nil != err {
		return nil, wrapError(err, "failed CTAP2 marshal")
	}
	h := sha256.New()
	h.Write(srzctx)

	return h.Sum(dst), nil
}

// EphemSecContextHash returns the sha256 of TLV encoding of realmId & agentCtx.
// EphemSecContextHash errors if realmId or agentCtx have length not in 32..255 range.
func EphemSecContextHash(realmId []byte, agentCtx []byte, dst []byte) ([]byte, error) {
	h := sha256.New()

	// append TLV of realmId to h state
	if len(realmId) < 32 || len(realmId) > 255 {
		return nil, wrapError(ErrValidation, "Invalid realmId length")
	}
	h.Write([]byte{markRealm, byte(len(realmId))})
	h.Write(realmId)

	// append TLV of agentCtx to h state
	if len(agentCtx) < 32 || len(agentCtx) > 255 {
		return nil, wrapError(ErrValidation, "Invalid agentCtx length")
	}
	h.Write([]byte{markAgentContext, byte(len(agentCtx))})
	h.Write(agentCtx)

	return h.Sum(dst), nil

}

func checkUrl(s string) error {
	if len(s) > 255 {
		return wrapError(ErrValidation, "invalid url, len > 255")
	}
	u, err := url.Parse(s)
	if nil != err {
		return wrapError(err, "failed url.Parse")
	}
	if "" == u.Hostname() {
		return wrapError(ErrValidation, "invalid url, missing HostName")
	}
	if !slices.Contains([]string{"http", "https"}, u.Scheme) {
		return wrapError(ErrValidation, "invalid url scheme")
	}

	return nil
}
