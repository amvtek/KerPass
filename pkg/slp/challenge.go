package slp

import (
	"context"
	"crypto"
	"crypto/rand"
	"slices"

	"golang.org/x/crypto/hkdf"

	"code.kerpass.org/golang/internal/algos"
	"code.kerpass.org/golang/internal/session"
	"code.kerpass.org/golang/pkg/credentials"
	"code.kerpass.org/golang/pkg/ephemsec"
)

// SessionChal holds ECDH ephemeral key and nonce used for generating EPHEMSEC OTP/OTK.
// It is used internally during authentication challenge generation.
type SessionChal struct {
	e credentials.PrivateKeyHandle
	n []byte
}

// ChalSetter generates EPHEMSEC authentication challenge (ECDH ephemeral key & nonce).
// Implementations of this interface are responsible for producing cryptographic
// material used in authentication sessions.
type ChalSetter interface {
	// SetChal set ecdh ephemeral key & nonce in dst.
	SetChal(crv algos.Curve, sid []byte, dst *SessionChal) error
}

// HkdfChalSetter is a ChalSetter that uses HKDF to derive EPHEMSEC authentication
// challenge from a session identifier. It provides deterministic yet unpredictable
// generation of ephemeral keys and nonces for authentication sessions.
type HkdfChalSetter struct {
	prk []byte
	crh crypto.Hash
}

// NewHkdfChalSetter creates a new HkdfChalSetter with the specified hash function.
// It generates random salt and input key material (IKM) for HKDF extraction.
// Returns an error if the hash function is not available.
func NewHkdfChalSetter(hash crypto.Hash) (*HkdfChalSetter, error) {
	if !hash.Available() {
		return nil, newError("missing Hash %s", hash.String())
	}

	salt := make([]byte, hash.Size())
	rand.Read(salt)

	ikm := make([]byte, hash.Size())
	rand.Read(ikm)

	rv := HkdfChalSetter{prk: hkdf.Extract(hash.New, ikm, salt), crh: hash}

	return &rv, rv.Check()

}

// Check validates the HkdfChalSetter and returns an error if invalid.
func (self *HkdfChalSetter) Check() error {
	if !self.crh.Available() {
		return newError("missing Hash %s", self.crh.String())
	}
	if len(self.prk) != self.crh.Size() {
		return wrapError(ErrValidation, "invalid prk size")
	}
	return nil
}

// SetChal initializes dst SessionChal by generating ECDH ephemeral key and nonce using HKDF.
// It uses the provided curve, session ID, and the HKDF state to deterministically
// generate cryptographic material. Returns an error if key generation fails.
func (self *HkdfChalSetter) SetChal(crv algos.Curve, sid []byte, dst *SessionChal) error {
	// prepare hkdf expansion
	kdf := hkdf.Expand(self.crh.New, self.prk, sid)

	// generate session ephemeral Key
	ekb := make([]byte, crv.PrivateKeyLen())
	kdf.Read(ekb)
	ek, err := crv.NewPrivateKey(ekb)
	if nil != err {
		return wrapError(err, "failed generating session ephemeral key")
	}
	dst.e.PrivateKey = ek

	// generate session nonce
	n := make([]byte, 32)
	kdf.Read(n)
	dst.n = n

	return nil
}

// ChallengeFactory provides methods for creating authentication challenges and contexts.
// It is the main interface for generating authentication protocol data structures.
type ChallengeFactory interface {
	GetCardChallenge(req *CardChallengeRequest, dst *CardChallenge) error
	GetAgentAuthContext(sid []byte, dst *AgentAuthContext) error
}

// AuthContext holds ChallengeFactoryImpl configuration for a specific authentication realm.
// It contains all the URLs and authentication method information needed to process
// authentication requests for a particular application realm.
type AuthContext struct {
	RealmId              [32]byte
	AuthMethod           AuthMethod
	AppContextUrl        string
	AuthServerGetChalUrl string
	AuthServerLoginUrl   string
	AppStartUrl          string
}

// Check validates the AuthContext configuration and returns an error if invalid.
// It verifies the authentication method and all configured URLs are valid.
func (self *AuthContext) Check() error {
	err := self.AuthMethod.Check()
	if nil != err {
		return wrapError(err, "failed AuthMethod validation")
	}

	err = checkUrl(self.AppContextUrl)
	if nil != err {
		return wrapError(err, "failed AppContextUrl validation")
	}

	err = checkUrl(self.AuthServerGetChalUrl)
	if nil != err {
		return wrapError(err, "failed AuthServerGetChalUrl validation")
	}

	err = checkUrl(self.AuthServerLoginUrl)
	if nil != err {
		return wrapError(err, "failed AuthServerLoginUrl validation")
	}

	err = checkUrl(self.AppStartUrl)
	if nil != err {
		return wrapError(err, "failed AppStartUrl validation")
	}

	return nil
}

// ChallengeFactoryImpl implements the ChallengeFactory interface.
// It uses a session key factory, key store, and challenge setter to generate
// authentication challenges and contexts based on configuration.
type ChallengeFactoryImpl struct {
	Skf  session.KeyFactory[session.Sid]
	Kst  credentials.KeyStore
	Cst  ChalSetter
	Cfgs []AuthContext
}

// Check validates the ChallengeFactoryImpl and returns an error if invalid.
func (self *ChallengeFactoryImpl) Check() error {
	if nil == self {
		return wrapError(ErrValidation, "nil ChallengeFactoryImpl")
	}
	if nil == self.Skf {
		return wrapError(ErrValidation, "nil session KeyFactory")
	}
	if nil == self.Kst {
		return wrapError(ErrValidation, "nil credentials KeyStore")
	}
	if nil == self.Cst {
		return wrapError(ErrValidation, "nil ChalSetter")
	}
	if 0 == len(self.Cfgs) {
		return wrapError(ErrValidation, "empty Cfgs list")
	}

	var err error
	for pos, cfg := range self.Cfgs {
		err = cfg.Check()
		if nil != err {
			return wrapError(err, "failed validating configured AuthContext at position %d", pos)
		}

		// make sure that KeyStore Kst contains scheme static key...
		sch, err := ephemsec.GetScheme(cfg.AuthMethod.Scheme)
		if nil != err {
			return wrapError(err, "failed loading cfg[%d] scheme", pos)
		}
		kx := sch.KeyExchangePattern()
		if kx == "E1S2" || kx == "E2S2" {
			sk := credentials.ServerKey{}
			found := self.Kst.GetServerKey(context.Background(), cfg.RealmId[:], sch.Name(), &sk)
			if !found {
				return wrapError(ErrValidation, "failed loading static key for cfg[%d]", pos)
			}
		}

	}
	return nil
}

// GetCardChallenge generates a CardChallenge response for a given CardChallengeRequest.
// It validates the request against configured AuthContexts, generates a session ID,
// creates an authentication challenge using the configured ChalSetter, and loads
// appropriate static keys for the selected EPHEMSEC scheme.
func (self *ChallengeFactoryImpl) GetCardChallenge(req *CardChallengeRequest, dst *CardChallenge) error {

	// load the AuthContext that corresponds to req.
	var realmId [32]byte
	copy(realmId[:], req.RealmId)
	cfgIdx := slices.IndexFunc(self.Cfgs, func(elt AuthContext) bool {
		return (elt.RealmId == realmId) && (elt.AuthMethod == req.SelectedMethod) && (elt.AppContextUrl == req.AppContextUrl)
	})
	if -1 == cfgIdx {
		return newError("invalid CardChallengeRequest")
	}
	cfg := self.Cfgs[cfgIdx]

	// generates new session Id that encodes the selected AuthContext.
	sId := self.Skf.New(uint64(cfgIdx))

	// retrieve req EPHEMSEC scheme.
	sch, err := ephemsec.GetScheme(req.SelectedMethod.Scheme)
	if nil != err {
		return wrapError(err, "failed loading SelectedMethod scheme")
	}
	curve := sch.Curve()

	// generates new authentication challenge.
	chal := SessionChal{}
	err = self.Cst.SetChal(curve, sId[:], &chal)
	if nil != err {
		return wrapError(err, "failed generating session challenge")
	}

	// load static key in dst CardChallenge.
	kx := sch.KeyExchangePattern()
	if kx == "E1S2" || kx == "E2S2" {
		sk := credentials.ServerKey{}
		found := self.Kst.GetServerKey(context.Background(), req.RealmId, sch.Name(), &sk)
		if !found {
			return newError("failed loading scheme static key, with keyref{[%d][%v], %s}", len(req.RealmId), req.RealmId, sch.Name())
		}
		dst.S.PublicKey = sk.Kh.PrivateKey.PublicKey()
		dst.StaticKeyCert = sk.Certificate
	}

	// fill dst CardChallenge.
	dst.SessionId = sId[:]
	dst.AuthServerLoginUrl = cfg.AuthServerLoginUrl
	dst.AppStartUrl = cfg.AppStartUrl
	dst.E.PublicKey = chal.e.PrivateKey.PublicKey()
	dst.INonce = chal.n

	return nil
}

// GetAgentAuthContext retrieves the authentication context for a given session ID.
// It validates the session ID, looks up the corresponding AuthContext configuration,
// loads the appropriate static key certificate if needed, and populates the
// AgentAuthContext with all necessary authentication protocol information.
func (self *ChallengeFactoryImpl) GetAgentAuthContext(sid []byte, dst *AgentAuthContext) error {

	// check session sid
	var sId session.Sid
	if len(sId) != len(sid) {
		return wrapError(ErrValidation, "invalid sid length")
	}
	copy(sId[:], sid)
	err := self.Skf.Check(sId)
	if nil != err {
		return wrapError(err, "failed sId validation")
	}

	// retrieve session cfg
	cfgIdx := sId.AD()
	if cfgIdx >= uint64(len(self.Cfgs)) {
		return newError("invalid cfg index")
	}
	cfg := self.Cfgs[int(cfgIdx)]

	// retrieve session EPHEMSEC scheme
	sch, err := ephemsec.GetScheme(cfg.AuthMethod.Scheme)
	if nil != err {
		return wrapError(err, "failed loading SelectedMethod scheme")
	}

	// set StaticKeyCert on dst
	kx := sch.KeyExchangePattern()
	if kx == "E1S2" || kx == "E2S2" {
		sk := credentials.ServerKey{}
		found := self.Kst.GetServerKey(context.Background(), cfg.RealmId[:], sch.Name(), &sk)
		if !found {
			return newError("failed loading scheme static key")
		}
		dst.StaticKeyCert = sk.Certificate
	} else {
		dst.StaticKeyCert = nil
	}

	// populate dst
	dst.SelectedProtocol = cfg.AuthMethod.Protocol
	dst.SessionId = sid
	dst.AppContextUrl = cfg.AppContextUrl
	dst.AuthServerGetChalUrl = cfg.AuthServerGetChalUrl
	dst.AuthServerLoginUrl = cfg.AuthServerLoginUrl
	dst.AppStartUrl = cfg.AppStartUrl

	return nil
}

var _ ChallengeFactory = &ChallengeFactoryImpl{}
