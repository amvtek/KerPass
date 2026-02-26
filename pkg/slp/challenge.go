package slp

import (
	"context"
	"crypto"
	"crypto/rand"
	"slices"
	"time"

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
	// GetCardChallenge generates a CardChallenge in response to a CardChallengeRequest.
	// Returns an error if the request does not match any configured AuthContext or challenge generation fails.
	GetCardChallenge(req *CardChallengeRequest, dst *CardChallenge) error

	// GetAgentAuthContext retrieves the AgentAuthContext bound to the given session ID.
	// Returns an error if the session ID is invalid or expired, or the AuthContext cannot be reconstructed.
	GetAgentAuthContext(sid []byte, dst *AgentAuthContext) error

	// GetServerOtp derives the server-side OTP/OTK matching the one independently derived
	// by the Client for the authentication session referenced in cc.
	// Returns an error if the session is invalid, the card cannot be loaded, or OTP derivation fails.
	GetServerOtp(cc *CardChalResponse, dst []byte) ([]byte, error)
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

// CardChalResponse holds client-side authentication commitment data transmitted to the Server
// during an SLP authentication session. It allows the Server to independently derive
// the same OTP/OTK as the Client — without the Client ever transmitting the secret itself.
type CardChalResponse struct {
	// references a Server generated CardChallenge
	SessionId []byte `json:"sid" cbor:"1,keyasint"`

	// identifier allowing ServerCard access
	CardId []byte `json:"cid" cbor:"2,keyasint"`

	// synchronization hint allowing Server to determine Client OTP time
	SyncHint byte `json:"sync" cbor:"3,keyasint"`

	// Client generated ephemeral key
	// transmitted if authentication scheme uses E2S2 key exchange
	E credentials.PublicKeyHandle `json:"e,omitzero" cbor:"4,keyasint,omitzero"`
}

// ChallengeFactoryImpl implements the ChallengeFactory interface.
// It uses a session key factory, key store, and challenge setter to generate
// authentication challenges and contexts based on configuration.
type ChallengeFactoryImpl struct {
	Skf  session.KeyFactory[session.Sid]
	Kst  credentials.KeyStore
	Scs  credentials.ServerCredStore
	Cst  ChalSetter
	Cfgs []AuthContext
}

// NewChallengeFactoryImpl creates and initializes a new ChallengeFactoryImpl.
// It configures a session key factory with the given lifetime sl, initializes
// an HKDF/SHA-512 based challenge setter, and validates all provided AuthContexts
// and their required static keys against the key store kst.
// Returns an error if any component fails initialization or validation.
func NewChallengeFactoryImpl(sl time.Duration, kst credentials.KeyStore, scs credentials.ServerCredStore, acts []AuthContext) (*ChallengeFactoryImpl, error) {
	skf, err := session.NewSidFactory(sl)
	if nil != err {
		return nil, wrapError(err, "failed creating SidFactory")
	}
	cst, err := NewHkdfChalSetter(crypto.SHA512)
	if nil != err {
		return nil, wrapError(err, "failed creating HkdfChalSetter")
	}

	rv := &ChallengeFactoryImpl{Skf: skf, Kst: kst, Scs: scs, Cst: cst, Cfgs: acts}

	return rv, wrapError(rv.Check(), "failed ChallengeFactoryImpl Check")
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
	if nil == self.Scs {
		return wrapError(ErrValidation, "nil credentials ServerCredStore")
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

// GetServerOtp derives the server-side OTP/OTK for a given CardChalResponse.
// It validates the session ID, retrieves the corresponding AuthContext and EPHEMSEC scheme,
// loads the Client Card identified by cc.CardId, reloads the deterministic session challenge,
// reconstructs the EPHEMSEC context hash, and runs EPHEMSEC as Initiator to produce the OTP/OTK.
// The result matches what the Client independently derived, enabling mutual authentication
// without transmission of the shared secret.
// Returns an error if the session is invalid, the card cannot be loaded, or OTP derivation fails.
func (self *ChallengeFactoryImpl) GetServerOtp(cc *CardChalResponse, dst []byte) ([]byte, error) {
	if nil == cc {
		return nil, wrapError(ErrValidation, "nil CardChalResponse")
	}
	// retrieve session cfg
	sId := session.Sid(cc.SessionId)
	if len(sId) != len(cc.SessionId) {
		return nil, wrapError(ErrValidation, "invalid sid length")
	}
	err := self.Skf.Check(sId)
	if nil != err {
		return nil, wrapError(err, "failed sId validation")
	}
	cfgIdx := sId.AD()
	if cfgIdx >= uint64(len(self.Cfgs)) {
		return nil, wrapError(ErrValidation, "invalid cfg index")
	}
	cfg := self.Cfgs[int(cfgIdx)]

	// retrieve session EPHEMSEC scheme
	sch, err := ephemsec.GetScheme(cfg.AuthMethod.Scheme)
	if nil != err {
		return nil, wrapError(err, "failed loading SelectedMethod scheme")
	}

	// load the Card
	var card credentials.ServerCard
	var sca credentials.ServerCardAccess
	if 256 == sch.B() {
		// OTK case
		sca = credentials.IdToken(cc.CardId)
	} else {
		// OTP case
		sca = credentials.OtpId{Realm: cfg.RealmId[:], Username: string(cc.CardId)}
	}
	// TODO: consider passing a context parameter
	err = self.Scs.LoadCard(context.Background(), sca, &card)
	if nil != err {
		return nil, wrapError(err, "failed loading card")
	}
	if !slices.Equal(card.RealmId, cfg.RealmId[:]) {
		return nil, wrapError(ErrValidation, "invalid card Realm")
	}

	// load server static key if scheme requires 1
	var sk credentials.ServerKey // sk.Kh.PrivateKey (*ecdh.PrivateKey) & sk.Certificate
	kx := sch.KeyExchangePattern()
	if kx == "E1S2" || kx == "E2S2" {
		found := self.Kst.GetServerKey(context.Background(), cfg.RealmId[:], sch.Name(), &sk)
		if !found {
			return nil, newError("failed loading scheme static key")
		}
	}

	// calculate the ephemsec Context
	ect := make([]byte, 32)
	act := AgentAuthContext{
		SessionId:            cc.SessionId,
		SelectedProtocol:     cfg.AuthMethod.Protocol,
		StaticKeyCert:        sk.Certificate,
		AppContextUrl:        cfg.AppContextUrl,
		AuthServerGetChalUrl: cfg.AuthServerGetChalUrl,
		AuthServerLoginUrl:   cfg.AuthServerLoginUrl,
		AppStartUrl:          cfg.AppStartUrl,
	}
	ect, err = act.Sum(ect)
	if nil != err {
		return nil, wrapError(err, "failed hashing AgentAuthContext")
	}
	ect, err = EphemSecContextHash(cfg.RealmId[:], ect, ect)
	if nil != err {
		return nil, wrapError(err, "failed hashing ephemsec Context")
	}

	// reload session challenge
	chl := SessionChal{}
	err = self.Cst.SetChal(sch.Curve(), cc.SessionId, &chl)
	if nil != err {
		return nil, wrapError(err, "failed reloading SessionChal")
	}

	// initialize ephemsec State
	eps := ephemsec.State{
		Context:         ect,
		Nonce:           chl.n,
		SynchroHint:     int(cc.SyncHint),
		EphemKey:        chl.e.PrivateKey,
		StaticKey:       sk.Kh.PrivateKey,
		RemoteEphemKey:  cc.E.PublicKey,
		RemoteStaticKey: card.Kh.PublicKey,
		Psk:             card.Psk,
	}

	// calculate the OTP
	dst, err = eps.EPHEMSEC(sch, ephemsec.Initiator, dst)

	return dst, wrapError(err, "failed OTP derivation")
}

var _ ChallengeFactory = &ChallengeFactoryImpl{}
