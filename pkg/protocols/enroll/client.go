package enroll

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"

	"code.kerpass.org/golang/internal/observability"
	"code.kerpass.org/golang/pkg/credentials"
	"code.kerpass.org/golang/pkg/noise"
	"code.kerpass.org/golang/pkg/protocols"
)

type ClientStateFunc = protocols.StateFunc[*ClientState]

type ClientExitFunc = protocols.ExitFunc[*ClientState]

type ClientCfg struct {
	RealmId         []byte
	AuthorizationId []byte
	Repo            credentials.ClientCredStore
}

func (self ClientCfg) Check() error {
	if nil == self.Repo {
		return newError("nil Repo")
	}
	if len(self.RealmId) < 32 {
		return newError("Invalid RealmId, length %d < 32", len(self.RealmId))
	}
	if len(self.AuthorizationId) < 16 {
		return newError("Invalid AuthorizationId, length %d < 16", len(self.AuthorizationId))
	}

	return nil
}

type ClientState struct {
	RealmId         []byte
	AuthorizationId []byte
	Repo            credentials.ClientCredStore
	hs              noise.HandshakeState
	cardId          int
	next            ClientStateFunc
}

func NewClientState(cfg ClientCfg) (*ClientState, error) {
	err := cfg.Check()
	if nil != err {
		return nil, wrapError(err, "Invalid ClientCfg")
	}

	rv := &ClientState{
		RealmId:         cfg.RealmId,
		AuthorizationId: cfg.AuthorizationId,
		Repo:            cfg.Repo,
		next:            ClientInit,
	}

	return rv, nil
}

// protocols.Fsm implementation

func (self *ClientState) State() (*ClientState, ClientStateFunc) {
	return self, self.next
}

func (self *ClientState) SetState(sf ClientStateFunc) {
	self.next = sf
}

func (self *ClientState) ExitHandler() ClientExitFunc {
	return ClientExit
}

func (self *ClientState) SetExitHandler(_ ClientExitFunc) {
}

func (self *ClientState) Initiator() bool {
	return true
}

var _ protocols.Fsm[*ClientState] = &ClientState{}

// State functions

func ClientInit(ctx context.Context, self *ClientState, _ []byte) (sf ClientStateFunc, rmsg []byte, err error) {
	sf = ClientInit
	var errmsg string

	// get logger
	log := observability.GetObservability(ctx).Log().With("state", "ClientInit")

	// create a Static Keypair
	log.Debug("generating Card Keypair")
	curve := noiseCfg.CurveAlgo
	keypair, err := curve.GenerateKey(rand.Reader)
	if nil != err {
		errmsg = "failed generating Card Keypair"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}

	// initialize noise Handshake
	log.Debug("initializing noise handshake")
	params := noise.HandshakeParams{
		Cfg:           noiseCfg,
		Prologue:      self.RealmId,
		StaticKeypair: keypair,
		Psks:          dummyPsks,
		Initiator:     true,
	}
	err = self.hs.Initialize(params)
	if nil != err {
		errmsg = "failed initializing noise handshake"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}

	// generate initial noise msg
	// Client: -> e
	log.Debug("generating handshake message with nil payload")
	var buf bytes.Buffer
	_, err = self.hs.WriteMessage(nil, &buf)
	if nil != err {
		errmsg = "failed generating handshake message"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)

	}

	// prepare Client: -> [EnrollReq]
	// It can not be send as noise payload because the server needs to know the RealmId to load its static key...
	log.Debug("preparing EnrollReq message")
	req := EnrollReq{RealmId: self.RealmId, Msg: buf.Bytes()}
	rmsg, err = cborSrz.Marshal(req)
	if nil != err {
		errmsg = "failed CBOR marshal of EnrollReq"
		log.Debug(errmsg, "error", err)
		return sf, nil, wrapError(err, errmsg)
	}

	log.Debug("OK, switching to ClientReceiveServerKey state")
	return ClientReceiveServerKey, rmsg, nil
}

func ClientReceiveServerKey(ctx context.Context, self *ClientState, msg []byte) (sf ClientStateFunc, rmsg []byte, err error) {
	sf = ClientReceiveServerKey
	var errmsg string

	// get logger
	log := observability.GetObservability(ctx).Log().With("state", "ClientReceiveServerKey")

	// schedule recovering inner noise HandshakeState in case of error...
	hsbkup := self.hs
	defer func() {
		if nil != err {
			log.Debug("restoring initial handshake state following error")
			self.hs = hsbkup
		}
	}()

	// receive Server: <- e, ee, s, es, {Certificate}
	log.Debug("reading handshake message")
	var buf bytes.Buffer
	_, err = self.hs.ReadMessage(msg, &buf)
	if nil != err {
		errmsg = "failed reading handshake message"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}
	srvcert := buf.Bytes()

	// control RemoteStaticKey()
	log.Debug("controlling remote server static key")
	srvkey := self.hs.RemoteStaticKey()
	err = pkiCheck(srvkey, srvcert)
	if nil != err {
		errmsg = "failed remote server static key control"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}

	// prepare Client: -> s, se, {EnrollAuthorization}
	log.Debug("generating handshake message with EnrollAuthorization payload")
	srzmsg, err := cborSrz.Marshal(EnrollAuthorization{AuthorizationId: self.AuthorizationId})
	if nil != err {
		errmsg = "failed CBOR marshal of EnrollAuthorization"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}
	buf.Reset()
	_, err = self.hs.WriteMessage(srzmsg, &buf)
	if nil != err {
		errmsg = "failed generating handshake message"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}

	log.Debug("OK, switching to ClientCardCreate state")
	return ClientCardCreate, buf.Bytes(), nil
}

func ClientCardCreate(ctx context.Context, self *ClientState, msg []byte) (sf ClientStateFunc, rmsg []byte, err error) {
	sf = ClientCardCreate
	var errmsg string

	// get logger
	log := observability.GetObservability(ctx).Log().With("state", "ClientCardCreate")

	// schedule recovering inner noise HandshakeState in case of error...
	hsbkup := self.hs
	defer func() {
		if protocols.IsError(err) {
			log.Debug("restoring initial handshake state following error")
			self.hs = hsbkup
		}
	}()

	// receive Server: <- psk, {EnrollCardCreateResp}
	log.Debug("reading handshake message")
	var buf bytes.Buffer
	_, err = self.hs.ReadMessage(msg, &buf)
	if nil != err {
		errmsg = "failed reading handshake message"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}
	log.Debug("extracting EnrollCardCreateResp from handshake message payload")
	srv := EnrollCardCreateResp{}
	err = cborSrz.Unmarshal(buf.Bytes(), &srv)
	if nil != err {
		errmsg = "failed CBOR unmarshal of EnrollCardCreateResp"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}

	// create new Card
	log.Debug("creating Card")
	psk, err := derivePSK(self.RealmId, srv.CardId, self.hs.GetHandshakeHash())
	if nil != err {
		errmsg = "failed deriving Card psk"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}
	card := credentials.Card{
		RealmId: self.RealmId,
		IdToken: srv.CardId,
		AppName: srv.AppName,
		AppLogo: srv.AppLogo,
		Psk:     psk,
	}
	card.Kh.PrivateKey = self.hs.StaticKeypair()

	// save new Card
	log.Debug("saving Card")
	cardId, err := self.Repo.SaveCard(card)
	if nil != err {
		errmsg = "failed saving card"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}
	card.ID = cardId
	self.cardId = cardId

	// prepare Client: -> psk, {}
	log.Debug("generating handshake message")
	buf.Reset()
	_, err = self.hs.WriteMessage(nil, &buf)
	if nil != err {
		errmsg = "failed generating handshake message"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}

	log.Debug("SUCCESS, completed enroll protocol")
	return nil, buf.Bytes(), protocols.OK
}

func ClientExit(self *ClientState, rs error) error {
	var err error
	if nil != rs {
		_, err = self.Repo.RemoveCard(self.cardId)
	}

	return err
}

// pkiCheck returns an error if cert is invalid or pubkey does not correspond to cert...
//
// TODO: current implementation of pkiCheck is a proof of concept
func pkiCheck(pubkey *ecdh.PublicKey, cert []byte) error {
	if nil == pubkey {
		return newError("Invalid PublicKey")
	}
	if len(cert) == 0 {
		return newError("Invalid cert")
	}

	return nil
}
