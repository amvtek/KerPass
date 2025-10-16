package enroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"slices"

	"code.kerpass.org/golang/internal/observability"
	"code.kerpass.org/golang/pkg/credentials"
	"code.kerpass.org/golang/pkg/noise"
	"code.kerpass.org/golang/pkg/protocols"
)

type ServerStateFunc = protocols.StateFunc[*ServerState]

type ServerExitFunc = protocols.ExitFunc[*ServerState]

type srvExitAction int

const (
	srvRestoreAuthorization srvExitAction = 1 << iota
	srvRemoveCard
)

type ServerCfg struct {
	KeyStore credentials.KeyStore
	Repo     credentials.ServerCredStore
}

func (self ServerCfg) Check() error {
	if nil == self.KeyStore {
		return newError("nil KeyStore")
	}
	if nil == self.Repo {
		return newError("nil Repo")
	}

	return nil
}

type ServerState struct {
	KeyStore      credentials.KeyStore
	Repo          credentials.ServerCredStore
	realmId       []byte
	exitActions   srvExitAction
	authorization credentials.EnrollAuthorization
	card          credentials.ServerCard
	hs            noise.HandshakeState
	next          ServerStateFunc
}

func NewServerState(cfg ServerCfg) (*ServerState, error) {
	err := cfg.Check()
	if nil != err {
		return nil, wrapError(err, "Invalid ServerCfg")
	}

	rv := &ServerState{
		KeyStore: cfg.KeyStore,
		Repo:     cfg.Repo,
		next:     ServerInit,
	}

	return rv, nil
}

// protocols.Fsm implementation

func (self *ServerState) State() (*ServerState, ServerStateFunc) {
	return self, self.next
}

func (self *ServerState) SetState(sf ServerStateFunc) {
	self.next = sf
}

func (self *ServerState) ExitHandler() ServerExitFunc {
	return ServerExit
}

func (self *ServerState) SetExitHandler(_ ServerExitFunc) {
}

func (self *ServerState) Initiator() bool {
	return false
}

var _ protocols.Fsm[*ServerState] = &ServerState{}

// State functions

func ServerInit(ctx context.Context, self *ServerState, msg []byte) (sf ServerStateFunc, rmsg []byte, err error) {
	sf = ServerInit
	var errmsg string

	// get logger
	log := observability.GetObservability(ctx).Log().With("state", "ClientInit")

	// receive Client: <- [EnrollReq]
	log.Debug("unmarshalling client EnrollReq")
	req := EnrollReq{}
	err = cborSrz.Unmarshal(msg, &req)
	if nil != err {
		errmsg = "failed unmarshalling client EnrollReq"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}

	// retrieve Realm ServerKey
	log.Debug("loading ServerKey for EnrollReq.RealmId")
	sk := credentials.ServerKey{}
	found := self.KeyStore.GetServerKey(ctx, req.RealmId, &sk)
	if !found {
		errmsg = "failed loading ServerKey for EnrollReq.RealmId"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg+" %X", req.RealmId)
	}
	self.realmId = req.RealmId

	// initialize Handshake
	log.Debug("initializing noise handshake")
	params := noise.HandshakeParams{
		Cfg:           noiseCfg,
		Prologue:      req.RealmId,
		StaticKeypair: sk.Kh.PrivateKey,
		Psks:          dummyPsks,
		Initiator:     false,
	}
	err = self.hs.Initialize(params)
	if nil != err {
		errmsg = "failed initializing noise handshake"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}

	// receive Client: <- e, []
	log.Debug("reading handshake message")
	var buf bytes.Buffer
	_, err = self.hs.ReadMessage(req.Msg, &buf)
	if nil != err {
		errmsg = "failed reading handshake message"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}

	// prepare Server: -> e, ee, s, es {Certificate}
	log.Debug("generating handshake message with static key certificate payload")
	buf.Reset()
	_, err = self.hs.WriteMessage(sk.Certificate, &buf)
	if nil != err {
		errmsg = "failed generating handshake message"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}

	log.Debug("OK, switching to ServerCheckEnrollAuthorization state")
	return ServerCheckEnrollAuthorization, buf.Bytes(), err
}

func ServerCheckEnrollAuthorization(ctx context.Context, self *ServerState, msg []byte) (sf ServerStateFunc, rmsg []byte, err error) {
	sf = ServerCheckEnrollAuthorization
	var errmsg string

	// get logger
	log := observability.GetObservability(ctx).Log().With("state", "ServerCheckEnrollAuthorization")

	// schedule recovering inner noise HandshakeState in case of error...
	hsbkup := self.hs
	defer func() {
		if nil != err {
			log.Debug("restoring initial handshake state following error")
			self.hs = hsbkup
		}
	}()

	// receive Client: <- s, se, {EnrollAuthorizatiom}
	log.Debug("reading handshake message")
	var buf bytes.Buffer
	_, err = self.hs.ReadMessage(msg, &buf)
	if nil != err {
		errmsg = "failed reading handshake message"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}
	log.Debug("extracting client EnrollAuthorization from handshake message payload")
	cli := EnrollAuthorization{}
	err = cborSrz.Unmarshal(buf.Bytes(), &cli)
	if nil != err {
		errmsg = "failed CBOR unmarshal of EnrollAuthorization"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}

	// check EnrollAuthorization
	log.Debug("controlling client EnrollAuthorization")
	authorization := credentials.EnrollAuthorization{}
	err = self.Repo.PopEnrollAuthorization(ctx, cli.AuthorizationId, &authorization)
	if nil != err {
		errmsg = "failed retrieving authorization"
		log.Debug(errmsg, "error", err)
		if errors.Is(err, credentials.ErrNotFound) {
			err = errors.Join(err, ErrInvalidAuthorization)
		}
		return sf, rmsg, wrapError(err, errmsg)
	}
	if !slices.Equal(self.realmId, authorization.RealmId) {
		errmsg = "client forwarded an invalid authorization"
		err = wrapError(ErrInvalidAuthorization, errmsg)
		log.Debug(errmsg, "error", err)
		return sf, rmsg, err
	}

	// Schedule exit authorization restoration, if protocol failed...
	authorization.AuthorizationId = cli.AuthorizationId
	self.authorization = authorization
	self.exitActions |= srvRestoreAuthorization

	// create EnrollCardCreateResp
	log.Debug("preparing EnrollCardCreateResp")
	cardId := make([]byte, 32)
	_, err = rand.Read(cardId)
	if nil != err {
		errmsg = "failed generating cardId"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}
	cardresp := EnrollCardCreateResp{
		CardId:  cardId,
		AppName: authorization.AppName,
		AppLogo: authorization.AppLogo,
	}
	srzcardresp, err := cborSrz.Marshal(cardresp)
	if nil != err {
		errmsg = "failed CBOR marshal of EnrollCardCreateResp"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}

	// prepare Server: -> psk, {EnrollCardCreateResp}
	log.Debug("generating handshake message with EnrollCardCreateResp payload")
	buf.Reset()
	_, err = self.hs.WriteMessage(srzcardresp, &buf)
	if nil != err {
		errmsg = "failed generating handshake message"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}

	// create new ServerCard
	log.Debug("creating Card")
	psk, err := derivePSK(authorization.RealmId, cardId, self.hs.GetHandshakeHash())
	if nil != err {
		errmsg = "failed deriving Card psk"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}
	sc := credentials.ServerCard{RealmId: authorization.RealmId, CardId: cardId, Psk: psk}
	sc.Kh.PublicKey = self.hs.RemoteStaticKey()
	self.card = sc

	log.Debug("OK, switching to ServerCardSave state")
	return ServerCardSave, buf.Bytes(), err
}

func ServerCardSave(ctx context.Context, self *ServerState, msg []byte) (sf ServerStateFunc, rmsg []byte, err error) {
	sf = ServerCardSave
	var errmsg string

	// get logger
	log := observability.GetObservability(ctx).Log().With("state", "ServerCardSave")

	// schedule recovering inner noise HandshakeState in case of error...
	hsbkup := self.hs
	defer func() {
		if protocols.IsError(err) {
			log.Debug("restoring initial handshake state following error")
			self.hs = hsbkup
		}
	}()

	// receive Client: <- psk, {}
	log.Debug("reading handshake message")
	var buf bytes.Buffer
	_, err = self.hs.ReadMessage(msg, &buf)
	if nil != err {
		errmsg = "failed reading handshake message"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}

	// save new ServerCard
	log.Debug("saving Card")
	err = self.Repo.SaveCard(ctx, self.card)
	if nil != err {
		errmsg = "failed saving card"
		log.Debug(errmsg, "error", err)
		return sf, rmsg, wrapError(err, errmsg)
	}
	self.exitActions |= srvRemoveCard

	log.Debug("SUCCESS, completed enroll protocol")
	return nil, nil, protocols.OK
}

func ServerExit(self *ServerState, rs error) error {
	defer func() {
		self.exitActions = 0
	}()

	if nil == rs {
		return nil
	}

	var err1, err2 error
	if srvRestoreAuthorization == (self.exitActions & srvRestoreAuthorization) {
		err1 = self.Repo.SaveEnrollAuthorization(context.Background(), self.authorization)
	}
	if srvRemoveCard == (self.exitActions & srvRemoveCard) {
		removed := self.Repo.RemoveCard(context.Background(), self.card.CardId)
		if !removed {
			err2 = newError("Failed removing ServerCard")
		}
	}

	return errors.Join(err1, err2)
}
