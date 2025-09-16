package enroll

import (
	"bytes"
	"crypto/rand"
	"errors"
	"slices"

	"code.kerpass.org/golang/internal/credentials"
	"code.kerpass.org/golang/internal/protocols"
	"code.kerpass.org/golang/internal/transport"
	"code.kerpass.org/golang/pkg/noise"
)

type ServerStateFunc = protocols.StateFunc[*ServerState]

type ServerExitFunc = protocols.ExitFunc[*ServerState]

type srvExitAction int

const (
	srvRestoreAuthorization srvExitAction = 1 << iota
	srvRemoveCard
)

type ServerState struct {
	KeyStore      credentials.KeyStore
	Repo          credentials.ServerCredStore
	Serializer    transport.Serializer
	realmId       []byte
	exitActions   srvExitAction
	authorization credentials.EnrollAuthorization
	card          credentials.ServerCard
	hs            noise.HandshakeState
	next          ServerStateFunc
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

func ServerInit(self *ServerState, msg []byte) (sf ServerStateFunc, rmsg []byte, err error) {
	sf = ServerInit

	// receive Client: <- [EnrollReq]
	req := EnrollReq{}
	err = self.Serializer.Unmarshal(msg, &req)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed unmarshaling EnrollReq")
	}

	// retrieve Realm ServerKey
	sk := credentials.ServerKey{}
	found := self.KeyStore.GetServerKey(req.RealmId, &sk)
	if !found {
		return sf, rmsg, newError("failed loading ServerKey for realm % X", req.RealmId)
	}
	self.realmId = req.RealmId

	// initialize Handshake
	params := noise.HandshakeParams{
		Cfg:           noiseCfg,
		Prologue:      req.RealmId,
		StaticKeypair: sk.Kh.PrivateKey,
		Psks:          dummyPsks,
		Initiator:     false,
	}

	// schedule recovering inner noise HandshakeState in case of error...
	hsbkup := self.hs
	defer func() {
		if nil != err {
			self.hs = hsbkup
		}
	}()

	err = self.hs.Initialize(params)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed hs.Initialize")
	}

	// receive Client: <- e, []
	var buf bytes.Buffer
	_, err = self.hs.ReadMessage(req.Msg, &buf)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed noise handshake ReadMessage")
	}

	// prepare Server: -> e, ee, s, es {Certificate}
	buf.Reset()
	_, err = self.hs.WriteMessage(sk.Certificate, &buf)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed noise handshake WriteMessage")
	}

	return ServerCheckEnrollAuthorization, buf.Bytes(), err
}

func ServerCheckEnrollAuthorization(self *ServerState, msg []byte) (sf ServerStateFunc, rmsg []byte, err error) {
	sf = ServerCheckEnrollAuthorization

	// schedule recovering inner noise HandshakeState in case of error...
	hsbkup := self.hs
	defer func() {
		if nil != err {
			self.hs = hsbkup
		}
	}()

	// receive Client: <- s, se, {EnrollAuthorizatiom}
	var buf bytes.Buffer
	_, err = self.hs.ReadMessage(msg, &buf)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed noise handshake ReadMessage")
	}
	cli := EnrollAuthorization{}
	err = self.Serializer.Unmarshal(buf.Bytes(), &cli)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed unmarshaling EnrollAuthorization")
	}

	// check EnrollAuthorization
	authorization := credentials.EnrollAuthorization{}
	var isValidAuthorization bool
	if self.Repo.PopEnrollAuthorization(cli.AuthorizationId, &authorization) {
		if slices.Equal(self.realmId, authorization.RealmId) {
			isValidAuthorization = true
		}
	}
	if !isValidAuthorization {
		err = newError("client forwarded an invalid authorization")
		return sf, rmsg, err
	}

	// Schedule exit authorization restoration, if protocol failed...
	authorization.AuthorizationId = cli.AuthorizationId
	self.authorization = authorization
	self.exitActions |= srvRestoreAuthorization

	// create EnrollCardCreateResp
	cardId := make([]byte, 32)
	_, err = rand.Read(cardId)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed generating cardId")
	}
	cardresp := EnrollCardCreateResp{
		CardId:  cardId,
		AppName: authorization.AppName,
		AppLogo: authorization.AppLogo,
	}
	srzcardresp, err := self.Serializer.Marshal(cardresp)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed serializing the EnrollCardCreateResp message")
	}

	// prepare Server: -> psk, {EnrollCardCreateResp}
	buf.Reset()
	_, err = self.hs.WriteMessage(srzcardresp, &buf)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed noise handshake WriteMessage")
	}

	// create new ServerCard
	psk, err := derivePSK(authorization.RealmId, cardId, self.hs.GetHandshakeHash())
	if nil != err {
		return sf, rmsg, wrapError(err, "failed deriving psk")
	}
	sc := credentials.ServerCard{RealmId: authorization.RealmId, CardId: cardId, Psk: psk}
	sc.Kh.PublicKey = self.hs.RemoteStaticKey()
	self.card = sc

	return ServerCardSave, buf.Bytes(), err
}

func ServerCardSave(self *ServerState, msg []byte) (sf ServerStateFunc, rmsg []byte, err error) {
	sf = ServerCardSave

	// schedule recovering inner noise HandshakeState in case of error...
	hsbkup := self.hs
	defer func() {
		if nil != err {
			self.hs = hsbkup
		}
	}()

	// receive Client: <- psk, {}
	var buf bytes.Buffer
	_, err = self.hs.ReadMessage(msg, &buf)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed noise handshake ReadMessage")
	}

	// save new ServerCard
	err = self.Repo.SaveCard(self.card)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed saving card")
	}
	self.exitActions |= srvRemoveCard

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
		err1 = self.Repo.SaveEnrollAuthorization(self.authorization)
	}
	if srvRemoveCard == (self.exitActions & srvRemoveCard) {
		removed := self.Repo.RemoveCard(self.card.CardId)
		if !removed {
			err2 = newError("Failed removing ServerCard")
		}
	}

	return errors.Join(err1, err2)
}
