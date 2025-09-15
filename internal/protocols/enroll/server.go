package enroll

import (
	"bytes"
	"crypto/rand"
	"slices"

	"code.kerpass.org/golang/internal/credentials"
	"code.kerpass.org/golang/internal/protocols"
	"code.kerpass.org/golang/internal/transport"
	"code.kerpass.org/golang/pkg/noise"
)

type ServerStateFunc = protocols.StateFunc[*ServerState]

type ServerState struct {
	KeyStore   credentials.KeyStore
	Repo       credentials.ServerCredStore
	Serializer transport.Serializer
	realmId    []byte
	card       credentials.ServerCard
	hs         noise.HandshakeState
	next       ServerStateFunc
}

// protocols.Fsm implementation

func (self *ServerState) State() (*ServerState, ServerStateFunc) {
	return self, self.next
}

func (self *ServerState) SetState(sf ServerStateFunc) {
	self.next = sf
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
	defer func() {
		if nil != err {
			// TODO: log error if restoration failed
			self.Repo.SaveEnrollAuthorization(authorization)
		}
	}()

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

	return nil, nil, nil
}
