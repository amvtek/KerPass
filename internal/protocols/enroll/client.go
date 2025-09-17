package enroll

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"

	"code.kerpass.org/golang/internal/credentials"
	"code.kerpass.org/golang/internal/protocols"
	"code.kerpass.org/golang/pkg/noise"
)

type ClientStateFunc = protocols.StateFunc[*ClientState]

type ClientExitFunc = protocols.ExitFunc[*ClientState]

type ClientState struct {
	RealmId         []byte
	AuthorizationId []byte
	Repo            credentials.ClientCredStore
	hs              noise.HandshakeState
	cardId          int
	next            ClientStateFunc
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

func ClientInit(self *ClientState, _ []byte) (sf ClientStateFunc, rmsg []byte, err error) {
	sf = ClientInit

	// create a Static Keypair
	curve := noiseCfg.CurveAlgo
	keypair, err := curve.GenerateKey(rand.Reader)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed generating Card Keypair")
	}

	// initialize noise Handshake
	params := noise.HandshakeParams{
		Cfg:           noiseCfg,
		Prologue:      self.RealmId,
		StaticKeypair: keypair,
		Psks:          dummyPsks,
		Initiator:     true,
	}
	err = self.hs.Initialize(params)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed hs.Initialize")
	}

	// generate initial noise msg
	// Client: -> e
	var buf bytes.Buffer
	_, err = self.hs.WriteMessage(nil, &buf)

	// prepare Client: -> [EnrollReq]
	// It can not be send as noise payload because the server needs to know the RealmId to load its static key...
	req := EnrollReq{RealmId: self.RealmId, Msg: buf.Bytes()}
	rmsg, err = cborSrz.Marshal(req)
	if nil != err {
		return sf, nil, wrapError(err, "failed serializing the initial EnrollReq message")
	}

	return ClientReceiveServerKey, rmsg, nil
}

func ClientReceiveServerKey(self *ClientState, msg []byte) (sf ClientStateFunc, rmsg []byte, err error) {
	sf = ClientReceiveServerKey

	// schedule recovering inner noise HandshakeState in case of error...
	hsbkup := self.hs
	defer func() {
		if nil != err {
			self.hs = hsbkup
		}
	}()

	// receive Server: <- e, ee, s, es, {Certificate}
	var buf bytes.Buffer
	_, err = self.hs.ReadMessage(msg, &buf)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed noise handshake ReadMessage")
	}
	srvcert := buf.Bytes()

	// control RemoteStaticKey()
	srvkey := self.hs.RemoteStaticKey()
	err = pkiCheck(srvkey, srvcert)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed server Static Key control")
	}

	// prepare Client: -> s, se, {EnrollAuthorization}
	srzmsg, err := cborSrz.Marshal(EnrollAuthorization{AuthorizationId: self.AuthorizationId})
	if nil != err {
		return sf, rmsg, wrapError(err, "failed serializing the EnrollAuthorization message")
	}
	buf.Reset()
	_, err = self.hs.WriteMessage(srzmsg, &buf)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed noise handshake WriteMessage")
	}

	return ClientCardCreate, buf.Bytes(), nil
}

func ClientCardCreate(self *ClientState, msg []byte) (sf ClientStateFunc, rmsg []byte, err error) {
	sf = ClientCardCreate

	// schedule recovering inner noise HandshakeState in case of error...
	hsbkup := self.hs
	defer func() {
		if nil != err {
			self.hs = hsbkup
		}
	}()

	// receive Server: <- psk, {EnrollCardCreateResp}
	var buf bytes.Buffer
	_, err = self.hs.ReadMessage(msg, &buf)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed noise handshake ReadMessage")
	}
	srv := EnrollCardCreateResp{}
	err = cborSrz.Unmarshal(buf.Bytes(), &srv)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed unmarshaling EnrollCardCreateResp")
	}

	// create new Card
	psk, err := derivePSK(self.RealmId, srv.CardId, self.hs.GetHandshakeHash())
	if nil != err {
		return sf, rmsg, wrapError(err, "failed deriving psk")
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
	cardId, err := self.Repo.SaveCard(card)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed saving card")
	}
	card.ID = cardId
	self.cardId = cardId

	// prepare Client: -> psk, {}
	buf.Reset()
	_, err = self.hs.WriteMessage(nil, &buf)
	if nil != err {
		return sf, rmsg, wrapError(err, "failed noise handshake WriteMessage")
	}

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
