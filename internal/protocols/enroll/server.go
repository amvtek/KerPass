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

type ServerEnrollProtocol struct {
	keystore credentials.KeyStore
	repos    credentials.ServerCredStore
}

func (self ServerEnrollProtocol) Run(mt transport.MessageTransport) error {
	var buf bytes.Buffer

	// receive EnrollReq from CardAgent client
	req := EnrollReq{}
	err := mt.ReadMessage(&req)
	if nil != err {
		return wrapError(err, "failed reading initial EnrollReq message")
	}

	// retrieve Realm ServerKey
	sk := credentials.ServerKey{}
	found := self.keystore.GetServerKey(req.RealmId, &sk)
	if !found {
		return newError("failed loading ServerKey for realm % X", req.RealmId)
	}

	// initialize Handshake
	hs := noise.HandshakeState{}
	params := noise.HandshakeParams{Cfg: noiseCfg, StaticKeypair: sk.Kh.PrivateKey, Initiator: false}
	err = hs.Initialize(params)
	if nil != err {
		return wrapError(err, "failed hs.Initialize")
	}

	// receive Client: -> e
	_, err = hs.ReadMessage(req.NoiseMsg, &buf)
	if nil != err {
		return wrapError(err, "failed hs.ReadMessage")
	}

	// send Server: <- e, ee, s, es {Certificate}
	buf.Reset()
	_, err = hs.WriteMessage(sk.Certificate, &buf)
	if nil != err {
		return wrapError(err, "failed hs.WriteMessage")
	}
	err = mt.WriteMessage(transport.RawMsg(buf.Bytes()))
	if nil != err {
		return wrapError(err, "failed mt.WriteMessage")
	}

	// receive Client: -> s, se, {authorizationId}
	rawmsg := transport.RawMsg{}
	err = mt.ReadMessage(&rawmsg)
	if nil != err {
		return wrapError(err, "failed mt.ReadMessage")
	}
	buf.Reset()
	completed, err := hs.ReadMessage([]byte(rawmsg), &buf)
	if nil != err {
		return wrapError(err, "failed hs.ReadMessage")
	}
	if !completed {
		// shall not happen if XX pattern is used
		panic("Invalid noise.Config, XX handshake not completed after 2nd hs.ReadMessage ?")
	}

	// check Client authorization
	authorizationId := buf.Bytes()
	metas := credentials.EnrollAuthorization{}
	var isValidAuthorization bool
	if self.repos.PopEnrollAuthorization(authorizationId, &metas) {
		if slices.Equal(req.RealmId, metas.RealmId) {
			isValidAuthorization = true
		}
	}
	if !isValidAuthorization {
		return newError("client forwarded an invalid authorization")
	}

	// noise Handshake completed, set transport ciphers
	ciphers := &noise.TransportCipherPair{}
	err = hs.Split(ciphers)
	if nil != err {
		return wrapError(err, "failed hs.Split")
	}
	mt.C = ciphers

	// create new ServerCard
	sc := credentials.ServerCard{RealmId: metas.RealmId}
	cardId := make([]byte, 32)
	_, err = rand.Read(cardId)
	if nil != err {
		return wrapError(err, "failed generating cardId")
	}
	sc.CardId = cardId
	psk, err := derivePSK(metas.RealmId, cardId, hs.GetHandshakeHash())
	if nil != err {
		return wrapError(err, "failed deriving psk")
	}
	sc.Psk = psk
	sc.Kh.PublicKey = hs.RemoteStaticKey()

	// save new ServerCard
	var success bool
	err = self.repos.SaveCard(sc)
	if nil != err {
		return wrapError(err, "failed saving card")
	}
	defer func(success *bool) {
		// rollback if success is false
		if !(*success) {
			self.repos.RemoveCard(cardId)
		}
	}(&success)

	// send EnrollCardCreateResp
	resp := EnrollCardCreateResp{
		RealmId: metas.RealmId,
		CardId:  cardId,
		AppName: metas.AppName,
		AppLogo: metas.AppLogo,
	}
	err = mt.WriteMessage(resp)
	if nil != err {
		return wrapError(err, "failed mt.WriteMessage")
	}

	// to confirm Client shall echo new cardId
	echoCardId := transport.RawMsg{}
	err = mt.ReadMessage(&echoCardId)
	if nil != err {
		return wrapError(err, "failed mt.ReadMessage")
	}
	if !slices.Equal(cardId, []byte(echoCardId)) {
		return newError("failed Client Card confirmation")
	}

	success = true
	return nil
}

var _ protocols.Runner = ServerEnrollProtocol{}
