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
	KeyStore   credentials.KeyStore
	Repo       credentials.ServerCredStore
	Serializer transport.Serializer
}

func (self ServerEnrollProtocol) Run(tr transport.Transport) error {
	// receive Client: <- [EnrollReq]
	srzreq, err := tr.ReadBytes()
	req := EnrollReq{}
	err = self.Serializer.Unmarshal(srzreq, &req)
	if nil != err {
		return wrapError(err, "failed unmarshaling EnrollReq")
	}

	// retrieve Realm ServerKey
	sk := credentials.ServerKey{}
	found := self.KeyStore.GetServerKey(req.RealmId, &sk)
	if !found {
		return newError("failed loading ServerKey for realm % X", req.RealmId)
	}

	// initialize Handshake
	params := noise.HandshakeParams{
		Cfg:           noiseCfg,
		Prologue:      req.RealmId,
		StaticKeypair: sk.Kh.PrivateKey,
		Psks:          dummyPsks,
		Initiator:     false,
	}
	hs := noise.HandshakeState{}
	err = hs.Initialize(params)
	if nil != err {
		return wrapError(err, "failed hs.Initialize")
	}

	// receive Client: <- e, []
	var buf bytes.Buffer
	_, err = hs.ReadMessage(req.Msg, &buf)
	if nil != err {
		return wrapError(err, "failed noise handshake ReadMessage")
	}

	// send Server: -> e, ee, s, es {Certificate}
	buf.Reset()
	_, err = hs.WriteMessage(sk.Certificate, &buf)
	if nil != err {
		return wrapError(err, "failed noise handshake WriteMessage")
	}
	err = tr.WriteBytes(buf.Bytes())
	if nil != err {
		return wrapError(err, "failed transport WriteBytes")
	}

	// receive Client: <- s, se, {EnrollAuthorizatiom}
	srzmsg, err := tr.ReadBytes()
	if nil != err {
		return wrapError(err, "failed transport ReadBytes")
	}
	buf.Reset()
	_, err = hs.ReadMessage(srzmsg, &buf)
	if nil != err {
		return wrapError(err, "failed noise handshake ReadMessage")
	}
	cli := EnrollAuthorization{}
	err = self.Serializer.Unmarshal(buf.Bytes(), &cli)
	if nil != err {
		return wrapError(err, "failed unmarshaling EnrollAuthorization")
	}

	// check EnrollAuthorization
	authorization := credentials.EnrollAuthorization{}
	var isValidAuthorization bool
	if self.Repo.PopEnrollAuthorization(cli.AuthorizationId, &authorization) {
		if slices.Equal(req.RealmId, authorization.RealmId) {
			isValidAuthorization = true
		}
	}
	if !isValidAuthorization {
		return newError("client forwarded an invalid authorization")
	}

	// Schedule exit authorization restoration, if protocol failed...
	var success bool
	authorization.AuthorizationId = cli.AuthorizationId
	defer func(success *bool) {
		if !(*success) {
			// TODO: log error if restoration failed
			self.Repo.SaveEnrollAuthorization(authorization)
		}
	}(&success)

	// create EnrollCardCreateResp
	cardId := make([]byte, 32)
	_, err = rand.Read(cardId)
	if nil != err {
		return wrapError(err, "failed generating cardId")
	}
	cardresp := EnrollCardCreateResp{
		CardId:  cardId,
		AppName: authorization.AppName,
		AppLogo: authorization.AppLogo,
	}
	srzcardresp, err := self.Serializer.Marshal(cardresp)
	if nil != err {
		return wrapError(err, "failed serializing the EnrollCardCreateResp message")
	}

	// send Server: -> psk, {EnrollCardCreateResp}
	buf.Reset()
	_, err = hs.WriteMessage(srzcardresp, &buf)
	if nil != err {
		return wrapError(err, "failed noise handshake WriteMessage")
	}
	err = tr.WriteBytes(buf.Bytes())
	if nil != err {
		return wrapError(err, "failed transport WriteBytes")
	}

	// create new ServerCard
	psk, err := derivePSK(authorization.RealmId, cardId, hs.GetHandshakeHash())
	if nil != err {
		return wrapError(err, "failed deriving psk")
	}
	sc := credentials.ServerCard{RealmId: authorization.RealmId, CardId: cardId, Psk: psk}
	sc.Kh.PublicKey = hs.RemoteStaticKey()

	// save new ServerCard
	err = self.Repo.SaveCard(sc)
	if nil != err {
		return wrapError(err, "failed saving card")
	}
	defer func(success *bool) {
		// rollback if success is false
		if !(*success) {
			self.Repo.RemoveCard(cardId)
		}
	}(&success)

	// receive Client: <- psk, {}
	srzmsg, err = tr.ReadBytes()
	if nil != err {
		return wrapError(err, "failed transport ReadBytes")
	}
	buf.Reset()
	_, err = hs.ReadMessage(srzmsg, &buf)
	if nil != err {
		return wrapError(err, "failed noise handshake ReadMessage")
	}

	success = true
	return nil
}

var _ protocols.Runner = ServerEnrollProtocol{}
