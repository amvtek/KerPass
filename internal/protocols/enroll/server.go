package enroll

import (
	"crypto/rand"
	"slices"

	"code.kerpass.org/golang/internal/credentials"
	"code.kerpass.org/golang/internal/protocols"
	"code.kerpass.org/golang/internal/transport"
	"code.kerpass.org/golang/pkg/noise"
)

type ServerEnrollProtocol struct {
	KeyStore credentials.KeyStore
	Repo     credentials.ServerCredStore
}

func (self ServerEnrollProtocol) Run(mt transport.MessageTransport) error {
	// receive Client: <- [EnrollReq]
	req := EnrollReq{}
	err := mt.ReadMessage(&req) // 1st ReadMessage
	if nil != err {
		return wrapError(err, "failed reading initial EnrollReq message")
	}

	// retrieve Realm ServerKey
	sk := credentials.ServerKey{}
	found := self.KeyStore.GetServerKey(req.RealmId, &sk)
	if !found {
		return newError("failed loading ServerKey for realm % X", req.RealmId)
	}

	// initialize Handshake
	hst := transport.NewHandshakeTransport(mt.Transport)
	params := noise.HandshakeParams{
		Cfg:           noiseCfg,
		Prologue:      req.RealmId,
		StaticKeypair: sk.Kh.PrivateKey,
		Psks:          dummyPsks,
		Initiator:     false,
	}
	err = hst.Initialize(params)
	if nil != err {
		return wrapError(err, "failed hst.Initialize")
	}
	mt.Transport = hst

	// receive Client: <- e, []
	empty := transport.RawMsg{}
	err = mt.ReadMessage(&empty)
	if nil != err {
		return wrapError(err, "failed mt.ReadMessage")
	}

	// send Server: -> e, ee, s, es {Certificate}
	err = mt.WriteMessage(transport.RawMsg(sk.Certificate))
	if nil != err {
		return wrapError(err, "failed mt.WriteMessage")
	}

	// receive Client: <- s, se, {EnrollAuthorizatiom}
	cli := EnrollAuthorization{}
	err = mt.ReadMessage(&cli) // 2nd ReadMessage
	if nil != err {
		return wrapError(err, "failed mt.ReadMessage")
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

	// create new ServerCard
	sc := credentials.ServerCard{RealmId: authorization.RealmId}

	cardId := make([]byte, 32)
	_, err = rand.Read(cardId)
	if nil != err {
		return wrapError(err, "failed generating cardId")
	}
	sc.CardId = cardId

	srvPSKShare := make([]byte, 32)
	_, err = rand.Read(srvPSKShare)
	if nil != err {
		return wrapError(err, "failed generating srvPSKShare")
	}

	psk, err := derivePSK(authorization.RealmId, cardId, cli.PSKShare, srvPSKShare)
	if nil != err {
		return wrapError(err, "failed deriving psk")
	}
	sc.Psk = psk

	sc.Kh.PublicKey = hst.RemoteStaticKey()

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

	// send Server: -> psk, {EnrollCardCreateResp}
	srv := EnrollCardCreateResp{
		CardId:   cardId,
		PSKShare: srvPSKShare,
		AppName:  authorization.AppName,
		AppLogo:  authorization.AppLogo,
	}
	err = mt.WriteMessage(srv)
	if nil != err {
		return wrapError(err, "failed mt.WriteMessage")
	}

	// receive Client: <- psk, {}
	err = mt.ReadMessage(&empty) // 3rd ReadMessage
	if nil != err {
		return wrapError(err, "failed mt.ReadMessage")
	}

	success = true
	return nil
}

var _ protocols.Runner = ServerEnrollProtocol{}
