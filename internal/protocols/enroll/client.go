package enroll

import (
	"crypto/ecdh"
	"crypto/rand"

	"code.kerpass.org/golang/internal/credentials"
	"code.kerpass.org/golang/internal/protocols"
	"code.kerpass.org/golang/internal/transport"
	"code.kerpass.org/golang/pkg/noise"
)

type ClientEnrollProtocol struct {
	RealmId         []byte
	AuthorizationId []byte
	Repo            credentials.ClientCredStore
}

func (self ClientEnrollProtocol) Run(mt transport.MessageTransport) error {
	// send Client: -> [EnrollReq]
	// It can not be send as noise payload because the server needs to know the RealmId to load its static key...
	req := EnrollReq{RealmId: self.RealmId}
	err := mt.WriteMessage(req)
	if nil != err {
		return wrapError(err, "failed sending initial EnrollReq message")
	}

	// create a Static Keypair
	curve := noiseCfg.CurveAlgo
	keypair, err := curve.GenerateKey(rand.Reader)
	if nil != err {
		return wrapError(err, "failed generating Card Keypair")
	}

	// initialize Handshake
	hst := transport.NewHandshakeTransport(mt.Transport)
	params := noise.HandshakeParams{
		Cfg:           noiseCfg,
		Prologue:      req.RealmId,
		StaticKeypair: keypair,
		Psks:          dummyPsks,
		Initiator:     true,
	}
	err = hst.Initialize(params)
	if nil != err {
		return wrapError(err, "failed hst.Initialize")
	}
	mt.Transport = hst

	// send Client: -> e
	err = mt.WriteMessage(transport.RawMsg(nil)) // 1st WriteMessage
	if nil != err {
		return wrapError(err, "failed mt.WriteMessage")
	}

	// receive Server: <- e, ee, s, es, {Certificate}
	srvcert := transport.RawMsg{}
	err = mt.ReadMessage(&srvcert)
	if nil != err {
		return wrapError(err, "failed mt.ReadMessage")
	}

	// control RemoteStaticKey()
	srvkey := hst.RemoteStaticKey()
	err = pkiCheck(srvkey, []byte(srvcert))
	if nil != err {
		return wrapError(err, "failed server Static Key control")
	}

	// send Client: -> s, se, {EnrollAuthorization}
	cli := EnrollAuthorization{AuthorizationId: self.AuthorizationId}
	pskShare := make([]byte, 32)
	_, err = rand.Read(pskShare)
	if nil != err {
		return wrapError(err, "failed generating pskShare")
	}
	cli.PSKShare = pskShare
	err = mt.WriteMessage(cli) // 2nd WriteMessage
	if nil != err {
		return wrapError(err, "failed mt.WriteMessage")
	}

	// receive Server: <- psk, {EnrollCardCreateResp}
	srv := EnrollCardCreateResp{}
	err = mt.ReadMessage(&srv)
	if nil != err {
		return wrapError(err, "failed mt.ReadMessage")
	}

	// create new Card
	card := credentials.Card{
		RealmId: self.RealmId,
		IdToken: srv.CardId,
		AppName: srv.AppName,
		AppLogo: srv.AppLogo,
	}
	psk, err := derivePSK(self.RealmId, srv.CardId, cli.PSKShare, srv.PSKShare)
	if nil != err {
		return wrapError(err, "failed deriving psk")
	}
	card.Psk = psk
	card.Kh.PrivateKey = keypair

	// save new Card
	var success bool
	cardId, err := self.Repo.SaveCard(card)
	if nil != err {
		return wrapError(err, "failed saving card")
	}
	card.ID = cardId
	defer func(success *bool) {
		// rollback if success is false
		if !(*success) {
			self.Repo.RemoveCard(cardId)
		}
	}(&success)

	// send Client: -> psk, {}
	err = mt.WriteMessage(transport.RawMsg(nil)) // 3rd WriteMessage
	if nil != err {
		return wrapError(err, "failed mt.WriteMessage")
	}

	success = true
	return nil

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

var _ protocols.Runner = ClientEnrollProtocol{}
