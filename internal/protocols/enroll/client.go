package enroll

import (
	"bytes"
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
	Serializer      transport.Serializer
	Repo            credentials.ClientCredStore
}

func (self ClientEnrollProtocol) Run(tr transport.Transport) error {

	// create a Static Keypair
	curve := noiseCfg.CurveAlgo
	keypair, err := curve.GenerateKey(rand.Reader)
	if nil != err {
		return wrapError(err, "failed generating Card Keypair")
	}

	// initialize noise Handshake
	params := noise.HandshakeParams{
		Cfg:           noiseCfg,
		Prologue:      self.RealmId,
		StaticKeypair: keypair,
		Psks:          dummyPsks,
		Initiator:     true,
	}
	hs := noise.HandshakeState{}
	err = hs.Initialize(params)
	if nil != err {
		return wrapError(err, "failed hs.Initialize")
	}

	// generate initial noise msg
	// Client: -> e
	var buf bytes.Buffer
	_, err = hs.WriteMessage(nil, &buf)

	// send Client: -> [EnrollReq]
	// It can not be send as noise payload because the server needs to know the RealmId to load its static key...
	req := EnrollReq{RealmId: self.RealmId, Msg: buf.Bytes()}
	srzmsg, err := self.Serializer.Marshal(req)
	if nil != err {
		return wrapError(err, "failed serializing the initial EnrollReq message")
	}
	err = tr.WriteBytes(srzmsg)
	if nil != err {
		return wrapError(err, "failed sending initial EnrollReq message")
	}

	// receive Server: <- e, ee, s, es, {Certificate}
	srzmsg, err = tr.ReadBytes()
	if nil != err {
		return wrapError(err, "failed receiving server keys")
	}
	buf.Reset()
	_, err = hs.ReadMessage(srzmsg, &buf)
	if nil != err {
		return wrapError(err, "failed noise handshake ReadMessage")
	}
	srvcert := buf.Bytes()

	// control RemoteStaticKey()
	srvkey := hs.RemoteStaticKey()
	err = pkiCheck(srvkey, srvcert)
	if nil != err {
		return wrapError(err, "failed server Static Key control")
	}

	// send Client: -> s, se, {EnrollAuthorization}
	srzmsg, err = self.Serializer.Marshal(EnrollAuthorization{AuthorizationId: self.AuthorizationId})
	if nil != err {
		return wrapError(err, "failed serializing the EnrollAuthorization message")
	}
	buf.Reset()
	_, err = hs.WriteMessage(srzmsg, &buf)
	if nil != err {
		return wrapError(err, "failed noise handshake WriteMessage")
	}
	err = tr.WriteBytes(buf.Bytes())
	if nil != err {
		return wrapError(err, "failed transport WriteBytes")
	}

	// receive Server: <- psk, {EnrollCardCreateResp}
	srzmsg, err = tr.ReadBytes()
	if nil != err {
		return wrapError(err, "failed transport ReadBytes")
	}
	buf.Reset()
	_, err = hs.ReadMessage(srzmsg, &buf)
	if nil != err {
		return wrapError(err, "failed noise handshake ReadMessage")
	}
	srv := EnrollCardCreateResp{}
	err = self.Serializer.Unmarshal(buf.Bytes(), &srv)
	if nil != err {
		return wrapError(err, "failed unmarshaling EnrollCardCreateResp")
	}

	// create new Card
	psk, err := derivePSK(self.RealmId, srv.CardId, hs.GetHandshakeHash())
	if nil != err {
		return wrapError(err, "failed deriving psk")
	}
	card := credentials.Card{
		RealmId: self.RealmId,
		IdToken: srv.CardId,
		AppName: srv.AppName,
		AppLogo: srv.AppLogo,
		Psk:     psk,
	}
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
	buf.Reset()
	_, err = hs.WriteMessage(nil, &buf)
	if nil != err {
		return wrapError(err, "failed noise handshake WriteMessage")
	}
	err = tr.WriteBytes(buf.Bytes())
	if nil != err {
		return wrapError(err, "failed transport WriteBytes")
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
