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
	Repo            credentials.ClientCredStore
}

func (self ClientEnrollProtocol) Run(mt transport.MessageTransport) error {
	var buf bytes.Buffer

	// create a Static Keypair
	curve := noiseCfg.CurveAlgo
	keypair, err := curve.GenerateKey(rand.Reader)
	if nil != err {
		return wrapError(err, "failed generating Card Keypair")
	}

	// initialize Handshake
	hs := noise.HandshakeState{}
	params := noise.HandshakeParams{Cfg: noiseCfg, StaticKeypair: keypair, Initiator: true}
	err = hs.Initialize(params)
	if nil != err {
		return wrapError(err, "failed hs.Initialize")
	}

	// send EnrollReq
	_, err = hs.WriteMessage(nil, &buf)
	if nil != err {
		return wrapError(err, "failed hs.WriteMessage")
	}
	req := EnrollReq{RealmId: self.RealmId, NoiseMsg: buf.Bytes()}
	err = mt.WriteMessage(req) // 1st WriteMessage
	if nil != err {
		return wrapError(err, "failed mt.WriteMessage")
	}

	// receive Server: <- e, ee, s, es, {Certificate}
	rawmsg := transport.RawMsg{}
	err = mt.ReadMessage(&rawmsg)
	if nil != err {
		return wrapError(err, "failed mt.ReadMessage")
	}
	buf.Reset()
	_, err = hs.ReadMessage([]byte(rawmsg), &buf)
	if nil != err {
		return wrapError(err, "failed hs.ReadMessage")
	}

	// control RemoteStaticKey()
	srvkey := hs.RemoteStaticKey()
	srvcert := buf.Bytes()
	err = pkiCheck(srvkey, srvcert)
	if nil != err {
		return wrapError(err, "failed server Static Key control")
	}

	// send Client: -> s, se, {authorizationId}
	buf.Reset()
	completed, err := hs.WriteMessage(self.AuthorizationId, &buf)
	if nil != err {
		return wrapError(err, "failed hs.WriteMessage")
	}
	if !completed {
		// shall not happen if XX pattern is used
		panic("Invalid noise.Config, XX handshake not completed after 2nd hs.WriteMessage")
	}
	rawmsg = transport.RawMsg(buf.Bytes())
	err = mt.WriteMessage(rawmsg) // 2nd WriteMessage
	if nil != err {
		return wrapError(err, "failed mt.WriteMessage")
	}

	// noise Handshake completed, set transport ciphers
	ciphers := &noise.TransportCipherPair{}
	err = hs.Split(ciphers)
	if nil != err {
		return wrapError(err, "failed hs.Split")
	}
	mt.C = ciphers

	// receive Server: <- EnrollCardCreateResp{}
	resp := EnrollCardCreateResp{}
	err = mt.ReadMessage(&resp)
	if nil != err {
		return wrapError(err, "failed mt.ReadMessage")
	}

	// create new Card
	card := credentials.Card{
		RealmId: self.RealmId,
		CardId:  resp.CardId,
		AppName: resp.AppName,
		AppLogo: resp.AppLogo,
	}
	psk, err := derivePSK(self.RealmId, resp.CardId, hs.GetHandshakeHash())
	if nil != err {
		return wrapError(err, "failed deriving psk")
	}
	card.Psk = psk
	card.Kh.PrivateKey = keypair

	// save new Card
	var success bool
	err = self.Repo.SaveCard(card)
	if nil != err {
		return wrapError(err, "failed saving card")
	}
	defer func(success *bool) {
		// rollback if success is false
		if !(*success) {
			self.Repo.RemoveCard(resp.CardId)
		}
	}(&success)

	// send Client: -> resp.CardId as confirmation
	rawmsg = transport.RawMsg(resp.CardId)
	err = mt.WriteMessage(rawmsg) // 3rd WriteMessage
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
