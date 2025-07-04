// Package enroll provides client & server implementation of KerPass Enrollment protocol.
// This protocol allows registering EPHEMSEC credentials (aka "Card") that allows generating
// and validating ephemeral mutual secrets in OTP/OTK format.
//
// Prior to execution of this protocol, a relying server Application has generated a client
// authorization and forwarded to the client a secret identifier for this authorization plus
// the Realm identifier to which this application belongs. KerPass Realm Identifier determines
// a PKI context that allows validating Application service keys...
//
// The Enrollment protocol is built on top of a Noise XX key exchange.
// Prior to execution of the protocol, the client generates a fresh X25519 Keypair which is used
// as client static Keypair for the Noise XX exchange. The server will accept client public key
// if client transmits a valid authorization identifier. If the Noise XX key exchange succeeds,
// client and server uses the exchange hash state to derive a PSK, and server generates a new
// Card identifier that it forwards to client...
//
// If the protocol succeeds:
// - Client stores RealmId, CardId, client Keypair, PSK as Card record.
// - Server stores RealmId, CardId, client PubKey, PSK as ServerCard record.
package enroll

import (
	"code.kerpass.org/golang/pkg/noise"
)

var noiseCfg noise.Config

func init() {
	err := noiseCfg.Load("Noise_XX_25519_AESGCM_SHA512")
	if nil != err {
		panic(err)
	}
}
