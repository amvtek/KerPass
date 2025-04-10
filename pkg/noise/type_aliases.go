package noise

import (
	"crypto/ecdh"
)

type (
	Keypair   = ecdh.PrivateKey
	PublicKey = ecdh.PublicKey
)
