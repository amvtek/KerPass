package noise

import (
	"crypto/ecdh"
	"crypto/rand"
)

const (
	KEYEXCH_25519 = "25519"
)

type DH interface {
	GenerateKeyPair() (*ecdh.PrivateKey, error)
	DH(keypair *ecdh.PrivateKey, pubkey *ecdh.PublicKey) ([]byte, error)
	DHLen() int
}

func GetDH(algo string) (DH, error) {
	switch algo {
	case KEYEXCH_25519:
		return ecDH{Curve: ecdh.X25519(), dhlen: 32}, nil
	default:
		return nil, ErrUnsupportedKeyExch
	}
}

type ecDH struct {
	ecdh.Curve
	dhlen int
}

func (self ecDH) GenerateKeyPair() (*ecdh.PrivateKey, error) {
	return self.GenerateKey(rand.Reader)
}

func (self ecDH) DH(keypair *ecdh.PrivateKey, pubkey *ecdh.PublicKey) ([]byte, error) {
	if nil == keypair {
		return nil, ErrNilKeyPair
	}
	return keypair.ECDH(pubkey)
}

func (self ecDH) DHLen() int {
	return self.dhlen
}
