package noise

import (
	"crypto/ecdh"
	"crypto/rand"
)

const (
	KEYEXCH_25519 = "25519"
)

func GetKeyExch(ke string) (KeyExch, error) {
	var err error
	kx := KeyExch{}
	switch ke {
	case KEYEXCH_25519:
		kx.curve = ecdh.X25519()
		kx.dhlen = 32
	default:
		err = ErrUnsupportedKeyExch
	}
	return kx, err
}

type KeyExch struct {
	curve ecdh.Curve
	dhlen int
}

func (self KeyExch) GenerateKey() (*ecdh.PrivateKey, error) {
	if nil == self.curve {
		return nil, ErrNilCurve
	}
	return self.curve.GenerateKey(rand.Reader)
}

func (self KeyExch) DhLen() int {
	return self.dhlen
}
