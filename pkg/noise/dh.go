package noise

import (
	"crypto/ecdh"
	"crypto/rand"
)

const (
	KEYEXCH_25519 = "25519"
)

var dhRegistry *registry[DH]

type DH interface {
	GenerateKeypair() (*Keypair, error)
	NewPublicKey(srzkey []byte) (*PublicKey, error)
	DH(keypair *Keypair, pubkey *PublicKey) ([]byte, error)
	DHLen() int
}

func MustRegisterDH(name string, algo DH) {
	err := RegisterDH(name, algo)
	if nil != err {
		panic(err)
	}
}

func RegisterDH(name string, algo DH) error {
	return registrySet(dhRegistry, name, algo)
}

func GetDH(name string) (DH, error) {
	dh, found := registryGet(dhRegistry, name)
	if !found || nil == dh || (dh.DHLen() < dhMinSize) {
		return dh, ErrUnsupportedKeyExch
	}
	return dh, nil

}

type EcDH struct {
	ecdh.Curve
	Size int
}

func (self EcDH) GenerateKeypair() (*Keypair, error) {
	return self.GenerateKey(rand.Reader)
}

func (self EcDH) DH(keypair *Keypair, pubkey *PublicKey) ([]byte, error) {
	if nil == keypair {
		return nil, ErrNilKeyPair
	}
	return keypair.ECDH(pubkey)
}

func (self EcDH) DHLen() int {
	return self.Size
}

func init() {
	dhRegistry = newRegistry[DH]()
	MustRegisterDH(KEYEXCH_25519, EcDH{Curve: ecdh.X25519(), Size: 32})
}
