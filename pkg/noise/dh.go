package noise

import (
	"crypto/ecdh"
	"crypto/rand"
	"io"

	"code.kerpass.org/golang/internal/utils"
)

const (
	KEYEXCH_25519 = "25519"
)

var (
	dhRegistry *utils.Registry[DH]

	// we maintain private rnd Reader as the global rand.Reader could be replaced by a malicious external package.
	rnd io.Reader
)

// DH adapts the golang ecdh.Curve interface to ease noise protocol implementation.
type DH interface {
	ecdh.Curve

	// Generate a random Keypair.
	GenerateKeypair() (*Keypair, error)

	// Execute Diffie-Hellmann key exchange.
	DH(keypair *Keypair, pubkey *PublicKey) ([]byte, error)

	// Size of the Diffie-Hellmann shared secret.
	DHLen() int
}

// MustRegisterDH adds algo to the DH registry. It panics if name is already in use or if algo is invalid.
func MustRegisterDH(name string, algo DH) {
	err := RegisterDH(name, algo)
	if nil != err {
		panic(err)
	}
}

// RegisterDH adds algo to the DH registry. It errors if name is already in use or if algo is invalid.
func RegisterDH(name string, algo DH) error {
	if nil == algo || (algo.DHLen() < dhMinSize) {
		return newError("Invalid DH algorithm")
	}
	return wrapError(
		utils.RegistrySet(dhRegistry, name, algo),
		"failed registering DH KeyExch %s",
		name,
	)
}

// GetDH loads a DH from the registry. It errors if no DH was registered with name.
func GetDH(name string) (DH, error) {
	dh, found := utils.RegistryGet(dhRegistry, name)
	if !found || nil == dh || (dh.DHLen() < dhMinSize) {
		return dh, newError("Unsupported DH KeyExch algorithm, %s", name)
	}
	return dh, nil
}

// EcDH embeds ecdh.Curve and implements the DH interface.
type EcDH struct {
	ecdh.Curve
	Size int
}

// GenerateKeypair generates a random Keypair.
func (self EcDH) GenerateKeypair() (*Keypair, error) {
	return self.GenerateKey(rnd)
}

// DH performs Diffie-Hellmann key exchange on inner Curve.
func (self EcDH) DH(keypair *Keypair, pubkey *PublicKey) ([]byte, error) {
	if nil == keypair || keypair.Curve() != self.Curve {
		return nil, newError("Invalid keypair")
	}
	return keypair.ECDH(pubkey)
}

// DHLen returns the size of the Diffie-Hellmann shared secret.
func (self EcDH) DHLen() int {
	return self.Size
}

// randReader is an io.Reader that wraps rand.Read
type randReader struct{}

func (_ randReader) Read(b []byte) (int, error) {
	return rand.Read(b)
}

func init() {
	rnd = randReader{}
	dhRegistry = utils.NewRegistry[DH]()
	MustRegisterDH(KEYEXCH_25519, EcDH{Curve: ecdh.X25519(), Size: 32})
}
