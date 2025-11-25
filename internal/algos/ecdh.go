package algos

import (
	"crypto/ecdh"
	"math/rand/v2"

	"code.kerpass.org/golang/internal/utils"
)

const (
	CURVE_X25519 = "X25519"
	CURVE_25519  = "25519" // alias used in noise protocol names
	CURVE_P256   = "P256"
	CURVE_P384   = "P384"
	CURVE_P521   = "P521"
)

// Curve embeds ecdh.Curve and adds methods that simplify usage.
type Curve struct {
	ecdh.Curve
	name        string
	privkeySize int
	pubkeySize  int
	dhsecSize   int
}

// Name returns Name of Curve
func (self Curve) Name() string {
	return self.name
}

// PrivateKeyLen returns byte length of Curve PrivateKey
func (self Curve) PrivateKeyLen() int {
	return self.privkeySize
}

// PublicKeyLen returns byte length of uncompressed form of Curve PublicKey
func (self Curve) PublicKeyLen() int {
	return self.pubkeySize
}

// DHLen returns byte length of Diffie-Hellmann shared secret
func (self Curve) DHLen() int {
	return self.dhsecSize
}

func (self *Curve) init() error {
	if nil == self || nil == self.Curve {
		return newError("can not initialize nil curve")
	}

	// rnd is just used to determine Curve outputs size, hence it does not need to be crypto rand.Reader
	rnd := rand.NewChaCha8([32]byte{})

	curve := self.Curve
	pk1, err := curve.GenerateKey(rnd)
	if nil != err {
		return wrapError(err, "failed generating pk1")
	}
	self.privkeySize = len(pk1.Bytes())
	self.pubkeySize = len(pk1.PublicKey().Bytes())

	pk2, err := curve.GenerateKey(rnd)
	if nil != err {
		return wrapError(err, "failed generating pk2")
	}

	dhsec, err := pk1.ECDH(pk2.PublicKey())
	if nil != err {
		return wrapError(err, "failed generating dhsec")
	}
	self.dhsecSize = len(dhsec)

	return nil
}

var curveRegistry *utils.Registry[string, Curve]

// MustRegisterCurve adds curve to the Curve registry. It panics if name is already in use or curve is invalid.
func MustRegisterCurve(name string, curve ecdh.Curve) {
	err := RegisterCurve(name, curve)
	if nil != err {
		panic(err)
	}
}

// RegisterCurve adds curve to the Curve registry. It errors if name is already in use or curve is invalid.
func RegisterCurve(name string, curve ecdh.Curve) error {
	regcurve := Curve{Curve: curve, name: name}
	err := regcurve.init()
	if nil != err {
		return wrapError(err, "failed initializing Curve %s", name)
	}
	return wrapError(
		utils.RegistrySet(curveRegistry, name, regcurve),
		"failed registering Curve algorithm, %s",
		name,
	)
}

// GetCurve loads Curve implementation from the registry. It errors if no curve was registered with name.
func GetCurve(name string) (Curve, error) {
	curve, found := utils.RegistryGet(curveRegistry, name)
	if !found {
		return curve, newError("unsupported Curve algorithm, %s", name)
	}
	return curve, nil
}

// ListCurves returns a slice containing the names of the registered elliptic curves.
func ListCurves() []string {
	curveIdx := utils.RegistryEntries(curveRegistry)
	rv := make([]string, 0, len(curveIdx))
	for name, _ := range curveIdx {
		rv = append(rv, name)
	}
	return rv
}

func init() {
	curveRegistry = utils.NewRegistry[string, Curve]()
	MustRegisterCurve(CURVE_X25519, ecdh.X25519())
	MustRegisterCurve(CURVE_25519, ecdh.X25519())
	MustRegisterCurve(CURVE_P256, ecdh.P256())
	MustRegisterCurve(CURVE_P384, ecdh.P384())
	MustRegisterCurve(CURVE_P521, ecdh.P521())
}
