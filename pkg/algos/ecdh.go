package algos

import (
	"crypto/ecdh"

	"code.kerpass.org/golang/internal/utils"
)

const (
	CURVE_X25519 = "X25519"
	CURVE_P256   = "P256"
	CURVE_P384   = "P384"
	CURVE_P521   = "P521"
)

var curveRegistry *utils.Registry[ecdh.Curve]

// MustRegisterCurve adds curve to the Curve registry. It panics if name is already in use or curve is invalid.
func MustRegisterCurve(name string, curve ecdh.Curve) {
	err := RegisterCurve(name, curve)
	if nil != err {
		panic(err)
	}
}

// RegisterCurve adds curve to the Curve registry. It errors if name is already in use or curve is invalid.
func RegisterCurve(name string, curve ecdh.Curve) error {
	if nil == curve {
		return newError("nil curve can not be registered")
	}
	return wrapError(
		utils.RegistrySet(curveRegistry, name, curve),
		"failed registering Curve algorithm, %s",
		name,
	)
}

// GetCurve loads Curve implementation from the registry. It errors if no curve was registered with name.
func GetCurve(name string) (ecdh.Curve, error) {
	curve, found := utils.RegistryGet(curveRegistry, name)
	if !found {
		return curve, newError("unsupported Curve algorithm, %s", name)
	}
	return curve, nil
}

func init() {
	curveRegistry = utils.NewRegistry[ecdh.Curve]()
	MustRegisterCurve(CURVE_X25519, ecdh.X25519())
	MustRegisterCurve(CURVE_P256, ecdh.P256())
	MustRegisterCurve(CURVE_P384, ecdh.P384())
	MustRegisterCurve(CURVE_P521, ecdh.P521())
}
