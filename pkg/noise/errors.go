package noise

import (
	"errors"
)

var (
	ErrNilCurve             = errors.New("Nil curve, KeyExch is invalid")
	ErrUnsupportedKeyExch   = errors.New("Unsupported KeyExch")
	ErrUnsupportedHash      = errors.New("Unsupported Hash")
	ErrUnsupportedCipher    = errors.New("Unsupported Cipher")
	ErrInvalidCipherKeySize = errors.New("Invalid Cipher Key size")
)
