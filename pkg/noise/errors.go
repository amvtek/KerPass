package noise

import (
	"errors"
)

var (
	ErrNilCurve             = errors.New("noise: Nil curve, KeyExch is invalid")
	ErrUnsupportedKeyExch   = errors.New("noise: Unsupported KeyExch")
	ErrUnsupportedHash      = errors.New("noise: Unsupported Hash")
	ErrNilCipher            = errors.New("noise: Nil Cipher")
	ErrCipherKeyOverUse     = errors.New("noise: Cipher Key Overuse")
	ErrInvalidCipherState   = errors.New("noise: Invalid CipherState")
	ErrRekeyLowEntropy      = errors.New("noise: Cipher rekey generated less than 256 bits entropy")
	ErrUnsupportedCipher    = errors.New("noise: Unsupported Cipher")
	ErrInvalidCipherKeySize = errors.New("noise: Invalid Cipher Key size")
	ErrInvalidProtocolName  = errors.New("noise: Invalid Protocol name")
)
