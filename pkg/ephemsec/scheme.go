package ephemsec

import (
	"crypto"
	"crypto/ecdh"
	"encoding/binary"
	"math"
	"regexp"
	"slices"
	"strconv"

	"code.kerpass.org/golang/internal/algos"
)

const (
	otpMaxBits    = 64
	otpB10MaxBits = 48
	otkMaxBytes   = 64
)

var (
	schemeRe = regexp.MustCompile(
		`Kerpass_([A-Za-z0-9/]+)_([A-Za-z0-9/]+)_(E[1-2]S[1-2])_T([0-9]+)B([0-9]+)P([0-9]+)`,
	)
)

const (
	// below constants index the schemeRe subgroups
	schN = 0
	schH = 1
	schD = 2
	schK = 3
	schT = 4
	schB = 5
	schP = 6
)

// scheme holds configuration parameters for OTP/OTK generation.
// scheme is an opaque type.
type scheme struct {

	// N scheme name
	N string

	// H hash algorithm name
	H string

	// D Diffie-Hellman Key Exchange function name
	D string

	// K Diffie-Hellman Key Exchange requirements
	// K defines the number of Ephemeral & Static keys used to derive the shared secret
	// K is a string of form E1S2
	//   E prefix is followed by the number (1 or 2) of ephemeral keys used in the exchange
	//   S prefix is followed by the number (1 or 2) of static keys used in the exchange
	K string

	// T timeWindow size in seconds
	// T > 0
	T float64

	// B OTP/OTK encoding base
	// B in 2..256
	B int

	// P OTP/OTK number of pseudo random digits
	// P > 0
	P int

	// S OTP/OTK number of synchronization digits
	// S in 0..1
	// S int

	// init tracks if Init was successfully called
	init bool

	// Hash algorithm implementation
	// loaded from registry using H as name
	hash crypto.Hash

	// ecdh Curve implementation
	// loaded from registry using D as name
	curve ecdh.Curve

	// pre calculated OTP step
	step float64

	// pre calculated OTP generation modulus
	// zero for binary code used for OTK
	maxcode int64
}

// NewScheme parses the name string to extract scheme fields values. It errors if name can not
// be parsed or if the constructed scheme is invalid.
//
// scheme name have the following form
//
//	Kerpass_SHA512/256_X25519_E1S2_T400B32P8
//	  1st subgroup (eg SHA512/256) is the name of the scheme Hash function
//	  2nd subgroup (eg X25519) is the name of the scheme Diffie-Hellmann function
//	  3rd subgroup (eg E1S2) details Diffie-Hellmann key exchange requirements,
//	    E is the number of ephemeral keys and S the number of static keys
//	  4th subgroup (eg T400) is the size of the OTP/OTK validation time window in seconds
//	  5th subgroup (eg B32) is the OTP encoding alphabet
//	  6th subgroup (eg P8) is the number of digits of the generated OTP/OTK
//	    including scheme synchronization digits
func NewScheme(name string) (*scheme, error) {
	parts := schemeRe.FindStringSubmatch(name)
	if len(parts) != 7 {
		return nil, newError("Invalid scheme name %s", name)
	}
	rv := scheme{}

	// N
	rv.N = parts[schN]

	// H
	rv.H = parts[schH]

	// D & curve
	rv.D = parts[schD]

	// K
	rv.K = parts[schK]

	// T
	val, err := strconv.Atoi(parts[schT])
	if nil != err {
		return nil, wrapError(err, "can not decode T")
	}
	rv.T = float64(val)

	// B
	val, err = strconv.Atoi(parts[schB])
	if nil != err {
		return nil, wrapError(err, "can not decode B")
	}
	rv.B = val

	// P
	val, err = strconv.Atoi(parts[schP])
	if nil != err {
		return nil, wrapError(err, "can not decode P")
	}
	rv.P = val

	return &rv, rv.Init()
}

// Init validates inner parameters and prepares the scheme for usage.
func (self *scheme) Init() error {
	if nil == self {
		return newError("nil scheme")
	}

	// hash reload
	hash, err := algos.GetHash(self.H)
	if nil != err {
		return wrapError(err, "error loading Hash %s", self.H)
	}
	if !hash.Available() {
		return newError("missing implementation for Hash %s", hash)
	}
	if hash.Size() > maxHashSize || hash.Size() < minHashSize {
		return newError("invalid hash %s, digest size %d not in %d..%d range", hash, minHashSize, maxHashSize)
	}
	self.hash = hash

	// curve reload
	curve, err := algos.GetCurve(self.D)
	if nil != err {
		return wrapError(err, "error loading Curve %s", self.D)
	}
	if nil == curve.Curve {
		// normally unreachable
		return newError("got a nil Curve loading %s", self.D)
	}
	self.curve = curve.Curve

	// N validation
	if self.N == "" || len(self.N) > maxSchemeName {
		return newError("invalid N, empty or longer than %d bytes", maxSchemeName)
	}

	// K validation
	switch self.K {
	case "E1S1", "E1S2", "E2S2":
		// ok
	default:
		return newError("non supported K %s", self.K)
	}

	// T validation
	if self.T <= 0 {
		return newError("invalid T timeWindow (%v <= 0)", self.T)
	}

	// P validation
	var maxBits int
	base := self.B
	switch base {
	case 256:
		maxBits = otkMaxBytes * 8
	case 16, 32:
		maxBits = otpMaxBits
	case 10:
		maxBits = otpB10MaxBits
	default:
		return newError("invalid B (encoding base) %d", base)
	}
	digits := self.P - 1
	if digits <= 1 {
		return newError("invalid P (code number of digits) (%d <= 2)", digits+1)
	}
	if (float64(digits) * math.Log2(float64(base))) > float64(maxBits) {
		return newError("not enough entropy for P (code number of digits = %d", digits)
	}

	// maxcode calculation
	var M int64
	if 256 != base {
		M = int64(math.Pow(float64(base), float64(digits)))
	}
	self.maxcode = M

	// step calculation
	self.step = self.T / float64(base-1)

	self.init = true // simplify testing that self was properly initialized

	return nil
}

// Name returns the scheme name.
func (self scheme) Name() string {
	return self.N
}

// KeyExchangePattern returns the scheme Key Exchange pattern.
// Possible values are E1S1, E1S2 & E2S2.
func (self scheme) KeyExchangePattern() string {
	return self.K
}

// TimeWindow returns the scheme Time Window size in seconds.
func (self scheme) TimeWindow() float64 {
	return self.T
}

// DigitBase returns the scheme digit base.
func (self scheme) DigitBase() int {
	return self.B
}

// CodeSize returns the scheme code size.
func (self scheme) CodeSize() int {
	return self.P
}

// Curve returns the scheme curve.
func (self scheme) Curve() ecdh.Curve {
	return self.curve
}

// Hash returns the scheme hash.
func (self scheme) Hash() crypto.Hash {
	return self.hash
}

// Time transforms a second precision Unix timestamp into a pseudo time that can be used as
// input for OTP/OTK calculation. It returns the pseudo time and its synchronization hint.
func (self scheme) Time(t int64) (int64, int) {
	ts := int64(math.Round(float64(t) / self.step))
	return ts, int(ts % int64(self.B))
}

// SyncTime returns the pseudo time which is the closest from Time(t)
// having a synchronization hint that matches sync. It errors if the sync
// parameter is invalid.
func (self scheme) SyncTime(t int64, sync int) (int64, error) {
	if sync < 0 || sync >= self.B {
		return 0, newError("invalid sync %d", sync)
	}

	// synchronization algorithm
	// t normally corresponds to current time on validator side
	// sync is the synchro hint forwarded by the responder (last OTP/OTK digit)
	// solution PTIME has sync synchro hint and correspond to time in [t - T/2 .. t + T/2] interval

	ptm, sm := self.Time(t - int64(self.T/2)) // ptm is minimum PTIME that can be valid
	b := int64(self.B)
	s := int64(sync)
	qm := ptm / b
	pt := qm*b + s
	if sync < sm {
		pt += b
	}
	return pt, nil
}

// NewOTP interprets src as a Uint64 integer and returns an OTP which digits encode
// the src integer in the scheme base B.
func (self scheme) NewOTP(src []byte, ptime int64) ([]byte, error) {
	B := self.B
	P := self.P

	var minSize int
	switch B {
	case 256:
		minSize = P
	default:
		minSize = 8
	}
	if len(src) < minSize {
		return nil, newError("src does not contain enough entropy")
	}

	switch B {
	case 256:
		src[P-1] = byte(ptime % int64(B))
		return src[:P], nil
	default:
		isrc := binary.BigEndian.Uint64(src[:8]) % uint64(self.maxcode)
		src = slices.Grow(src[:0], P)
		src = src[:P]
		base := uint64(B)
		for i := range P - 1 {
			src[P-2-i] = byte(isrc % base)
			isrc /= base
		}
		src[P-1] = byte(ptime % int64(B))
		return src, nil
	}
}

func (self scheme) ecdh(seckey *ecdh.PrivateKey, pubkey *ecdh.PublicKey) ([]byte, error) {
	if nil == seckey || seckey.Curve() != self.curve {
		return nil, newError("invalid seckey")
	}
	return seckey.ECDH(pubkey)
}
