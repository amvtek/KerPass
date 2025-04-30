package ephemsec

import (
	"crypto"
	"crypto/ecdh"
	"math"
	"regexp"
	"strconv"

	"code.kerpass.org/golang/pkg/algos"
)

const (
	otpMaxBits    = 64
	otpB10MaxBits = 48 // TODO: check RFC 4226 Annex A, B10 bias analysis
	otkMaxBits    = 512
)

var (
	schemeRe = regexp.MustCompile(
		`Kerpass_([A-Za-z0-9/]+)_([A-Za-z0-9/]+)_(E[1-2]S[1-2])_T([0-9]+)_B([0-9]+)_P([0-9]+)_S([0-1])`,
	)
)

const (
	// below constants index the schemeRe subgroups
	schH = 1
	schD = 2
	schK = 3
	schT = 4
	schB = 5
	schP = 6
	schS = 7
)

// scheme holds configuration parameters for OTP/OTK generation.
// scheme is an opaque type.
type scheme struct {

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
	S int

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
//	Kerpass_SHA512/256_X25519_E1S2_T400_B32_P8_S1
//	  1st subgroup (eg SHA512/256) is the name of the scheme Hash function
//	  2nd subgroup (eg X25519) is the name of the scheme Diffie-Hellmann function
//	  3rd subgroup (eg E1S2) details Diffie-Hellmann key exchange requirements,
//	    E is the number of ephemeral keys and S the number of static keys
//	  4th subgroup (eg T400) is the size of the OTP/OTK validation time window in seconds
//	  5th subgroup (eg B32) is the OTP encoding alphabet
//	  6th subgroup (eg P8) is the number of alphabet digits of the generated OTP/OTK excluding
//	    scheme synchronization digits
//	  7th subgroup (eg S1) is the number of synchronization digits added to generated OTP/OTK
func NewScheme(name string) (*scheme, error) {
	parts := schemeRe.FindStringSubmatch(name)
	if len(parts) != 8 {
		return nil, newError("Invalid scheme name %s", name)
	}
	rv := scheme{}

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

	// S
	val, err = strconv.Atoi(parts[schS])
	if nil != err {
		return nil, wrapError(err, "can not decode S")
	}
	rv.S = val

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
	self.hash = hash

	// curve reload
	curve, err := algos.GetCurve(self.D)
	if nil != err {
		return wrapError(err, "error loading Curve %s", self.D)
	}
	if nil == curve {
		// normally unreachable
		return newError("got a nil Curve loading %s", self.D)
	}
	self.curve = curve

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

	// S validation
	switch self.S {
	case 0, 1:
		// ok
	default:
		return newError("invalid S (number of synchronization digits) %d not in [0..1]", self.S)
	}

	// P validation
	var maxBits int
	base := self.B
	switch base {
	case 256:
		maxBits = otkMaxBits
	case 16, 32:
		maxBits = otpMaxBits
	case 10:
		maxBits = otpB10MaxBits
	default:
		return newError("invalid B (encoding base) %d", base)
	}
	digits := self.P
	if digits <= 0 {
		return newError("invalid P (code number of digits) (%d <= 0)", digits)
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
	self.step = self.T / float64(base)
	return nil
}

// Time transforms a second precision Unix timestamp into a pseudo time that can be used as
// input for OTP/OTK calculation. It returns the pseudo time and its synchronization hint.
func (self scheme) Time(timestamp int64) (int64, int) {
	ts := int64(math.Round(float64(timestamp) / self.step))
	return ts, int(ts % int64(self.B))
}

// SyncTime returns the pseudo time which is the closest from Time(timestamp)
// having a synchronization hint that matches sync. It errors if the sync
// parameter is invalid.
func (self scheme) SyncTime(timestamp int64, sync int) (int64, error) {
	codeBase := self.B
	if sync < 0 || sync >= codeBase {
		return 0, newError("invalid sync %d", sync)
	}
	reftime, _ := self.Time(timestamp)

	B := int64(codeBase)
	Q := (reftime / B) - 1
	S := int64(sync)
	var c, bestTime int64
	var d, delta float64
	c = Q*B + S // c % B == S
	delta = math.Inf(1)
	for _ = range 3 {
		d = math.Abs(float64(reftime - c))
		if d < delta {
			delta = d
			bestTime = c

		}
		c += B
	}
	return bestTime, nil
}
