package ephemsec

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
)

const (
	otpMaxBits    = 64
	otpB10MaxBits = 48 // TODO: check RFC 4226 Annex A, B10 bias analysis
	otkMaxBits    = 512
)

var (
	schemeRe = regexp.MustCompile(
		`Kerpass_([A-Za-z0-9/]+)_([A-Za-z0-9/]+)_(E[1-2]S[1-2])_T([0-9]+)_B([0-9]+)_P([0-9]+)_S([0-2])`,
	)
)

// Scheme holds configuration parameters for OTP/OTK generation.
type Scheme struct {
	pHash string

	pCurveName string

	pDH string

	// T timeWindow size in seconds
	// T > 0
	pT float64

	// B OTP/OTK encoding base
	// B in 2..256
	pB int

	// P OTP/OTK number of pseudo random digits
	// P > 0
	pP int

	// S OTP/OTK number of synchronization digits
	// S >= 0
	pS int

	// pre calculated OTP step
	step float64

	// pre calculated OTP generation modulus
	// zero for binary code used for OTK
	maxCode int64
}

// NewScheme parses the name string to extract Scheme fields values. It errors if name can not
// be parsed or if the constructed scheme is invalid.
//
// Scheme name have the following form
// Kerpass_SHA512/256_X25519_E1S2_T400_B32_P8_S1
//
//	1st subgroup (eg SHA512/256) is the name of the scheme Hash function
//	2nd subgroup (eg X25519) is the name of the scheme Diffie-Hellmann function
//	3rd subgroup (eg E1S2) details Diffie-Hellmann key exchange requirements,
//	  E is the number of ephemeral keys and S the number of static keys
//	4th subgroup (eg T400) is the size of the OTP/OTK validation time window in seconds
//	5th subgroup (eg B32) is the OTP encoding alphabet
//	6th subgroup (eg P8) is the number of alphabet digits of the generated OTP/OTK excluding
//	  scheme synchronization digits
//	7th subgroup (eg S1) is the number of synchronization digits added to generated OTP/OTK
func NewScheme(name string) (*Scheme, error) {
	parts := schemeRe.FindStringSubmatch(name)
	if len(parts) != 8 {
		return nil, newError("Invalid scheme name %s", name)
	}
	fmt.Printf("parts -> %+v\n", parts)
	rv := Scheme{}

	// TODO: we need to load algorithms
	rv.pHash = parts[1]
	rv.pCurveName = parts[2]
	rv.pDH = parts[3]

	// pT
	val, err := strconv.Atoi(parts[4])
	if nil != err {
		return nil, wrapError(err, "can not decode pT")
	}
	rv.pT = float64(val)

	// pB
	val, err = strconv.Atoi(parts[5])
	if nil != err {
		return nil, wrapError(err, "can not decode pB")
	}
	rv.pB = val

	// pP
	val, err = strconv.Atoi(parts[6])
	if nil != err {
		return nil, wrapError(err, "can not decode pP")
	}
	rv.pP = val

	// pS
	val, err = strconv.Atoi(parts[7])
	if nil != err {
		return nil, wrapError(err, "can not decode pS")
	}
	rv.pS = val

	return &rv, rv.Init()
}

// Init validates inner parameters and prepares the Scheme for usage.
func (self *Scheme) Init() error {
	if nil == self {
		return newError("nil Scheme")
	}
	if self.pT <= 0 {
		return newError("invalid T timeWindow (%v <= 0)", self.pT)
	}
	if self.pS < 0 {
		return newError("invalid S (number of synchronization digits) (%d < 0)", self.pS)
	}

	var maxBits int
	base := self.pB
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
	digits := self.pP
	if digits <= 0 {
		return newError("invalid P (code number of digits) (%d <= 0)", digits)
	}
	if (float64(digits) * math.Log2(float64(base))) > float64(maxBits) {
		return newError("not enough entropy for P (code number of digits = %d", digits)
	}
	var M int64
	if 256 != base {
		M = int64(math.Pow(float64(base), float64(digits)))
	}
	self.step = self.pT / float64(base)
	self.maxCode = M
	return nil
}

// Time transforms a second precision Unix timestamp into a pseudo time that can be used as
// input for OTP/OTK calculation. It returns the pseudo time and its synchronization hint.
func (self Scheme) Time(timestamp int64) (int64, int) {
	ts := int64(math.Round(float64(timestamp) / self.step))
	return ts, int(ts % int64(self.pB))
}

// SyncTime returns the pseudo time which is the closest from Time(timestamp)
// having a synchronization hint that matches sync. It errors if the sync
// parameter is invalid.
func (self Scheme) SyncTime(timestamp int64, sync int) (int64, error) {
	codeBase := self.pB
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
