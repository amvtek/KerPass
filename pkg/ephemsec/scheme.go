package ephemsec

import (
	"math"
)

const (
	otpMaxBits    = 64
	otpB10MaxBits = 48 // TODO: check RFC 4226 Annex A, B10 bias analysis
	otkMaxBits    = 512
)

// Scheme holds configuration parameters for OTP/OTK generation.
type Scheme struct {

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
